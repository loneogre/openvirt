"""
ovnctl diagnose -- port of ovn-diagnose.sh

Walks the OVN/OVS stack layer by layer to find where connectivity is
breaking.

Deployment-tracker aware: checks are gated on what has actually been
deployed, so "gateway port missing" is only a FAIL if a localnet command
recorded itself as run, and a clean SKIP otherwise. Conversely, ambiguous
results become definitive: tracker says localnet-internal ran + no
chassisredirect port exists = hard FAIL, no hedging.

With NO tracker file, every check runs unconditionally -- the tracker is
advisory, the OVN db remains the source of truth.

FIXES CARRIED OVER FROM THE SHELL VERSION
  * check_isolation referenced $_iso_vms, which was never defined -- the
    live non-member proof silently picked the wrong VM (or none).
  * Three calls passed a default argument to cfg(), which takes two args
    and exits on a miss. Those are cfg_opt lookups here.
  * require_cfg demanded [localnet_external].br_asa / .phys_nic, which no
    longer exist in the settings file, so the whole script aborted before
    running a single check. Those are optional now.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter

from .. import netcalc, ovn
from ..context import Ctx
from ..inventory import Inventory
from ..state import (ACLS, LOCALNET_EXTERNAL, LOCALNET_INTERNAL, SETUP,
                     VM_CONFIG, VM_ISOLATION, Tracker)
from ..steps import StepRunner, add_step_args

NAME = "diagnose"
HELP = "layer-by-layer health check of the OVN/OVS stack"

PASS = "[ OK ]"
FAIL = "[FAIL]"
WARN = "[WARN]"
SKIP = "[SKIP]"

_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class Diagnose:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.br_int = c.cfg_opt("topology", "br_int", "br-int")
        self.host_if = c.cfg_opt("topology", "host_if", "host-if")
        self.lr_core = c.cfg_opt("topology", "lr_core", "lr-core")
        self.ls_int = c.cfg_opt("topology", "ls_int", "ls-int-vm")
        self.ls_ext = c.cfg_opt("topology", "ls_ext", "ls-ext-vm")
        self.lrp_int = c.cfg_opt("diagnose", "lrp_int", "lrp-int-vm")
        self.gateway = c.cfg_opt("diagnose", "gateway", "172.31.1.10")
        self.pg_name = c.cfg_opt("vm_isolation", "pg_name", "pg_isolated")
        self.pg_expected = c.cfg_int_opt("diagnose", "pg_expected_members", 4)

        # These two bridges may not exist at all in a single-NIC deployment.
        self.br_internal = c.cfg_opt("localnet_internal", "br_internal",
                                     "br-internal")
        self.br_asa = c.cfg_opt("localnet_external", "br_asa", "")
        self.nic_internal = c.cfg_opt("localnet_internal", "phys_nic", "")
        self.nic_asa = c.cfg_opt("localnet_external", "phys_nic", "")

        self.internal_ranges = c.cfg_list("internal_ranges", "ranges")
        self.external_ranges = c.cfg_list("external_ranges", "ranges")
        self.shadow_ranges = c.cfg_list("shadow_ranges", "ranges")
        self.external_only_ips = c.cfg_list("policy", "external_only_ips")
        self.target_subnets = c.cfg_list("engagement", "target_subnets")

        self.prio_src_override = c.cfg_opt("policy", "priority_source_override", "300")
        self.prio_target = c.cfg_opt("engagement", "priority_target", "250")
        self.prio_shadow = c.cfg_opt("policy", "priority_shadow", "200")
        self.prio_external = c.cfg_opt("policy", "priority_external", "150")
        self.prio_split = c.cfg_opt("policy", "priority_split", "100")

        self.inv = Inventory(c, self.ls_int, self.ls_ext)

        self.tracker = Tracker(ctx)
        self.has_tracker = self.tracker.exists()
        self.flags = self.tracker.flags()

        self.fail_count = 0
        self.warn_count = 0

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------
    @staticmethod
    def section(title: str) -> None:
        print(f"\n=== {title} ===")

    @staticmethod
    def detail(*lines: str) -> None:
        for line in lines:
            print(f"        {line}")

    @staticmethod
    def block(text: str) -> None:
        for line in str(text).splitlines():
            print(f"        {line}")

    def ok(self, msg: str) -> None:
        print(f"{PASS} {msg}")

    def bad(self, msg: str) -> None:
        print(f"{FAIL} {msg}")
        self.fail_count += 1

    def note(self, msg: str) -> None:
        print(f"{WARN} {msg}")
        self.warn_count += 1

    def skip(self, msg: str) -> None:
        print(f"{SKIP} {msg}")

    def not_deployed(self, key: str) -> bool:
        """True if the tracker is active and says this was NOT deployed.

        With no tracker, always False -> every check runs (legacy behaviour).
        """
        return self.has_tracker and not self.flags.get(key, False)

    # ------------------------------------------------------------------
    # 0
    # ------------------------------------------------------------------
    def check_tracker(self) -> None:
        self.section("0. Deployment tracker")
        if not self.has_tracker:
            self.note("No tracker file found -- running ALL checks unconditionally.")
            self.note("(Deploy with the tracker in place to enable gating.)")
            return
        self.ok(f"Tracker active: {self.tracker.path}")
        self.block(self.tracker.show())
        f = self.flags
        self.detail(
            f"setup={f[SETUP]} localnet-internal={f[LOCALNET_INTERNAL]} "
            f"localnet-external={f[LOCALNET_EXTERNAL]}",
            f"vm-config={f[VM_CONFIG]} vm-isolation={f[VM_ISOLATION]} "
            f"acls={f[ACLS]}",
        )

        # Flags that violate the documented run order are suspicious.
        if not f[SETUP] and any(f[k] for k in (LOCALNET_INTERNAL,
                                               LOCALNET_EXTERNAL,
                                               VM_CONFIG, VM_ISOLATION)):
            self.note("Tracker inconsistency: components recorded but 'setup' is not.")
            self.note("Either the teardown partially ran or the tracker was hand-edited.")
        if f[VM_ISOLATION] and not f[VM_CONFIG]:
            self.note("Tracker inconsistency: vm-isolation recorded without vm-config.")

    # ------------------------------------------------------------------
    # 1
    # ------------------------------------------------------------------
    def check_controller_service(self) -> None:
        ctx = self.ctx
        self.section("1. ovn-controller service")
        if not ctx.have("systemctl"):
            self.note("systemctl not found, cannot check service status directly.")
            return
        if ctx.unit_active("ovn-controller"):
            self.ok("ovn-controller service is active.")
            return
        if self.not_deployed(SETUP):
            self.skip("ovn-controller not active -- expected, tracker shows "
                      "setup not run.")
            return
        self.bad("ovn-controller is NOT active.")
        self.detail("-> journalctl -u ovn-controller -e --no-pager | tail -30")
        logs = ctx.qout("journalctl", "-u", "ovn-controller", "-e", "--no-pager")
        if logs:
            self.block("\n".join(logs.splitlines()[-30:]))

    # ------------------------------------------------------------------
    # 2
    # ------------------------------------------------------------------
    def check_br_int(self) -> None:
        ctx = self.ctx
        self.section("2. br-int bridge")
        if ovn.br_exists(ctx, self.br_int):
            self.ok(f"{self.br_int} exists.")
            if "state UP" in ctx.qout("ip", "link", "show", self.br_int):
                self.ok(f"{self.br_int} link state is UP.")
            else:
                self.note(f"{self.br_int} link state is DOWN. Usually harmless for "
                          "OVS internal")
                self.detail("bridges with no physical uplink, but worth noting.")
            return
        if self.not_deployed(SETUP):
            self.skip(f"{self.br_int} does not exist -- expected, tracker shows "
                      "setup not run.")
            return
        self.bad(f"{self.br_int} does not exist. ovn-controller has never "
                 "successfully connected.")

    # ------------------------------------------------------------------
    # 3
    # ------------------------------------------------------------------
    def check_external_ids(self) -> None:
        ctx = self.ctx
        self.section("3. OVS external-ids")
        ids = ctx.qout("ovs-vsctl", "get", "open", ".", "external_ids") or "{}"
        self.detail(ids)
        if ovn.has_external_id(ctx, "ovn-remote"):
            self.ok("ovn-remote is set.")
            return
        if self.not_deployed(SETUP):
            self.skip("ovn-remote not set -- expected, tracker shows setup not run.")
            return
        self.bad("ovn-remote key is missing from external-ids (this is the root "
                 "cause")
        self.detail("if ovn-controller can't reach the SB db -- OVS always shows",
                    "hostname/rundir by default, so the map is never truly '{}').")

    # ------------------------------------------------------------------
    # 4
    # ------------------------------------------------------------------
    def check_chassis(self) -> None:
        ctx = self.ctx
        self.section("4. Chassis registration (Southbound db)")
        if self.not_deployed(SETUP):
            self.skip("Tracker shows setup not run -- no chassis expected yet.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        names = ovn.chassis_names(ctx)
        local_id = ovn.external_id(ctx, "system-id")

        if not names:
            self.bad("No Chassis registered in the Southbound db.")
            self.detail(
                "This means ovn-controller has not successfully connected to",
                "the SB db at the ovn-remote configured in external-ids.",
                "Check: ovs-vsctl get open . external_ids:ovn-remote",
                "Check: ls -l /var/run/ovn/ovnsb_db.sock")
            return

        if len(names) > 1:
            self.bad(f"MULTIPLE chassis registered ({len(names)}) on a "
                     "single-node deployment:")
            self.block("\n".join(names))
            self.detail(
                "This is the classic system-id drift problem (e.g. hostname vs",
                "FQDN changing across reboots). Gateway ports pinned to the OLD",
                f"name will never bind. Local system-id right now: {local_id or '<unset>'}",
                "Fix: pick ONE canonical name, set it in",
                "/etc/openvswitch/system-id.conf AND external-ids:system-id,",
                "delete the stale chassis (ovn-sbctl chassis-del <old>), and",
                "re-pin gateway ports (ovn-nbctl lrp-set-gateway-chassis ...).")
            return

        self.ok(f"Exactly one chassis is registered: {names[0]}")

        # Ghost chassis: a row left in the SB db by a controller that is no
        # longer running. Everything looks registered, nothing binds.
        if not ctx.q("pgrep", "-x", "ovn-controller").ok:
            self.bad("But NO ovn-controller process is running -- this is a GHOST "
                     "chassis")
            self.detail(
                "row left behind by a previous controller. Port bindings will",
                "exist but never bind (cr-lrp-* unbound, VIFs DOWN).",
                "Fix: systemctl stop ovn-controller",
                "     ovn-sbctl --bare --columns=_uuid list Chassis "
                "| xargs -r -n1 ovn-sbctl destroy Chassis",
                "     ovn-sbctl --bare --columns=_uuid list Chassis_Private "
                "| xargs -r -n1 ovn-sbctl destroy Chassis_Private",
                "     systemctl start ovn-controller")
        elif ctx.have("ovn-appctl"):
            conn = ctx.qout("ovn-appctl", "-t", "ovn-controller",
                            "connection-status")
            if conn and "connected" not in conn:
                self.bad(f"ovn-controller is running but its SB connection is "
                         f"'{conn}'.")
            elif conn:
                self.ok(f"ovn-controller SB connection: {conn}")

        if local_id and names[0] != local_id:
            self.bad(f"But local external-ids:system-id ({local_id}) does NOT "
                     "match it.")
            self.detail("ovn-controller may be about to register a second chassis, or",
                        "the registered one is stale from a previous identity.")
        else:
            self.ok("Chassis name matches local external-ids:system-id.")

    # ------------------------------------------------------------------
    # 5
    # ------------------------------------------------------------------
    def check_port_bindings(self) -> None:
        ctx = self.ctx
        self.section(f"5. Port binding state (host-if, {self.lrp_int})")
        if self.not_deployed(SETUP):
            self.skip(f"Tracker shows setup not run -- {self.host_if} not "
                      "expected to exist.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        pb = ctx.qout("ovn-sbctl", "find", "Port_Binding",
                      f"logical_port={self.host_if}")
        if not pb:
            self.bad(f"No Port_Binding found for logical port '{self.host_if}'.")
            self.detail("The logical switch port may not have propagated from "
                        "NB to SB.")
            return

        chassis = ovn.port_binding_chassis(ctx, self.host_if)
        if not chassis or chassis == "[]":
            self.bad(f"{self.host_if} has no chassis bound -- it's not 'up'.")
        else:
            self.ok(f"{self.host_if} port binding exists and has a chassis bound.")
        for line in pb.splitlines():
            if re.search(r"chassis|logical_port|mac", line):
                print(f"        {line}")

    # ------------------------------------------------------------------
    # 5b
    # ------------------------------------------------------------------
    def check_all_port_bindings(self) -> None:
        """Sweep ALL port bindings and flag any that should have a chassis.

        Not every unbound port is a fault: patch/router ports never bind,
        localnet/l2gateway bind differently, and a VIF for a powered-off VM
        is legitimately unbound. So:
          - patch/router/localnet/localport/l2gateway/chassisredirect: skipped
            (cr- ports get their own check in 5c)
          - VIF: FAIL only if the same iface-id is actually plugged into
            local OVS (the VM tap exists), WARN otherwise.
        """
        ctx = self.ctx
        self.section("5b. Full port_binding sweep (missing chassis detection)")
        if self.not_deployed(SETUP):
            self.skip("Tracker shows setup not run -- no port bindings expected.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        if self.has_tracker and not self.flags[VM_CONFIG]:
            self.detail(f"(tracker: vm-config not run -- only {self.host_if} and router",
                        " ports are expected; VM VIFs would be leftovers)")

        ports = ovn.port_binding_ports(ctx)
        if not ports:
            self.bad("No Port_Binding rows at all in the SB db -- NB config has not")
            self.detail("propagated (is ovn-northd running?).")
            return

        non_vif = {"patch", "router", "localnet", "localport", "l2gateway",
                   "chassisredirect"}
        total = bound = skipped = problems = 0
        off_vifs: list[str] = []

        for lp in ports:
            total += 1
            ptype = ovn.port_binding_type(ctx, lp)
            if ptype in non_vif:
                skipped += 1
                continue
            if ovn.port_binding_chassis(ctx, lp):
                bound += 1
                continue
            # Unbound VIF -- is a local OVS interface carrying this iface-id?
            tap = ovn.iface_for_iface_id(ctx, lp)
            if tap:
                self.bad(f"VIF '{lp}' is plugged into local OVS (interface: {tap}) "
                         "but has NO chassis bound.")
                self.detail("The tap exists but ovn-controller never claimed the port.",
                            "This is the reboot-race signature. "
                            "Try: systemctl restart ovn-controller")
                problems += 1
            else:
                off_vifs.append(lp)

        if off_vifs:
            self.note(f"{len(off_vifs)} VIF(s) unbound with no local tap -- "
                      "consistent with powered-off VMs; only a problem if one of "
                      "these should be running:")
            for v in off_vifs:
                self.detail(v)

        self.ok(f"Swept {total} port bindings: {bound} bound, {skipped} non-VIF "
                f"skipped, {len(off_vifs)} powered-off VIF(s), {problems} problem(s).")
        if problems == 0:
            self.ok("No running-but-unbound VIFs detected.")

    # ------------------------------------------------------------------
    # 5c
    # ------------------------------------------------------------------
    def check_chassisredirect(self) -> None:
        """cr-lrp-* ports MUST have a chassis when a gateway is deployed.

        An unbound cr- port means the uplink path is dead even though VMs
        can still talk to each other -- the FreeIPA outage pattern.
        """
        ctx = self.ctx
        self.section("5c. Chassisredirect (gateway) port bindings")
        if self.has_tracker and not self.flags[LOCALNET_INTERNAL] \
                and not self.flags[LOCALNET_EXTERNAL]:
            self.skip("Tracker shows no localnet gateway deployed -- no cr- ports "
                      "expected.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        rows = ovn.sb_records(ctx, "logical_port,chassis", "Port_Binding",
                              "type=chassisredirect")
        if not rows:
            if self.has_tracker:
                self.bad(f"Tracker records a localnet gateway "
                         f"(internal={self.flags[LOCALNET_INTERNAL]}, "
                         f"external={self.flags[LOCALNET_EXTERNAL]})")
                self.detail(
                    "but NO chassisredirect port exists in the SB db. The gateway",
                    "config was lost or never propagated. Check:",
                    f"  ovn-nbctl lrp-list {self.lr_core}     "
                    "(do the uplink lrps exist?)",
                    "  ovn-nbctl --bare --columns=name list Gateway_Chassis",
                    "If the lrp is missing, re-run the localnet command.")
            else:
                self.note("No chassisredirect ports exist. Fine if no localnet "
                          "gateway has")
                self.note("been set up yet; a problem if you expected an uplink "
                          "to exist.")
            return

        for lp, chassis in rows:
            if chassis and chassis != "[]":
                self.ok(f"{lp} is bound to a chassis.")
            else:
                self.bad(f"{lp} has NO chassis bound -- the gateway path through "
                         "this")
                self.detail(
                    "port is DOWN. VM-to-VM traffic will still work, but nothing",
                    "reaches the physical network (this is the FreeIPA outage).",
                    "Likely causes, in order:",
                    "  1) Gateway pinned to a chassis name that no longer exists",
                    "     (see sections 4 and 5d)",
                    "  2) ovn-controller started before the SB db at boot --",
                    "     try: systemctl restart ovn-controller",
                    "  3) ovn-bridge-mappings missing for the physnet",
                    "     (ovs-vsctl get open . external-ids:ovn-bridge-mappings)")

    # ------------------------------------------------------------------
    # 5d
    # ------------------------------------------------------------------
    def check_gateway_pins(self) -> None:
        """Cross-check every gateway-chassis pin against the registered chassis.

        A pin referencing a dead/renamed chassis silently never binds.
        """
        ctx = self.ctx
        self.section("5d. Gateway-chassis pins vs. registered chassis")
        if self.has_tracker and not self.flags[LOCALNET_INTERNAL] \
                and not self.flags[LOCALNET_EXTERNAL]:
            self.skip("Tracker shows no localnet gateway deployed -- no pins "
                      "expected.")
            return
        if not (ctx.have("ovn-nbctl") and ctx.have("ovn-sbctl")):
            self.note("ovn-nbctl/ovn-sbctl not found, skipping.")
            return

        rows = ovn.nb_json(ctx, "name,chassis_name", "Gateway_Chassis")
        pins = [(str(r[0] or ""), str(r[1] or "")) for r in rows]

        if not pins:
            if self.has_tracker:
                self.bad("Tracker records a localnet gateway but NO Gateway_Chassis "
                         "rows")
                self.detail("exist -- the lrp was never pinned or the pin was removed.",
                            "Fix: ovn-nbctl lrp-set-gateway-chassis <lrp> <chassis> 10")
            else:
                self.note("No Gateway_Chassis rows in the NB db. Fine if no uplink "
                          "gateway")
                self.note("is configured; otherwise the lrp was never pinned.")
            return

        registered = set(ovn.chassis_names(ctx))
        for pin_name, pin_chassis in pins:
            if pin_chassis in registered:
                self.ok(f"Pin '{pin_name}' -> chassis '{pin_chassis}' (registered).")
            else:
                self.bad(f"Pin '{pin_name}' references chassis '{pin_chassis}', "
                         "which is")
                self.detail("NOT registered in the SB db. The cr- port for this lrp can",
                            "never bind. Registered chassis right now:")
                for name in sorted(registered):
                    print(f"          {name}")
                self.detail("Fix: ovn-nbctl lrp-set-gateway-chassis <lrp> "
                            "<current-chassis> 10",
                            "(and remove the stale pin / chassis if identity drifted).")

    # ------------------------------------------------------------------
    # 5e
    # ------------------------------------------------------------------
    def check_isolation(self) -> None:
        ctx = self.ctx
        self.section(f"5e. VM isolation ({self.pg_name})")
        if not self.has_tracker:
            self.skip("No tracker -- cannot tell whether isolation is expected; "
                      "not checked.")
            return
        if not self.flags[VM_ISOLATION]:
            self.skip(f"Tracker shows vm-isolation not run -- {self.pg_name} not "
                      "expected.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, skipping.")
            return

        if not ovn.pg_exists(ctx, self.pg_name):
            self.bad(f"Tracker records vm-isolation but port group "
                     f"{self.pg_name} does NOT exist.")
            self.detail(f"The {self.pg_expected} 'isolated' VMs are NOT isolated. "
                        "Re-run `ovnctl vm-isolation`.")
            return
        self.ok(f"Port group {self.pg_name} exists.")

        members = len(ovn.pg_members(ctx, self.pg_name))
        if members == self.pg_expected:
            self.ok(f"{self.pg_name} has the expected {self.pg_expected} members.")
        else:
            self.bad(f"{self.pg_name} has {members} members, expected "
                     f"{self.pg_expected}.")
            self.detail("Membership drifted -- re-run `ovnctl vm-isolation` "
                        "(it recreates",
                        "the group with correct membership).")

        acls = ovn.acl_list(ctx, self.pg_name)
        drops = [a for a in acls if "drop" in a]
        if len(drops) >= 2:
            self.ok(f"{self.pg_name} has {len(drops)} drop ACLs "
                    "(expected 2: from-lport + to-lport).")
        else:
            self.bad(f"{self.pg_name} has only {len(drops)} drop ACL(s), expected 2.")
            self.detail("Isolation is partial or absent -- re-run `ovnctl vm-isolation`.")

        # SCOPE CHECK. Port-group ACLs are installed on every logical switch
        # the group's ports touch; if the match lacks "inport/outport ==
        # @group" it silently drops traffic for NON-members too. acl-list
        # looks perfectly fine in that state.
        scoped = [a for a in acls if f"@{self.pg_name}" in a]
        if len(scoped) < len(acls):
            self.bad(f"One or more ACLs on {self.pg_name} are NOT scoped to the "
                     "port group.")
            self.detail(
                f"Matches must contain 'inport == @{self.pg_name}' (from-lport) or",
                f"'outport == @{self.pg_name}' (to-lport). Without it the rule applies",
                "to EVERY port on the switch -- non-member VMs lose connectivity.",
                "Re-run `ovnctl vm-isolation` (it writes scoped matches).")
        else:
            self.ok(f"All {self.pg_name} ACLs are scoped to group members.")

        # Legacy hyphenated groups keep their unscoped ACLs alive.
        legacy_names = ctx.cfg_list("vm_isolation", "legacy_pg_names") \
            or ["pg-isolated"]
        for legacy in legacy_names:
            if not legacy or legacy == self.pg_name:
                continue
            if ovn.pg_exists(ctx, legacy):
                self.bad(f"Legacy port group '{legacy}' still exists alongside "
                         f"{self.pg_name}.")
                self.detail("Its ACLs are unscoped and will still drop non-member "
                            "traffic.",
                            f"Remove with: ovn-nbctl pg-del {legacy}")

        self._isolation_live_proof()

    def _isolation_live_proof(self) -> None:
        """Live proof: a non-member must not be dropped.

        The shell version tested membership against $_iso_vms, a variable it
        never defined -- so this check either picked the wrong victim or
        never ran. Membership comes from the inventory here.
        """
        ctx = self.ctx
        if not ctx.have("ovn-trace"):
            return
        from ..context import trace_verdict

        iso_uuids = set(self.inv.isolated_uuids)
        victim = next((vm for vm in self.inv.external
                       if vm.uuid not in iso_uuids), None)
        if victim is None:
            return

        lrp_mac = ctx.cfg_opt("setup", "lrp_ext_mac", "")
        if not lrp_mac:
            return
        expr = (f'inport=="{self.ls_ext}-to-lr" && eth.src=={lrp_mac} && '
                f'eth.dst=={victim.mac} && ip4.src=={self.gateway} && '
                f'ip4.dst=={victim.ip} && ip.ttl==63 && icmp4')
        out = ovn.trace(ctx, self.ls_ext, expr)
        if trace_verdict(out) == "DROP":
            self.bad(f"LIVE PROOF: non-member {victim.name} ({victim.ip}) is "
                     "being DROPPED.")
            self.detail("This is a switch-wide outage for every non-isolated VM on",
                        "that switch. Re-run `ovnctl vm-isolation` to fix scoping.")
        else:
            self.ok(f"Live trace: non-member {victim.name} ({victim.ip}) is not "
                    "affected.")

    # ------------------------------------------------------------------
    # 5h
    # ------------------------------------------------------------------
    def check_acls(self) -> None:
        ctx = self.ctx
        from ..context import trace_verdict

        self.section("5h. Micro-segmentation ACLs")
        group_defs = ctx.cfg_list("acls", "port_groups")
        if not group_defs:
            self.skip("No [acls].port_groups defined.")
            return
        if self.not_deployed(ACLS):
            self.skip("Tracker shows the ACL command has not been run.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, skipping.")
            return

        for entry in group_defs:
            parts = entry.split(None, 1)
            pg = parts[0]
            sel = parts[1] if len(parts) > 1 else ""
            if not pg:
                continue
            if not ovn.pg_exists(ctx, pg):
                self.bad(f"Port group {pg} does not exist -- re-run `ovnctl acl`.")
                continue
            members = len(ovn.pg_members(ctx, pg))
            acls = ovn.acl_list(ctx, pg)
            scoped = [a for a in acls if f"@{pg}" in a]
            self.ok(f"{pg} ({sel}): {members} member(s), {len(acls)} ACL(s).")
            if acls and len(scoped) < len(acls):
                self.bad(f"  {len(acls) - len(scoped)} ACL(s) on {pg} are NOT "
                         f"scoped with @{pg}")
                self.detail("-- they apply to every port on the switch.")

        # Prove the lateral rule denies and management still works.
        if not ctx.have("ovn-trace") or len(self.inv.internal) < 2:
            return
        v1, v2 = self.inv.internal[0], self.inv.internal[1]
        hip = ctx.cfg_opt("setup", "host_if_ip", "")
        lmac = ctx.cfg_opt("setup", "lrp_int_mac", "")
        if not (hip and lmac):
            return

        out = ovn.trace(ctx, self.ls_int,
                        f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                        f'eth.dst=={v2.mac} && ip4.src=={v1.ip} && '
                        f'ip4.dst=={v2.ip} && ip.ttl==64 && tcp && tcp.dst==22')
        if trace_verdict(out) == "DROP":
            self.ok(f"Lateral SSH {v1.name} -> {v2.name} is DENIED (correct).")
        else:
            self.bad(f"Lateral SSH {v1.name} -> {v2.name} is ALLOWED -- "
                     "segmentation is not effective.")

        out = ovn.trace(ctx, self.ls_int,
                        f'inport=="{self.ls_int}-to-lr" && eth.src=={lmac} && '
                        f'eth.dst=={v1.mac} && ip4.src=={hip} && '
                        f'ip4.dst=={v1.ip} && ip.ttl==63 && tcp && tcp.dst==22')
        if trace_verdict(out) == "DROP":
            self.bad(f"Management SSH {hip} -> {v1.name} is DENIED -- you have "
                     "locked yourself out.")
        else:
            self.ok(f"Management SSH {hip} -> {v1.name} is allowed (correct).")

    # ------------------------------------------------------------------
    # 5i
    # ------------------------------------------------------------------
    def check_port_security(self) -> None:
        """lsp-set-port-security binds a port to its MAC+IP.

        Several controls match on ip4.src -- the priority-300 ASA override,
        the management-SSH allow -- so a VM able to spoof a source address
        can route around them. This check exists because the command was
        once misspelled AND error-suppressed, so it failed silently on every
        deployment and nobody noticed.
        """
        ctx = self.ctx
        self.section("5i. VM port security")
        if self.not_deployed(VM_CONFIG):
            self.skip("Tracker shows vm-config not run -- no VM ports expected.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, skipping.")
            return
        if not self.inv.all:
            self.skip("No VMs in [vm_config].")
            return

        missing = 0
        ok_count = 0
        for vm in self.inv.all:
            ps = ovn.port_security(ctx, vm.uuid)
            if not ps:
                missing += 1
            elif vm.ip in ps and vm.mac in ps:
                ok_count += 1
            else:
                self.bad(f"{vm.name}: port security is set but does not match "
                         "the inventory.")
                self.detail(f"expected: {vm.mac} {vm.ip}", f"actual:   {ps}")

        if missing > 0:
            self.bad(f"{missing} of {len(self.inv.all)} VM port(s) have NO port "
                     "security.")
            self.detail(
                "Those guests can forge their MAC and source IP. Because the",
                "ASA reroute policy and the management-SSH allow both match on",
                "ip4.src, a spoofing VM can bypass them.",
                "Fix: re-run `ovnctl vm-config`.")
        else:
            self.ok(f"All {ok_count} VM port(s) have port security matching the "
                    "inventory.")

    # ------------------------------------------------------------------
    # 5f
    # ------------------------------------------------------------------
    def check_range_overlap(self) -> None:
        ctx = self.ctx
        self.section("5f. Range overlap & policy tiers")

        if not self.internal_ranges:
            self.skip("No [internal_ranges] configured -- nothing to compare.")
            return

        self.detail(f"internal: {' '.join(self.internal_ranges)}")
        if not self.external_ranges:
            self.skip("No [external_ranges] declared -- exclusion-only policy, "
                      "no ambiguity possible.")
        else:
            self.detail(f"external: {' '.join(self.external_ranges)}")
            if self.shadow_ranges:
                self.detail(f"shadow:   {' '.join(self.shadow_ranges)}")

            overlaps = netcalc.find_overlaps(self.internal_ranges,
                                             self.external_ranges)
            if overlaps:
                for i, e, d in overlaps:
                    self.detail(f"collision: internal {i} vs external {e} on {d}")
                if self.shadow_ranges:
                    self.ok("Overlap present but RESOLVED via shadow space "
                            f"({' '.join(self.shadow_ranges)}).")
                    self.detail(
                        "Real addresses stay internal; shadow addresses reach the",
                        "ASA-side twin. Confirm the matching NAT entries exist on",
                        "the ASA -- OVN cannot verify the far side.")
                else:
                    self.bad("Overlap present and UNRESOLVED (no [shadow_ranges] "
                             "configured).")
                    self.detail(
                        "Colliding addresses are reachable via ONE path only.",
                        "Fix: add a shadow range + ASA NAT, narrow the prefixes,",
                        "or list affected VMs in [policy].external_only_ips.")
            else:
                self.ok("Internal and external ranges are disjoint.")

        if self.target_subnets:
            self.detail(f"engagement targets: {' '.join(self.target_subnets)}")
            colliding = False
            for t in self.target_subnets:
                if netcalc.find_overlaps([t], self.internal_ranges):
                    colliding = True
                    self.detail(f"{t} overrides an internal range "
                                "(expected for this engagement)")
            if not colliding:
                self.note(f"No listed target collides with our ranges -- the "
                          f"priority-{self.prio_split} rule would have covered "
                          "them anyway; listing them is harmless.")
        else:
            self.skip("No engagement targets listed (normal -- unknown "
                      "destinations are")
            self.detail(f"covered by the priority-{self.prio_split} "
                        "not-internal rule).")

        self._check_policy_tiers()

    def _check_policy_tiers(self) -> None:
        ctx = self.ctx
        if self.not_deployed(LOCALNET_EXTERNAL):
            self.skip("Tracker shows the ASA split path is not deployed -- "
                      "tiers not checked.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, cannot verify policy tiers.")
            return

        tiers = (
            (self.prio_src_override, "source-override", len(self.external_only_ips)),
            (self.prio_target, "engagement-targets", len(self.target_subnets)),
            (self.prio_shadow, "shadow", len(self.shadow_ranges)),
            (self.prio_external, "external", len(self.external_ranges)),
            (self.prio_split, "split", 1),
        )
        for prio, label, expected in tiers:
            present = len(ovn.policy_uuids(ctx, prio))
            if expected > 0:
                if present > 0:
                    self.ok(f"Tier {prio} ({label}): present.")
                else:
                    self.bad(f"Tier {prio} ({label}): configured in yaml but NO "
                             "policy exists.")
                    self.detail("Re-run `ovnctl localnet-external` to apply it.")
            else:
                if present > 0:
                    self.note(f"Tier {prio} ({label}): a policy exists but nothing "
                              "is configured")
                    self.note("for it in the yaml -- possible leftover from an "
                              "earlier run.")
                else:
                    self.skip(f"Tier {prio} ({label}): not configured, none present.")

    # ------------------------------------------------------------------
    # 5g
    # ------------------------------------------------------------------
    def check_duplicate_delivery(self) -> None:
        """Duplicate-delivery detection (the 'DUP!' symptom).

        A ping answered twice means the request reached the target twice, or
        two things replied. Every cause below also duplicates TCP segments,
        so it degrades far more than ICMP.
        """
        ctx = self.ctx
        self.section("5g. Duplicate delivery (DUP! causes)")
        found = 0

        found += self._dup_iface_ids()
        found += self._dup_logical_addresses()
        found += self._dup_inventory()
        found += self._dup_additional_chassis()
        found += self._dup_kernel_addresses()
        found += self._dup_shared_segment()

        if found == 0:
            self.ok("No duplicate-delivery causes detected.")
        else:
            print("")
            self.detail(
                f"{found} probable cause(s) of 'DUP!' found above. To confirm which",
                "leg duplicates, capture while pinging one VM:",
                f"  tcpdump -nni {self.br_int} icmp        # OVN's view",
                "  tcpdump -nni <vm tap> icmp        # request arriving twice?")

    def _dup_iface_ids(self) -> int:
        """Two OVS interfaces carrying one iface-id: OVN binds both and
        delivers to both. Cloned domain XMLs are the usual origin."""
        ctx = self.ctx
        if not ctx.have("ovs-vsctl"):
            return 0
        out = ctx.qout("ovs-vsctl", "--bare", "--columns=external_ids", "list",
                       "Interface")
        ids = re.findall(r'iface-id=([^,}"\s]+)', out)
        dupes = [k for k, n in Counter(ids).items() if n > 1]
        if dupes:
            self.bad("Duplicate iface-id on more than one local OVS interface:")
            for d in dupes:
                print(f"          {d}")
            self.detail("Each of these logical ports is plugged in twice, so every",
                        "packet to it is delivered twice. Fix the duplicated",
                        "interfaceid in the libvirt domain XML.")
            return 1
        self.ok("No duplicate iface-id among local OVS interfaces.")
        return 0

    def _dup_logical_addresses(self) -> int:
        ctx = self.ctx
        if not ctx.have("ovn-nbctl"):
            return 0
        addrs = ctx.qout("ovn-nbctl", "--bare", "--columns=addresses", "list",
                         "Logical_Switch_Port")
        found = 0
        macs = [m.lower() for m in _MAC_RE.findall(addrs)]
        dup_mac = [k for k, n in Counter(macs).items() if n > 1]
        if dup_mac:
            self.bad("Duplicate MAC across logical switch ports:")
            for d in dup_mac:
                print(f"          {d}")
            found += 1
        else:
            self.ok("No duplicate MAC among logical switch ports.")

        ips = _IP_RE.findall(addrs)
        dup_ip = [k for k, n in Counter(ips).items() if n > 1]
        if dup_ip:
            self.bad("Duplicate IP across logical switch ports:")
            for d in dup_ip:
                print(f"          {d}")
            found += 1
        else:
            self.ok("No duplicate IP among logical switch ports.")
        return found

    def _dup_inventory(self) -> int:
        """Catch it at the source, before it is ever applied."""
        if not self.inv.all:
            return 0
        found = 0
        for label, values in (("UUID", [v.uuid for v in self.inv.all]),
                              ("MAC", [v.mac for v in self.inv.all]),
                              ("IP", [v.ip for v in self.inv.all])):
            dupes = [k for k, n in Counter(values).items() if n > 1]
            if dupes:
                self.bad(f"Duplicate {label} in yaml [vm_config]:")
                for d in dupes:
                    print(f"          {d}")
                found += 1
        if found == 0:
            self.ok("yaml [vm_config] inventory has no duplicate UUID/MAC/IP.")
        return found

    def _dup_additional_chassis(self) -> int:
        """additional_chassis exists for live migration; if it is populated
        here, duplicate delivery is by design."""
        ctx = self.ctx
        if not ctx.have("ovn-sbctl"):
            return 0
        probe = ctx.q("ovn-sbctl", "--columns=additional_chassis", "list",
                      "Port_Binding")
        if not probe.ok:
            return 0
        found = 0
        for lp in ovn.port_binding_ports(ctx):
            extra = ctx.qout("ovn-sbctl", "--bare",
                             "--columns=additional_chassis", "find",
                             "Port_Binding", f"logical_port={lp}")
            if extra.strip():
                self.bad(f"Port '{lp}' has additional_chassis set ({extra}).")
                self.detail("Traffic to it is delivered to more than one chassis.")
                found += 1
        if found == 0:
            self.ok("No port binding has additional_chassis set.")
        return found

    def _dup_kernel_addresses(self) -> int:
        """An IP left on a bridge or its physical member means the kernel
        answers alongside OVN."""
        ctx = self.ctx
        found = 0
        for ifn in (self.br_internal, self.br_asa, self.nic_internal,
                    self.nic_asa):
            if not ifn:
                continue
            if not ctx.q("ip", "link", "show", ifn).ok:
                continue
            if "inet " in ctx.qout("ip", "-4", "addr", "show", "dev", ifn):
                self.bad(f"{ifn} has a kernel IPv4 address but OVN should own "
                         "this path.")
                self.block(ctx.qout("ip", "-br", "-4", "addr", "show", "dev", ifn))
                self.detail("The kernel will reply alongside OVN. Remove it, and set the",
                            "NIC unmanaged in NetworkManager so it does not come back.")
                found += 1
        return found

    def _dup_shared_segment(self) -> int:
        """A MAC learned on both bridges means frames flooded out one come
        back in the other."""
        ctx = self.ctx
        if not self.br_asa or not ctx.have("ovs-appctl"):
            return 0
        if not (ovn.br_exists(ctx, self.br_internal)
                and ovn.br_exists(ctx, self.br_asa)):
            return 0

        def fdb(bridge: str) -> set[str]:
            out = ctx.qout("ovs-appctl", "fdb/show", bridge)
            macs = set()
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    macs.add(parts[1])
            return macs

        both = fdb(self.br_internal) & fdb(self.br_asa)
        if both:
            self.bad(f"MAC(s) learned on BOTH {self.br_internal} and {self.br_asa}:")
            for m in sorted(both):
                print(f"          {m}")
            self.detail("The two uplink NICs appear to share a physical segment, so",
                        "flooded frames loop back in. Separate the VLANs/switch ports.")
            return 1
        self.ok("No MAC learned on both uplink bridges.")
        return 0

    # ------------------------------------------------------------------
    # 6
    # ------------------------------------------------------------------
    def check_flows(self) -> None:
        ctx = self.ctx
        self.section(f"6. OpenFlow rules on {self.br_int}")
        if self.not_deployed(SETUP):
            self.skip("Tracker shows setup not run -- no flows expected.")
            return
        if not ctx.have("ovs-ofctl"):
            self.note("ovs-ofctl not found, skipping.")
            return
        out = ctx.qout("ovs-ofctl", "dump-flows", self.br_int)
        count = sum(1 for ln in out.splitlines() if "cookie=" in ln)
        if count == 0:
            self.bad(f"Zero flows programmed on {self.br_int}.")
            self.detail("This confirms ovn-controller isn't programming the pipeline --",
                        "almost always caused by #1 (service not running) or "
                        "#4 (no chassis).")
        else:
            self.ok(f"{count} flow entries present on {self.br_int}.")

    # ------------------------------------------------------------------
    # 7
    # ------------------------------------------------------------------
    def check_host_if(self) -> None:
        ctx = self.ctx
        self.section(f"7. {self.host_if} OVS interface")
        if self.not_deployed(SETUP):
            self.skip(f"Tracker shows setup not run -- {self.host_if} not "
                      "expected to exist.")
            return
        iface_id = ctx.qout("ovs-vsctl", "get", "interface", self.host_if,
                            "external_ids:iface-id").strip('"')
        admin = ctx.qout("ovs-vsctl", "get", "interface", self.host_if,
                         "admin_state").strip('"')
        link = ctx.qout("ovs-vsctl", "get", "interface", self.host_if,
                        "link_state").strip('"')
        if iface_id == self.host_if:
            self.ok(f"iface-id is set correctly ({iface_id}).")
        else:
            self.bad(f"iface-id is '{iface_id}', expected '{self.host_if}'.")
        self.detail(f"admin_state={admin} link_state={link}")

    # ------------------------------------------------------------------
    # 8
    # ------------------------------------------------------------------
    def check_live_arp(self) -> None:
        ctx = self.ctx
        self.section(f"8. Live ARP test for gateway {self.gateway}")
        if self.not_deployed(SETUP):
            self.skip(f"Tracker shows setup not run -- gateway {self.gateway} "
                      "not expected to answer.")
            return

        if ctx.have("arping"):
            cmd = ["arping", "-I", self.host_if, "-c", "2", "-w", "2",
                   self.gateway]
        else:
            self.note("arping not installed, falling back to ping "
                      "(less conclusive).")
            cmd = ["ping", "-c", "2", "-W", "1", self.gateway]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  check=False, timeout=15)
            output = (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = str(exc)

        if re.search(r"1 received|1 packets received|reply from", output,
                     re.IGNORECASE):
            self.ok(f"Got a response from {self.gateway}.")
        else:
            self.bad(f"No response from {self.gateway}.")
            self.block(output)

    # ------------------------------------------------------------------
    def summary(self) -> None:
        self.section("Summary / likely next step")
        print(f"Result: {self.fail_count} failure(s), {self.warn_count} warning(s).")
        if self.has_tracker:
            print("Tracker gating was ACTIVE -- [SKIP] sections were not counted.")
        else:
            print("No tracker file -- all sections ran unconditionally.")
        print("")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-diagnose")
    # Deliberately NOT requiring the localnet_external keys: a single-NIC
    # deployment does not have them, and refusing to run any check because
    # of that is exactly the failure this port is fixing.
    ctx.require_cfg("localnet_internal:br_internal", "localnet_internal:phys_nic",
                    "setup:host_if_ip", "setup:lrp_ext_mac", "setup:lrp_int_mac",
                    "topology:ls_ext", "topology:ls_int")
    ctx.require_root()

    d = Diagnose(ctx)
    runner = StepRunner(ctx, "diagnose")
    runner.add("tracker", "deployment tracker state", d.check_tracker)
    runner.add("controller", "ovn-controller service", d.check_controller_service)
    runner.add("br-int", "the integration bridge", d.check_br_int)
    runner.add("external-ids", "OVS external-ids", d.check_external_ids)
    runner.add("chassis", "chassis registration in the SB db", d.check_chassis)
    runner.add("port-bindings", "host-if port binding", d.check_port_bindings)
    runner.add("port-binding-sweep", "every port binding, missing chassis",
               d.check_all_port_bindings)
    runner.add("chassisredirect", "gateway port bindings", d.check_chassisredirect)
    runner.add("gateway-pins", "gateway-chassis pins vs registered chassis",
               d.check_gateway_pins)
    runner.add("isolation", "isolation port group and its scope",
               d.check_isolation)
    runner.add("acls", "micro-segmentation ACLs", d.check_acls)
    runner.add("port-security", "VM port security", d.check_port_security)
    runner.add("range-overlap", "range overlap and policy tiers",
               d.check_range_overlap)
    runner.add("duplicate-delivery", "causes of duplicated packets",
               d.check_duplicate_delivery)
    runner.add("flows", "OpenFlow rules on br-int", d.check_flows)
    runner.add("host-if", "the host-facing OVS interface", d.check_host_if)
    runner.add("live-arp", "live ARP/ping test of the gateway", d.check_live_arp)
    runner.add("summary", "the failure/warning tally", d.summary)

    if not runner.run(args):
        return 0
    return 1 if d.fail_count else 0
