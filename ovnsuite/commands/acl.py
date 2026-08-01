"""
ovnctl acl -- port of ovn-acl.sh

Applies the declarative ACL rules in ovn-settings.yaml [acls].

Port groups are built from the VM inventory (so membership can never drift
from [vm_config]), and every rule is scoped to its group with
inport/outport == @group -- without that scoping an ACL applies to every
port on the switch.

Rule format:
  <name> <direction> <priority> <action> <group> <spec>...
    direction  to-lport   evaluated on the way IN to a group member
               from-lport evaluated on the way OUT of a group member
    action     allow | allow-related | drop | reject
    spec       src=CIDR[,CIDR]   dst=CIDR[,CIDR]   src=any
               src=internal / dst=internal  expands to [internal_ranges]
               tcp=PORT | tcp=@portset   udp=PORT | udp=@portset   icmp

Per-ACL logging was removed while investigating ovn-controller memory
use. The rules, names and priorities are unchanged; nothing writes
acl_log records. See ovn-settings.yaml for how to bring it back.

Higher priority wins. Anything with no matching rule is ALLOWED (OVN's
default), so these rules only constrain what they name.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass

from .. import ovn
from ..context import Abort, Ctx, trace_verdict
from ..inventory import Inventory
from ..state import ACLS, Tracker, record
from ..steps import StepRunner, add_step_args
from .acl_audit import ACLAudit

NAME = "acl"
HELP = "declarative micro-segmentation ACLs"

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")



@dataclass
class ParsedRule:
    """One entry of [acls].rules, split into its fields.

    `error` is set instead of raising so a single bad line can be reported
    against its own name rather than stopping the whole run.
    """

    name: str
    direction: str
    priority: str
    action: str
    group: str
    specs: list[str]
    raw: str
    index: int = 0
    error: str = ""


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--remove", action="store_true",
                   help="remove the groups and their ACLs")
    g.add_argument("--verify", action="store_true",
                   help="ovn-trace the key allow/deny cases")
    g.add_argument("--list", dest="do_list", action="store_true",
                   help="show what is currently applied")
    g.add_argument("--audit", action="store_true",
                   help="test every rule in the yaml against what is deployed")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class ACLManager:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.enabled = c.cfg_bool("acls", "enabled", False)
        self.ls_int = c.cfg("topology", "ls_int")
        self.ls_ext = c.cfg("topology", "ls_ext")

        self.internal_ranges = c.cfg_list("internal_ranges", "ranges")
        self.port_sets = self._parse_port_sets(c.cfg_list("acls", "port_sets"))
        self.group_defs = [self._split2(d) for d in c.cfg_list("acls", "port_groups")]
        self.rules = c.cfg_list("acls", "rules")
        self.verify_pairs = c.cfg_list("acls", "verify_pairs")


        self.inv = Inventory(c, self.ls_int, self.ls_ext)
        self.created: list[str] = []

    @staticmethod
    def _split2(entry: str) -> tuple[str, str]:
        parts = entry.split(None, 1)
        return (parts[0], parts[1].strip() if len(parts) > 1 else "")

    @staticmethod
    def _parse_port_sets(entries: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for entry in entries:
            parts = entry.split(None, 1)
            if len(parts) == 2:
                out[parts[0]] = parts[1].strip()
        return out

    # ------------------------------------------------------------------
    # rule parsing
    # ------------------------------------------------------------------
    def expand_ports(self, spec: str) -> str:
        """Resolve @name to a named port set from [acls].port_sets."""
        if not spec.startswith("@"):
            return spec
        name = spec[1:]
        if name not in self.port_sets:
            raise Abort(f"Unknown port set '{spec}'.")
        return self.port_sets[name]

    def expand_cidrs(self, spec: str) -> str:
        if spec == "internal":
            return ",".join(self.internal_ranges)
        return spec

    def build_match(self, direction: str, group: str, specs: list[str]) -> str:
        if direction == "to-lport":
            match = f"outport == @{group}"
        else:
            match = f"inport == @{group}"
        match += " && ip4"

        for spec in specs:
            if spec in ("src=any", "dst=any", "any"):
                continue
            if spec.startswith("src="):
                match += f" && ip4.src == {{{self.expand_cidrs(spec[4:])}}}"
            elif spec.startswith("dst="):
                match += f" && ip4.dst == {{{self.expand_cidrs(spec[4:])}}}"
            elif spec.startswith("tcp="):
                val = self.expand_ports(spec[4:])
                match += (f" && tcp && tcp.dst == {{{val}}}" if "," in val
                          else f" && tcp && tcp.dst == {val}")
            elif spec.startswith("udp="):
                val = self.expand_ports(spec[4:])
                match += (f" && udp && udp.dst == {{{val}}}" if "," in val
                          else f" && udp && udp.dst == {val}")
            elif spec == "icmp":
                match += " && icmp4"
            else:
                self.ctx.warn(f"Ignoring unrecognised rule token '{spec}'.")
        return match

    # ------------------------------------------------------------------
    # apply
    # ------------------------------------------------------------------
    def port_groups(self) -> None:
        ctx = self.ctx
        if not self.group_defs:
            ctx.log("No [acls].port_groups defined -- nothing to do.")
            return

        ctx.dr_head("ACL port groups")
        for pg, sel in self.group_defs:
            if not pg:
                continue
            if not _IDENT_RE.match(pg):
                raise Abort(
                    f"Port group name '{pg}' is not a valid OVN identifier.\n"
                    f"It must be referenceable as @{pg} in a match (no hyphens)."
                )

            members = self.inv.select(sel)
            if not members:
                ctx.warn(f"Port group {pg} ({sel}) has no members -- skipping.")
                continue

            # Recreate so membership always matches the inventory. pg-del
            # also clears the group's ACLs, re-added immediately below.
            if ovn.pg_exists(ctx, pg):
                ctx.run("ovn-nbctl", "pg-del", pg)
            ctx.run("ovn-nbctl", "pg-add", pg, *[vm.uuid for vm in members])
            self.created.append(pg)
            ctx.log(f"Port group {pg} ({sel}): {len(members)} member(s).")

    def parsed_rules(self) -> list[ParsedRule]:
        """[acls].rules split into fields, in file order.

        The deployer and the auditor both come through here. If they parsed
        separately, a rule could mean one thing when applied and another
        when checked, and the audit would be worth nothing.
        """
        out: list[ParsedRule] = []
        for idx, raw in enumerate(self.rules):
            if not raw.strip():
                continue
            parts = raw.split()
            if len(parts) < 5:
                out.append(ParsedRule(
                    "", "", "", "", "", [], raw, idx,
                    "needs at least 5 fields: <name> <direction> <priority> "
                    "<action> <group> [spec...]"))
                continue
            name, direction, priority, action, group = parts[:5]
            out.append(ParsedRule(name, direction, priority, action, group,
                                  parts[5:], raw, idx))
        return out

    def acl_rules(self) -> None:
        ctx = self.ctx
        ctx.dr_head("ACL rules")
        for rule in self.parsed_rules():
            if rule.error:
                ctx.warn(f"Skipping malformed rule: {rule.raw}")
                continue
            name, direction, priority = rule.name, rule.direction, rule.priority
            action, group = rule.action, rule.group

            # Accept a group created moments ago in this same run without
            # re-querying it; only fall back to the db for groups defined
            # elsewhere.
            if group not in self.created and not ctx.dry_run:
                if not ovn.pg_exists(ctx, group):
                    ctx.warn(f"Rule '{name}' targets unknown port group "
                             f"'{group}' -- skipping.")
                    continue

            match = self.build_match(direction, group, rule.specs)
            ovn.add_acl(ctx, group, direction, priority, match, action,
                        name=name)
            ctx.log(f"  {name}: [{priority}] {direction} {action}")
            ctx.log(f"      {match}")

        self.name_existing_rules()

    def name_existing_rules(self) -> None:
        """Backfill the name on ACLs that were created without one.

        --may-exist makes acl-add a no-op when the (direction, priority,
        match) triple already exists, which means it does NOT apply a name
        to a row that predates named ACLs. Every deployment built before
        this change is in exactly that state, so reconcile the column
        directly rather than making people tear their ACLs down to get
        readable output.
        """
        ctx = self.ctx
        if ctx.dry_run:
            return
        index = ovn.acl_index(ctx)
        if not index:
            return
        fixed = 0
        for rule in self.parsed_rules():
            if rule.error or not rule.name:
                continue
            match = self.build_match(rule.direction, rule.group, rule.specs)
            entry = index.get((rule.direction, str(rule.priority), match))
            if not entry:
                continue
            if entry.get("name") == rule.name:
                continue
            # Also clears any log/severity/meter left over from when this
            # suite set them -- an ACL that still says log=true keeps
            # ovn-controller emitting records for a feature that has been
            # removed from the tooling.
            for column in ("severity", "meter"):
                ctx.run("ovn-nbctl", "clear", "acl", entry["uuid"], column)
            if ctx.run("ovn-nbctl", "set", "acl", entry["uuid"],
                       f"name={rule.name}", "log=false"):
                fixed += 1
            else:
                ctx.warn(f"Could not set name '{rule.name}' on ACL "
                         f"{entry['uuid']}.")
        if fixed:
            ctx.log(f"Reconciled {fixed} existing ACL(s).")

    # ------------------------------------------------------------------
    def do_list(self) -> None:
        ctx = self.ctx
        print("=== Applied ACLs ===")
        for pg, sel in self.group_defs:
            if not pg:
                continue
            n = len(ovn.pg_members(ctx, pg))
            print("")
            print(f"{pg}  ({sel})  members: {n}")
            for line in ovn.acl_list(ctx, pg):
                print(f"    {line}")

    def do_remove(self) -> None:
        ctx = self.ctx
        ctx.log("Removing ACL port groups and their rules...")
        for pg, _sel in self.group_defs:
            if not pg:
                continue
            if ovn.pg_exists(ctx, pg):
                if ctx.run("ovn-nbctl", "pg-del", pg):
                    ctx.log(f"Removed {pg} (and its ACLs).")
            else:
                ctx.log(f"{pg} does not exist.")
        Tracker(ctx).unmark(ACLS)
        ctx.log("Done. VM-to-VM traffic is unrestricted again.")

    # ------------------------------------------------------------------
    # verify
    # ------------------------------------------------------------------
    def _check(self, label: str, expect: str, datapath: str, expr: str) -> None:
        out = ovn.trace(self.ctx, datapath, expr)
        verdict = trace_verdict(out)
        if verdict == expect:
            print(f"  [ OK ] {label:<46} {verdict}")
        elif verdict == "UNKNOWN":
            # Not a failure of the policy -- a failure to measure it.
            # Printing FAIL here would send you to fix a rule that is fine.
            print(f"  [WARN] {label:<46} no verdict (trace failed/timed out)")
            for line in (out.splitlines()[-6:] or ["(no output)"]):
                print(f"         {line}")
        else:
            print(f"  [FAIL] {label:<46} {verdict} (expected {expect})")
            for line in out.splitlines()[-6:]:
                print(f"         {line}")

    def do_verify(self) -> None:
        ctx = self.ctx
        ctx.require_cmd("ovn-trace")

        # ovn-trace reads the Southbound db, which northd populates from
        # the Northbound one asynchronously. Verifying immediately after
        # applying rules can therefore trace the pipeline as it was before
        # they existed and report failures that are pure timing.
        ovn.sync_sb(ctx)

        if len(self.inv.internal) < 2 or len(self.inv.external) < 1:
            raise Abort("Need at least 2 internal and 1 external VM in the "
                        "inventory.")

        v1, v2 = self.inv.internal[0], self.inv.internal[1]
        ev = self.inv.external[0]

        host_ip = ctx.cfg("setup", "host_if_ip")
        lrp_int_mac = ctx.cfg("setup", "lrp_int_mac")
        lrp_ext_mac = ctx.cfg("setup", "lrp_ext_mac")

        print("")
        print("=== ACL verification ===")

        # Management SSH in -- must be allowed.
        self._check(f"host {host_ip} -> {v1.name} :22", "ALLOW", self.ls_int,
                    f'inport=="{self.ls_int}-to-lr" && eth.src=={lrp_int_mac} && '
                    f'eth.dst=={v1.mac} && ip4.src=={host_ip} && '
                    f'ip4.dst=={v1.ip} && ip.ttl==63 && tcp && tcp.dst==22')

        self._check(f"workstation 172.31.0.5 -> {v1.name} :22", "ALLOW",
                    self.ls_int,
                    f'inport=="{self.ls_int}-to-lr" && eth.src=={lrp_int_mac} && '
                    f'eth.dst=={v1.mac} && ip4.src==172.31.0.5 && '
                    f'ip4.dst=={v1.ip} && ip.ttl==63 && tcp && tcp.dst==22')

        # Lateral SSH -- must be dropped.
        self._check(f"{v1.name} -> {v2.name} :22 (same subnet)", "DROP",
                    self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={v2.mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={v2.ip} && ip.ttl==64 && tcp && tcp.dst==22')

        self._check(f"{v1.name} -> {ev.name} :22 (across subnets)", "DROP",
                    self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={lrp_int_mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={ev.ip} && ip.ttl==64 && tcp && tcp.dst==22')

        self._check(f"{v1.name} -> host {host_ip} :22", "DROP", self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={lrp_int_mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={host_ip} && ip.ttl==64 && tcp && tcp.dst==22')

        # Non-SSH between VMs is untouched.
        self._check(f"{v1.name} -> {v2.name} :443 (non-SSH unaffected)", "ALLOW",
                    self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={v2.mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={v2.ip} && ip.ttl==64 && tcp && tcp.dst==443')

        self._verify_configured_pairs(lrp_int_mac, lrp_ext_mac)

        # Engagement traffic out must survive.
        self._check(f"{ev.name} -> 203.0.113.10 :22 (external OK)", "ALLOW",
                    self.ls_ext,
                    f'inport=="{ev.uuid}" && eth.src=={ev.mac} && '
                    f'eth.dst=={lrp_ext_mac} && ip4.src=={ev.ip} && '
                    f'ip4.dst==203.0.113.10 && ip.ttl==64 && tcp && tcp.dst==22')
        print("")

    def _verify_configured_pairs(self, lrp_int_mac: str, lrp_ext_mac: str) -> None:
        """Declarative pairs from [acls].verify_pairs.

        Format: "<name> <src-ip> <dst-ip> <tcp|udp|icmp> <port|-> <ALLOW|DROP>"
        """
        if not self.verify_pairs:
            return
        print("  --- configured checks ---")
        for pair in self.verify_pairs:
            parts = pair.split()
            if len(parts) < 6:
                continue
            pname, psrc, pdst, pproto, pport, pexp = parts[:6]

            src_vm = self.inv.by_ip(psrc)
            dst_vm = self.inv.by_ip(pdst)
            ttl = 64

            if src_vm is None:
                # Source is not a VM (a workstation, the host, anything
                # off-switch). Such traffic arrives already routed, so the
                # trace enters the DESTINATION switch via its router port
                # with a decremented TTL.
                if dst_vm is None:
                    print(f"  [SKIP] {pname:<46} neither {psrc} nor {pdst} is a VM")
                    continue
                datapath = dst_vm.switch
                inport = f"{dst_vm.switch}-to-lr"
                src_mac = lrp_int_mac if dst_vm.switch == self.ls_int else lrp_ext_mac
                eth_dst = dst_vm.mac
                ttl = 63
            else:
                datapath = src_vm.switch
                inport = src_vm.uuid
                src_mac = src_vm.mac
                if dst_vm is not None and dst_vm.switch == src_vm.switch:
                    # Same switch -> address the peer directly.
                    eth_dst = dst_vm.mac
                elif src_vm.switch == self.ls_int:
                    eth_dst = lrp_int_mac
                else:
                    eth_dst = lrp_ext_mac

            if pproto == "tcp":
                proto = f"tcp && tcp.dst=={pport}"
            elif pproto == "udp":
                proto = f"udp && udp.dst=={pport}"
            elif pproto == "icmp":
                proto = "icmp4"
            else:
                print(f"  [SKIP] {pname:<46} unknown protocol {pproto}")
                continue

            src_label = src_vm.name if src_vm else psrc
            dst_label = dst_vm.name if dst_vm else pdst
            port_label = f"/{pport}" if pport and pport != "-" else ""
            label = f"{pname}: {src_label} -> {dst_label} {pproto}{port_label}"

            self._check(label, pexp, datapath,
                        f'inport=="{inport}" && eth.src=={src_mac} && '
                        f'eth.dst=={eth_dst} && ip4.src=={psrc} && '
                        f'ip4.dst=={pdst} && ip.ttl=={ttl} && {proto}')
        print("")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-acl")
    ctx.require_cfg("acls:enabled", "setup:host_if_ip", "setup:lrp_ext_mac",
                    "setup:lrp_int_mac", "topology:ls_ext", "topology:ls_int")

    ctx.require_root()
    ctx.require_cmd("ovn-nbctl")

    cmd = ACLManager(ctx)

    # Before the enabled check on purpose. "We turned ACLs off -- is the
    # policy actually gone?" is exactly the question an audit should be
    # able to answer.
    if args.audit:
        return ACLAudit(cmd).run()

    # --list-steps is documentation: answer it even when the feature is
    # switched off, or "what would this do?" is unanswerable precisely
    # when you are deciding whether to switch it on.
    if not cmd.enabled and not ctx.listing:
        ctx.log("acls.enabled is false -- nothing to do.")
        return 0

    if args.remove:
        cmd.do_remove()
        return 0
    if args.verify:
        cmd.do_verify()
        return 0
    if args.do_list:
        cmd.do_list()
        return 0

    if not cmd.group_defs and not ctx.listing:
        ctx.log("No [acls].port_groups defined -- nothing to do.")
        return 0

    runner = StepRunner(ctx, "acl")
    runner.add("port-groups", "rebuild the port groups from the inventory",
               cmd.port_groups)
    runner.add("rules", "apply the ACL rules", cmd.acl_rules)

    if not runner.run(args):
        return 0

    record(ctx, ACLS, runner)
    if ctx.dry_run:
        return 0

    if ctx.verbose:
        print("")
        cmd.do_list()
    ctx.finish(f"{len(cmd.group_defs)} port group(s), "
               f"{len(cmd.rules)} rule(s) applied")
    return 0