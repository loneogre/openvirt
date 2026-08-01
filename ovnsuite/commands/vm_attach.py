"""
ovnctl vm-attach -- port of ovn-vm-attach.sh

Re-attaches running VMs' tap interfaces to br-int with the correct
iface-id, without restarting the guests.

Why this is needed: deleting br-int (as `ovnctl delete` does) detaches
every running VM's tap from OVS. libvirt only plugs a tap in when a domain
starts, so after a teardown + redeploy the guests keep running with a tap
attached to nothing -- their ports show "DOWN (no chassis)" forever.
Rebooting works only because it restarts the guests.

Taps are matched to logical ports by MAC using [vm_config], so a mismatch
is reported rather than silently wired to the wrong port.
"""

from __future__ import annotations

import argparse
import time

from .. import libvirtutil, ovn
from ..context import Abort, Ctx
from ..inventory import VM, Inventory
from ..steps import StepRunner, add_step_args

NAME = "vm-attach"
HELP = "re-attach running VM taps to br-int"

# How long to wait for ovn-controller to claim a freshly attached port.
#
# This used to be a flat 3-second sleep followed by an immediate status
# print, which is why `ovnctl deploy` could report every VM as
# "DOWN (no chassis)" on a deployment that was in fact fine thirty seconds
# later. Claiming is not instant, and it is slowest in exactly the case
# where this command matters most: right after `delete --purge-db`, when
# ovn-controller is rebuilding its whole view and computing several
# hundred thousand flows.
DEFAULT_TIMEOUT = 60


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--status", action="store_true",
                   help="show what is attached vs not, and change nothing")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   metavar="SECONDS",
                   help=f"how long to wait for ports to bind "
                        f"(default: {DEFAULT_TIMEOUT})")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class VMAttach:
    def __init__(self, ctx: Ctx, timeout: int = DEFAULT_TIMEOUT):
        self.ctx = ctx
        self.br_int = ctx.cfg("topology", "br_int")
        self.timeout = timeout
        self.inv = Inventory(ctx.config)
        if not self.inv.all:
            raise Abort("No [vm_config] inventory in ovn-settings.yaml -- "
                        "cannot map taps to ports.")
        ctx.log(f"Loaded {len(self.inv.all)} VMs from the inventory.")
        self.attached = 0
        self.skipped = 0
        self.unknown = 0
        # Every VM that has a live tap this run, attached now or already
        # attached. These are the ones that SHOULD end up bound, and the
        # only ones worth waiting on -- a powered-off VM has no tap and
        # will never bind, which is not a fault.
        self.expect_bound: list[tuple[VM, str]] = []

    # ------------------------------------------------------------------
    def check_bridge(self) -> None:
        if not ovn.br_exists(self.ctx, self.br_int):
            raise Abort(f"{self.br_int} does not exist. Run `ovnctl setup` first.")

    # ------------------------------------------------------------------
    def attach(self) -> None:
        ctx = self.ctx
        domains = libvirtutil.running_domains(ctx)
        if not domains:
            ctx.log("No running VMs.")
            return

        ctx.dr_head(f"Re-attach VM taps to {self.br_int}")
        bridge_ports = ovn.list_ports(ctx, self.br_int)

        for domain in domains:
            for iface in libvirtutil.domiflist(ctx, domain):
                vm = self.inv.by_mac(iface.mac)
                if vm is None:
                    ctx.warn(f"{domain}: tap {iface.tap} has MAC {iface.mac}, "
                             "which is not in the inventory.")
                    ctx.warn("  Not attaching -- fix [vm_config] or the domain "
                             "XML first.")
                    self.unknown += 1
                    continue

                self.expect_bound.append((vm, iface.tap))

                if iface.tap in bridge_ports:
                    current = ovn.iface_id_of(ctx, iface.tap)
                    if current == vm.uuid:
                        ctx.log(f"  {domain}/{iface.tap} ({vm.name}) already "
                                "attached correctly.")
                        self.skipped += 1
                        continue
                    ctx.warn(f"{domain}/{iface.tap} is attached with iface-id "
                             f"'{current}', expected '{vm.uuid}'. Correcting.")

                ctx.run("ovs-vsctl", "--may-exist", "add-port", self.br_int,
                        iface.tap, "--", "set", "interface", iface.tap,
                        f"external-ids:iface-id={vm.uuid}")
                ctx.log(f"  attached {domain}/{iface.tap} -> {vm.name} ({vm.uuid})")
                self.attached += 1

        if ctx.dry_run:
            return

        print("")
        ctx.log(f"Attached {self.attached}, already correct {self.skipped}, "
                f"unmatched {self.unknown}.")

    # ------------------------------------------------------------------
    def wait_for_bindings(self) -> None:
        """Wait until every tap that should be claimed actually is.

        Polls the SB db rather than sleeping a fixed interval. The old
        3-second sleep was a guess, and it was wrong in the one situation
        this command exists for: straight after `delete --purge-db`,
        ovn-controller is rebuilding from an empty SB db and has several
        hundred thousand flows to compute, so a claim can take far longer
        than three seconds. Deploy then printed "DOWN (no chassis)" for a
        deployment that came good on its own a minute later, which is
        indistinguishable from a real failure.
        """
        ctx = self.ctx
        if ctx.dry_run or not self.expect_bound:
            return

        pending = list(self.expect_bound)
        ctx.log(f"Waiting up to {self.timeout}s for ovn-controller to claim "
                f"{len(pending)} port(s)...")
        nudged = False
        deadline = time.time() + self.timeout

        while pending and time.time() < deadline:
            still: list[tuple[VM, str]] = []
            for vm, tap in pending:
                if ovn.port_binding_chassis(ctx, vm.uuid):
                    ctx.log(f"  {vm.name} bound.")
                else:
                    still.append((vm, tap))
            pending = still
            if not pending:
                break

            # One nudge, halfway through. ovn-controller claims a port in
            # response to the iface-id appearing; if that event was missed
            # -- the SB Port_Binding row not having propagated from the NB
            # db yet is the usual reason, and a purge makes it likely --
            # nothing will re-fire it on its own. Clearing and re-setting
            # the key produces the event again.
            if not nudged and time.time() > deadline - self.timeout / 2:
                nudged = True
                ctx.log("  Still unclaimed -- re-asserting iface-id to "
                        "re-trigger the claim.")
                for vm, tap in pending:
                    ctx.run("ovs-vsctl", "remove", "interface", tap,
                            "external-ids", "iface-id")
                    ctx.run("ovs-vsctl", "set", "interface", tap,
                            f"external-ids:iface-id={vm.uuid}")
            time.sleep(2)

        if not pending:
            ctx.log("All expected ports are bound.")
            return

        ctx.warn(f"{len(pending)} port(s) still unbound after {self.timeout}s:")
        for vm, tap in pending:
            ctx.warn(f"  {vm.name} ({vm.uuid}) tap {tap}")
        ctx.warn("The VMs are running and their taps are on the bridge, so "
                 "this is")
        ctx.warn("ovn-controller not claiming them. Check:")
        ctx.warn("  journalctl -u ovn-controller -e --no-pager | tail -30")
        ctx.warn("  ovnctl diagnose")

    # ------------------------------------------------------------------
    def print_status(self) -> None:
        """The resulting table.

        A VM with no tap is powered off and was never going to bind, so it
        gets its own state rather than the same "DOWN (no chassis)" as a
        running VM whose port failed to be claimed. Printing ten identical
        alarming rows, nine of which are normal, trains people to ignore
        the one that matters.
        """
        ctx = self.ctx
        chassis_names = ovn.chassis_uuid_names(ctx)
        print("")
        print("=== Port binding status ===")
        print(f"{'VM':<10} {'PORT (iface-id)':<38} {'TAP':<10} CHASSIS")
        problems = 0
        for vm in self.inv.all:
            tap = ovn.iface_for_iface_id(ctx, vm.uuid)
            chassis = ovn.port_binding_chassis(ctx, vm.uuid)
            if chassis:
                state = f"bound @{chassis_names.get(chassis, chassis[:12])}"
            elif not tap:
                state = "no tap -- VM not running"
            else:
                state = "UNBOUND -- tap present, not claimed"
                problems += 1
            print(f"{vm.name:<10} {vm.uuid:<38} {tap or '-':<10} {state}")
        if problems:
            print("")
            print(f"{problems} running VM(s) are not bound. Re-run "
                  "`ovnctl vm-attach`, then `ovnctl diagnose`.")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-attach")
    ctx.require_cfg("topology:br_int")
    ctx.require_root()

    cmd = VMAttach(ctx, timeout=getattr(args, "timeout", DEFAULT_TIMEOUT))

    if args.status:
        cmd.print_status()
        return 0

    # No libvirt CLI on this host means there are no taps for us to re-plug
    # -- that is a no-op, not a deployment failure. Exiting non-zero here
    # would break the chain in `ovnctl deploy`.
    if not libvirtutil.available(ctx) and not ctx.listing:
        ctx.warn("virsh not found -- nothing to re-attach, skipping.")
        return 0
    ctx.require_cmd("ovs-vsctl")

    runner = StepRunner(ctx, "vm-attach")
    runner.add("check-bridge", "verify br-int exists", cmd.check_bridge)
    runner.add("attach", "re-attach every running VM's tap", cmd.attach)
    runner.add("wait", "wait for ovn-controller to claim the ports",
               cmd.wait_for_bindings)
    runner.add("status", "print the resulting port binding table",
               cmd.print_status)

    if not runner.run(args):
        return 0
    return 0