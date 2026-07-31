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
from ..inventory import Inventory
from ..steps import StepRunner, add_step_args

NAME = "vm-attach"
HELP = "re-attach running VM taps to br-int"


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--status", action="store_true",
                   help="show what is attached vs not, and change nothing")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class VMAttach:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.br_int = ctx.cfg("topology", "br_int")
        self.inv = Inventory(ctx.config)
        if not self.inv.all:
            raise Abort("No [vm_config] inventory in ovn-settings.yaml -- "
                        "cannot map taps to ports.")
        ctx.log(f"Loaded {len(self.inv.all)} VMs from the inventory.")
        self.attached = 0
        self.skipped = 0
        self.unknown = 0

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
        if self.attached > 0:
            ctx.log("Waiting 3s for ovn-controller to claim the ports...")
            time.sleep(3)

    # ------------------------------------------------------------------
    def print_status(self) -> None:
        ctx = self.ctx
        print("")
        print("=== Port binding status ===")
        print(f"{'VM':<10} {'PORT (iface-id)':<38} {'TAP':<10} CHASSIS")
        for vm in self.inv.all:
            tap = ovn.iface_for_iface_id(ctx, vm.uuid)
            chassis = ovn.port_binding_chassis(ctx, vm.uuid)
            print(f"{vm.name:<10} {vm.uuid:<38} {tap or '-':<10} "
                  f"{chassis or 'DOWN (no chassis)'}")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-attach")
    ctx.require_cfg("topology:br_int")
    ctx.require_root()

    cmd = VMAttach(ctx)

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
    runner.add("status", "print the resulting port binding table",
               cmd.print_status)

    if not runner.run(args):
        return 0
    return 0
