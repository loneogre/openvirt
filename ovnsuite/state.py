"""
Shared deployment-state tracker (port of ovn-state.sh).

Each command records a flag here when it completes, removes its own flag
on --remove, and ``ovnctl delete`` truncates the whole file.
``ovnctl diagnose`` reads the flags to know which checks are meaningful --
there is no point failing on a missing gateway port if the gateway command
was never run.

State file format: one flag per line, "key <ISO-8601 timestamp>".

The tracker is ADVISORY. Commands must never hard-fail because a flag is
missing -- the OVN database itself is always the source of truth. The
tracker only records what was *intended* to be deployed, so diagnose can
tell "not configured yet" apart from "broken".
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import paths

# Known keys, in documented run order.
SETUP = "setup"
LOCALNET_INTERNAL = "localnet-internal"
LOCALNET_EXTERNAL = "localnet-external"
VM_CONFIG = "vm-config"
VM_ISOLATION = "vm-isolation"
ACLS = "acls"

ALL_KEYS = (SETUP, LOCALNET_INTERNAL, LOCALNET_EXTERNAL,
            VM_CONFIG, VM_ISOLATION, ACLS)


class Tracker:
    """Reader/writer for the tracker file.

    Pass the Ctx so writes can honour --dry-run. The shell suite called
    ``state_mark`` unconditionally, so ``./ovn-setup.sh --dry-run`` wrote
    a 'setup' flag and every later ``ovn-diagnose.sh`` run then believed
    the deployment existed -- a preview that changes what the next
    diagnosis reports is worse than no preview at all. Writes here are
    no-ops in a dry run.
    """

    def __init__(self, ctx=None, path: Path | None = None):
        self.ctx = ctx
        self.path: Path = Path(path) if path else paths.state_file()

    @property
    def _readonly(self) -> bool:
        return bool(self.ctx is not None and getattr(self.ctx, "dry_run", False))

    # ------------------------------------------------------------------
    def _read(self) -> list[str]:
        if not self.path.is_file():
            return []
        return self.path.read_text(encoding="utf-8").splitlines()

    def _write(self, lines: list[str]) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                "".join(f"{ln}\n" for ln in lines if ln.strip()), encoding="utf-8"
            )
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    def mark(self, key: str) -> bool:
        """Record a deployed component (idempotent: refreshes the timestamp)."""
        if self._readonly:
            return True
        stamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        lines = [ln for ln in self._read() if not ln.startswith(f"{key} ")]
        lines.append(f"{key} {stamp}")
        return self._write(lines)

    def unmark(self, key: str) -> bool:
        """Remove a single component's flag (each command's --remove path)."""
        if self._readonly:
            return True
        if not self.path.is_file():
            return True
        return self._write([ln for ln in self._read()
                            if not ln.startswith(f"{key} ")])

    def has(self, key: str) -> bool:
        return any(ln.startswith(f"{key} ") for ln in self._read())

    def exists(self) -> bool:
        """True if the tracker file exists at all, even empty.

        An existing-but-empty file means "tracking is in use and nothing is
        deployed", which is different from "tracking has never been used".
        """
        return self.path.is_file()

    def clear(self) -> bool:
        """Truncate the tracker, keeping the file so diagnose knows it is active."""
        if self._readonly:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")
            return True
        except OSError:
            return False

    def show(self) -> str:
        if not self.path.is_file():
            return "(no tracker file -- state tracking not in use)"
        content = self.path.read_text(encoding="utf-8").strip()
        if not content:
            return "(tracker present, no components recorded -- clean slate)"
        return content

    def flags(self) -> dict[str, bool]:
        return {key: self.has(key) for key in ALL_KEYS}


def record(ctx, key: str, runner=None) -> None:
    """Mark a component deployed -- but only if the whole command ran.

    ``ovnctl setup --only switches`` does a fraction of the work, so
    recording 'setup' would tell diagnose to expect a host interface, a
    router and gateway ports that were never created, and every one of
    those checks would then be reported as a failure rather than as
    'not deployed yet'. A partial run leaves the flag alone and says so.
    """
    if runner is not None and getattr(runner, "partial", False):
        ctx.log(f"Partial run -- not recording '{key}' in the deployment tracker.")
        return
    if Tracker(ctx).mark(key):
        ctx.log(f"Recorded '{key}' in deployment tracker.")
    else:
        ctx.warn(f"Could not write the deployment tracker at {paths.state_file()}.")
