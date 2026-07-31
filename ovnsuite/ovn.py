"""
Thin helpers around ovn-nbctl / ovn-sbctl / ovs-vsctl.

These are all READ-ONLY queries. Mutating commands stay as explicit
``ctx.run("ovn-nbctl", ...)`` calls in the command modules so they remain
visible in the --dry-run listing exactly as the shell version printed them.
"""

from __future__ import annotations

import json

from .context import Ctx


# ---------------------------------------------------------------------------
# ovs-vsctl
# ---------------------------------------------------------------------------
def br_exists(ctx: Ctx, bridge: str) -> bool:
    return ctx.q("ovs-vsctl", "br-exists", bridge).ok


def list_br(ctx: Ctx) -> list[str]:
    return ctx.q("ovs-vsctl", "list-br").lines


def list_ports(ctx: Ctx, bridge: str) -> list[str]:
    return ctx.q("ovs-vsctl", "list-ports", bridge).lines


def iface_type(ctx: Ctx, iface: str) -> str:
    return ctx.qout("ovs-vsctl", "get", "interface", iface, "type").strip('"')


def external_id(ctx: Ctx, key: str) -> str:
    """A single key out of Open_vSwitch external-ids ('' if unset)."""
    res = ctx.q("ovs-vsctl", "get", "open", ".", f"external-ids:{key}")
    return res.stdout.strip('"') if res.ok else ""


def has_external_id(ctx: Ctx, key: str) -> bool:
    return ctx.q("ovs-vsctl", "get", "open", ".", f"external-ids:{key}").ok


def iface_for_iface_id(ctx: Ctx, iface_id: str) -> str:
    """The local OVS interface carrying this OVN logical port, if any."""
    out = ctx.qout("ovs-vsctl", "--bare", "--columns=name", "find", "Interface",
                   f"external-ids:iface-id={iface_id}")
    return out.splitlines()[0].strip() if out.strip() else ""


def iface_id_map(ctx: Ctx) -> dict[str, str]:
    """Every local OVS interface carrying an iface-id: iface-id -> name.

    One query for the whole table. iface_for_iface_id() is the same lookup
    for a single id; use this one when more than a couple are wanted.
    """
    rows = _json_rows(
        ctx.qout("ovs-vsctl", "--format=json", "--columns=name,external_ids",
                 "list", "Interface"), "name,external_ids")
    found: dict[str, str] = {}
    for row in rows:
        if len(row) < 2:
            continue
        for key, value in _json_map(row[1]):
            if key == "iface-id" and value:
                found.setdefault(value, str(row[0]))
    return found


def iface_id_of(ctx: Ctx, iface: str) -> str:
    res = ctx.q("ovs-vsctl", "get", "interface", iface, "external-ids:iface-id")
    return res.stdout.strip('"') if res.ok else ""


def mirror_exists(ctx: Ctx, name: str) -> bool:
    out = ctx.qout("ovs-vsctl", "--bare", "--columns=_uuid", "find", "Mirror",
                   f"name={name}")
    return bool(out.strip())


# ---------------------------------------------------------------------------
# ovn-nbctl
# ---------------------------------------------------------------------------
def nb_exists(ctx: Ctx, table: str, name: str) -> bool:
    return ctx.q("ovn-nbctl", "list", table, name).ok


def lr_exists(ctx: Ctx, router: str) -> bool:
    return nb_exists(ctx, "Logical_Router", router)


def ls_exists(ctx: Ctx, switch: str) -> bool:
    return nb_exists(ctx, "Logical_Switch", switch)


def lsp_exists(ctx: Ctx, port: str) -> bool:
    return nb_exists(ctx, "Logical_Switch_Port", port)


def lrp_list(ctx: Ctx, router: str) -> str:
    return ctx.qout("ovn-nbctl", "lrp-list", router)


def lrp_present(ctx: Ctx, router: str, port: str) -> bool:
    return port in lrp_list(ctx, router)


def lsp_list(ctx: Ctx, switch: str) -> str:
    return ctx.qout("ovn-nbctl", "lsp-list", switch)


def pg_uuid(ctx: Ctx, name: str) -> str:
    return ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid", "find",
                    "Port_Group", f"name={name}").strip()


def pg_exists(ctx: Ctx, name: str) -> bool:
    return bool(pg_uuid(ctx, name))


def pg_members(ctx: Ctx, name: str) -> list[str]:
    out = ctx.qout("ovn-nbctl", "--bare", "--columns=ports", "list",
                   "Port_Group", name)
    return out.split()


def acl_list(ctx: Ctx, target: str) -> list[str]:
    return ctx.q("ovn-nbctl", "acl-list", target).lines


def policy_uuids(ctx: Ctx, priority: int | str) -> list[str]:
    out = ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid", "find",
                   "Logical_Router_Policy", f"priority={priority}")
    return [u for u in out.split() if u]


def policies_with_match(ctx: Ctx, priority: int | str) -> list[tuple[str, str]]:
    """(_uuid, match) pairs for every policy at this priority.

    ``--bare --columns=_uuid,match`` emits one value per line with a blank
    line between records, so records are paired up here rather than with
    the shell version's ``paste - -`` (which silently mis-pairs whenever a
    match contains a newline).
    """
    out = ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid,match", "find",
                   "Logical_Router_Policy", f"priority={priority}")
    pairs: list[tuple[str, str]] = []
    for record in out.split("\n\n"):
        lines = [ln for ln in record.splitlines() if ln.strip()]
        if len(lines) >= 2:
            pairs.append((lines[0].strip(), lines[1].strip()))
        elif len(lines) == 1:
            pairs.append((lines[0].strip(), ""))
    return pairs


def port_security(ctx: Ctx, port: str) -> str:
    return ctx.qout("ovn-nbctl", "--bare", "--columns=port_security", "list",
                    "Logical_Switch_Port", port)


def _json_rows(out: str, columns: str) -> list[list]:
    """`--format=json` output -> rows, in the order the columns were asked for.

    ovsdb reports what it actually returned in "headings"; keying off that
    rather than trusting the order of --columns costs nothing and means a
    reordered response cannot silently shift every field by one.
    """
    if not out:
        return []
    try:
        parsed = json.loads(out)
        data = parsed.get("data", [])
        headings = parsed.get("headings", [])
    except (ValueError, AttributeError):
        return []
    want = [c.strip() for c in columns.split(",")]
    if headings and headings != want and all(c in headings for c in want):
        idx = [headings.index(c) for c in want]
        return [[row[i] if i < len(row) else "" for i in idx] for row in data]
    return data


def _json_map(value) -> list[tuple[str, str]]:
    """An ovsdb map column (['map', [[k, v], ...]]) as pairs."""
    if isinstance(value, list) and len(value) == 2 and value[0] == "map":
        return [(str(p[0]), str(p[1])) for p in value[1] if len(p) == 2]
    return []


def ref_is_set(value) -> bool:
    """True if an ovsdb reference column actually points at a row.

    JSON renders an unset reference as ['set', []] and a set one as
    ['uuid', '...']. A bare truthiness test calls the empty case True.
    """
    if isinstance(value, list) and len(value) == 2 and value[0] == "set":
        return bool(value[1])
    return bool(value)


def nb_json(ctx: Ctx, columns: str, table: str, *extra: str) -> list[list]:
    """`ovn-nbctl --format=json --columns=... list TABLE` -> rows."""
    return _json_rows(
        ctx.qout("ovn-nbctl", "--format=json", f"--columns={columns}",
                 "list", table, *extra), columns)


# ---------------------------------------------------------------------------
# ovn-sbctl
# ---------------------------------------------------------------------------
def chassis_names(ctx: Ctx) -> list[str]:
    return ctx.q("ovn-sbctl", "--bare", "--columns=name", "list", "Chassis").lines


def first_chassis(ctx: Ctx) -> str:
    names = chassis_names(ctx)
    return names[0] if names else ""


def port_binding_chassis(ctx: Ctx, logical_port: str) -> str:
    return ctx.qout("ovn-sbctl", "--bare", "--columns=chassis", "find",
                    "Port_Binding", f"logical_port={logical_port}").strip()


def port_binding_type(ctx: Ctx, logical_port: str) -> str:
    return ctx.qout("ovn-sbctl", "--bare", "--columns=type", "find",
                    "Port_Binding", f"logical_port={logical_port}").strip()


def port_binding_ports(ctx: Ctx) -> list[str]:
    return ctx.q("ovn-sbctl", "--bare", "--columns=logical_port", "list",
                 "Port_Binding").lines


def sb_json(ctx: Ctx, columns: str, table: str, *extra: str) -> list[list]:
    """`ovn-sbctl --format=json --columns=... list TABLE` -> rows.

    Preferred over sb_records() for multi-column reads: --bare prints an
    empty column as a blank line and uses a blank line as the record
    separator too, so an empty column in the MIDDLE of the list (a VIF's
    'type', an unbound port's 'chassis') is indistinguishable from the end
    of a record. JSON has no such ambiguity.
    """
    return _json_rows(
        ctx.qout("ovn-sbctl", "--format=json", f"--columns={columns}",
                 "list", table, *extra), columns)


def sb_records(ctx: Ctx, columns: str, table: str,
               *find: str) -> list[list[str]]:
    """`ovn-sbctl --bare --columns=a,b find TABLE ...` -> list of records.

    Records are separated by blank lines and each column is on its own
    line. A VIF's 'type' column is an EMPTY STRING, which --bare prints as
    a blank line -- and a blank line is also the record separator. The
    shell version's ``awk RS=""`` split every VIF record in half because of
    this; here the record shape is reconstructed by padding short records
    instead of assuming they are well-formed.
    """
    ncols = len(columns.split(","))
    verb = "find" if find else "list"
    out = ctx.qout("ovn-sbctl", "--bare", f"--columns={columns}", verb, table,
                   *find)
    records: list[list[str]] = []
    for record in out.split("\n\n"):
        if not record.strip():
            continue
        fields = record.splitlines()
        fields += [""] * (ncols - len(fields))
        records.append([f.strip() for f in fields[:ncols]])
    return records


# ---------------------------------------------------------------------------
# ovn-trace
# ---------------------------------------------------------------------------
def trace(ctx: Ctx, datapath: str, expr: str) -> str:
    """Run ovn-trace and return combined output (stderr included).

    ovn-trace reports parse errors on stderr, and a trace that failed to
    parse must not be read as ALLOW.
    """
    res = ctx.q("ovn-trace", datapath, expr)
    return "\n".join(p for p in (res.stdout, res.stderr) if p)