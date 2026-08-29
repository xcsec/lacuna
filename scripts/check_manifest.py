#!/usr/bin/env python3
"""LACUNA -- validate a port's emitted CSV against the shared structure manifest.

Seven ports are implemented in seven vendor trees by seven agents working in
parallel.  Nothing stops them from inventing a different name for the same
program shape, a different acceptance predicate, or a different idea of what a
"control" is -- and nothing would notice until the seven corpora were merged and
found to be incomparable.  This script is what notices.

It checks three things, in this order:

  1. THE MANIFEST IS INTERNALLY SOUND.  Every structure has all seven target
     cells, every enumerated field holds a legal value, every blocked cell
     carries a reason, and every capability flag exists on every target.  Run
     with no CSV argument to do only this.

  2. THE SEVEN FROZEN NAMES ARE STILL THE SEVEN FROZEN NAMES.  The exact strings
     in `FROZEN_PUBLISHED_NAMES` below are hard-coded here on purpose.  They are
     the values already sitting in the `program_structure` column of
     the published candidates table, and every published table keys on them.  A
     rename in the manifest -- an en dash for the two hyphens in "Store--load",
     a lower-cased "state" -- silently orphans a published number, so the guard
     against it must live somewhere the manifest cannot edit.

  3. A PORT'S CSV USES ONLY MANIFEST VOCABULARY.  `program_structure` must be a
     manifest `published_name`; `operand_source` and `candidate_class` must be
     present and legal; new `seed_id`s must follow the naming convention; and a
     row must not claim a cell the manifest declares blocked unless it is
     declared a control.

WHY THERE IS NO YAML DEPENDENCY.  The manifest is authored as YAML because seven
people will hand-edit it.  Emitting a parallel .json would give two artefacts
that drift.  So this script parses the YAML itself, with a loader restricted to
the exact subset the manifest is written in -- block mappings, block sequences,
and scalars that are one of true / false / null / a number / a double-quoted
string whose only escapes are \\" \\\\ \\n \\r \\t.  The loader RAISES on anything outside that subset rather
than guessing, so a file it accepts means what it looks like it means.  Pass
--emit-json to get a JSON rendering for downstream consumers; it is a
convenience output, never a second source of truth.

Usage:
  check_manifest.py                                   # manifest self-check only
  check_manifest.py path/to/candidates.csv [more.csv] # + CSV conformance
  check_manifest.py --spec DIR --emit-json OUT.json
  check_manifest.py --against-published <published-candidates>.csv
"""
import argparse
import csv
import json
import os
import re
import sys

# Resolve the spec relative to THIS file so the artifact is self-contained wherever it is
# unpacked. Layout: <root>/scripts/check_manifest.py and <root>/spec/*.yaml. The legacy
# source-repo layout (<root>/evaluation/spec) is accepted as a fallback.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_DIR = os.environ.get("LACUNA_SPEC_DIR") or os.path.join(ROOT, "spec")
if not os.path.isdir(SPEC_DIR):
    SPEC_DIR = os.path.join(ROOT, "evaluation", "spec")

# Hard-coded on purpose -- see docstring point 2.  Do not read these from the
# manifest; the whole point is to be able to detect the manifest changing them.
FROZEN_PUBLISHED_NAMES = {
    "st_single_op": "Single operation",
    "st_store_load": "Store--load",
    "st_control_flow": "Control flow",
    "st_hazard_chain": "Hazard chain",
    "st_initial_state": "Initial state",
    "st_redirect": "Redirect",
    "st_whole_program": "Whole program",
}

TARGETS = ["pico", "sp1", "ceno", "nexus", "openvm", "risc0", "zisk"]

STATUS = {"already_implemented", "trivial", "moderate", "hard", "blocked", "not_determined"}
CANDIDATE_CLASS = {"probe", "control", "calibration"}
OPERAND_SOURCE = {"input", "hint", "immediate"}
SITE_ROLE = {"value", "address", "selector", "syscall_arg"}
MUTATION_MODE = {"encoding", "binding", "both"}
PREDICATE = {"accepted_case_strict", "accepted_case_v2"}
OBSERVABILITY = {"observable", "state_object_only", "observable_only_under_v2",
                 "not_observable_control", "calibration_expected_accept", "not_determined"}
CAP_FLAGS = ["nth_supported", "mem_read_hookable", "address_hookable", "timestamp_hookable",
             "init_value_hookable", "final_value_hookable", "next_pc_hookable",
             "hint_hookable", "x0_hookable"]
CAP_VALUES = {True, False, "partial", "not_determined"}

# Seed ids that predate the naming convention and are frozen as published
# artefacts.  st_single_op alone accounts for three incompatible legacy
# patterns, one per port family; regularising them would orphan published rows.
LEGACY_SEED_ID_PATTERNS = [
    re.compile(r"^op_[a-z0-9]+$"),          # pico / sp1 / ceno / nexus / openvm
    re.compile(r"^op_[a-z0-9]+_mem$"),      # sp1 Store--load
    re.compile(r"^[A-Z]+_single_op$"),      # risc0
    re.compile(r"^(add|and|divu|mul|mulhu|sll)$"),  # zisk
    re.compile(r"^fib$"),                   # pico Whole program
]


# --------------------------------------------------------------------------
# A YAML loader for exactly the subset the manifest is written in.
# --------------------------------------------------------------------------
KEY_RE = re.compile(r"^([A-Za-z0-9_.\-]+):(?: (.*))?$")
ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}


class YamlSubsetError(Exception):
    pass


def _scalar(text, lineno):
    s = text.strip()
    if s == "null":
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    if s == "[]":
        return []
    if s == "{}":
        return {}
    if s.startswith('"'):
        if not s.endswith('"') or len(s) < 2:
            raise YamlSubsetError("line %d: unterminated double-quoted scalar" % lineno)
        body, out, i = s[1:-1], [], 0
        while i < len(body):
            c = body[i]
            if c == "\\":
                if i + 1 >= len(body):
                    raise YamlSubsetError("line %d: trailing backslash" % lineno)
                nxt = body[i + 1]
                if nxt not in ESCAPES:
                    raise YamlSubsetError(
                        "line %d: unsupported escape \\%s (the subset allows only "
                        "\\\" \\\\ \\n \\r \\t)" % (lineno, nxt))
                out.append(ESCAPES[nxt])
                i += 2
            else:
                if c == '"':
                    raise YamlSubsetError("line %d: unescaped quote inside a quoted scalar" % lineno)
                out.append(c)
                i += 1
        return "".join(out)
    for cast in (int, float):
        try:
            return cast(s)
        except ValueError:
            pass
    raise YamlSubsetError(
        "line %d: %r is outside the allowed subset. Strings must be double-quoted." % (lineno, s))


def _tokenize(text):
    toks = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlSubsetError("line %d: tab in indentation" % lineno)
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        if body == "-":
            toks.append((indent, "item", None, lineno))
        elif body.startswith("- "):
            toks.append((indent, "item", None, lineno))
            toks.append((indent + 2, "line", body[2:], lineno))
        else:
            toks.append((indent, "line", body, lineno))
    return toks


def _parse(toks, i, indent):
    if toks[i][1] == "item":
        out = []
        while i < len(toks) and toks[i][0] == indent and toks[i][1] == "item":
            i += 1
            if i < len(toks) and toks[i][0] > indent:
                v, i = _parse(toks, i, toks[i][0])
            else:
                v = None
            out.append(v)
        return out, i
    m = KEY_RE.match(toks[i][2])
    if not m:                                  # a bare scalar, e.g. a list element
        return _scalar(toks[i][2], toks[i][3]), i + 1
    out = {}
    while i < len(toks) and toks[i][0] == indent and toks[i][1] == "line":
        _, _, body, lineno = toks[i]
        m = KEY_RE.match(body)
        if not m:
            raise YamlSubsetError("line %d: expected `key:` or `key: value`, got %r" % (lineno, body))
        key, rest = m.group(1), m.group(2)
        if key in out:
            raise YamlSubsetError("line %d: duplicate key %r" % (lineno, key))
        i += 1
        if rest is None or rest == "":
            if i < len(toks) and toks[i][0] > indent:
                out[key], i = _parse(toks, i, toks[i][0])
            else:
                out[key] = None
        else:
            out[key] = _scalar(rest, lineno)
    return out, i


def load_yaml_subset(path):
    with open(path, encoding="utf-8") as fh:
        toks = _tokenize(fh.read())
    if not toks:
        raise YamlSubsetError("%s: empty" % path)
    doc, i = _parse(toks, 0, toks[0][0])
    if i != len(toks):
        raise YamlSubsetError("%s: trailing content at line %d" % (path, toks[i][3]))
    return doc


# --------------------------------------------------------------------------
class Report(object):
    def __init__(self):
        self.errors = []
        self.warnings = []

    def err(self, where, msg):
        self.errors.append("%s: %s" % (where, msg))

    def warn(self, where, msg):
        self.warnings.append("%s: %s" % (where, msg))


def check_manifest(man, rep):
    where = "STRUCTURE_MANIFEST.yaml"
    structures = man.get("structures") or []
    if not structures:
        rep.err(where, "no structures")
        return {}
    by_id, names = {}, {}
    for s in structures:
        sid = s.get("id")
        if not sid:
            rep.err(where, "a structure has no id")
            continue
        if sid in by_id:
            rep.err(where, "duplicate structure id %r" % sid)
        by_id[sid] = s
        pub = s.get("published_name")
        if not pub:
            rep.err(where, "%s: no published_name" % sid)
        elif pub in names:
            rep.err(where, "published_name %r used by both %s and %s" % (pub, names[pub], sid))
        else:
            names[pub] = sid

    # --- the frozen-name guard --------------------------------------------
    for sid, pub in sorted(FROZEN_PUBLISHED_NAMES.items()):
        s = by_id.get(sid)
        if s is None:
            rep.err(where, "FROZEN structure %s is missing from the manifest" % sid)
            continue
        if s.get("published_name") != pub:
            rep.err(where, "FROZEN NAME RENAMED: %s must publish as %r, manifest says %r. "
                           "the published candidates table keys on the frozen string."
                    % (sid, pub, s.get("published_name")))
        if s.get("published_name_frozen") is not True:
            rep.err(where, "%s must carry published_name_frozen: true" % sid)
    declared = man.get("frozen_published_names") or []
    if sorted(declared) != sorted(FROZEN_PUBLISHED_NAMES.values()):
        rep.err(where, "frozen_published_names does not match the seven frozen strings: %r" % (declared,))
    for sid, s in by_id.items():
        if sid not in FROZEN_PUBLISHED_NAMES and s.get("published_name_frozen") is True:
            rep.err(where, "%s claims published_name_frozen but is not one of the seven" % sid)

    # --- per-structure and per-cell fields --------------------------------
    for sid, s in sorted(by_id.items()):
        w = "%s / %s" % (where, sid)
        if s.get("mutation_mode") not in MUTATION_MODE:
            rep.err(w, "mutation_mode %r" % s.get("mutation_mode"))
        if s.get("site_role") not in SITE_ROLE:
            rep.err(w, "site_role %r" % s.get("site_role"))
        if s.get("predicate_version_required") not in PREDICATE:
            rep.err(w, "predicate_version_required %r" % s.get("predicate_version_required"))
        if s.get("priority") not in ("must", "should", "nice"):
            rep.err(w, "priority %r" % s.get("priority"))
        cells = s.get("targets") or []
        seen = [c.get("target") for c in cells]
        if sorted(seen) != sorted(TARGETS):
            rep.err(w, "target cells are %r, expected all seven" % (sorted(seen),))
        for c in cells:
            cw = "%s / %s" % (w, c.get("target"))
            if c.get("status") not in STATUS:
                rep.err(cw, "status %r" % c.get("status"))
            if c.get("candidate_class") not in CANDIDATE_CLASS:
                rep.err(cw, "candidate_class %r" % c.get("candidate_class"))
            if c.get("expected_observability") not in OBSERVABILITY:
                rep.err(cw, "expected_observability %r" % c.get("expected_observability"))
            if not c.get("status_source"):
                rep.err(cw, "no status_source -- say where the status came from")
            if not c.get("approach"):
                rep.err(cw, "no approach -- an implementation agent has nothing to act on")
            if c.get("status") == "blocked" and not c.get("blocker"):
                rep.err(cw, "blocked with no blocker. A blocked cell is a published result and "
                            "must carry its reason.")
            if c.get("status") == "not_determined" and c.get("status_source") != "not_assessed":
                rep.warn(cw, "not_determined but status_source is %r" % c.get("status_source"))
            sa = c.get("scored_against")
            if sa != "target_default" and s.get("predicate_version_required") != "accepted_case_v2":
                rep.err(cw, "scored_against names a non-default object (%r) but the structure "
                            "requires only accepted_case_strict, which does not read it" % sa)
    return by_id


def check_capabilities(caps, rep):
    where = "TARGET_CAPABILITIES.yaml"
    rows = caps.get("targets") or []
    by_t = {}
    for r in rows:
        t = r.get("target")
        if t in by_t:
            rep.err(where, "duplicate target %r" % t)
        by_t[t] = r
    if sorted(by_t) != sorted(TARGETS):
        rep.err(where, "targets are %r, expected all seven" % (sorted(by_t),))
    for t, r in sorted(by_t.items()):
        w = "%s / %s" % (where, t)
        cap = r.get("capability") or {}
        for flag in CAP_FLAGS:
            if flag not in cap:
                rep.err(w, "missing capability flag %r" % flag)
                continue
            v = cap[flag]
            if not isinstance(v, dict) or "value" not in v or "note" not in v:
                rep.err(w, "capability %r must be a {value, note} mapping" % flag)
                continue
            if v["value"] not in CAP_VALUES:
                rep.err(w, "capability %r value %r" % (flag, v["value"]))
            if not v["note"]:
                rep.err(w, "capability %r has no note -- an unexplained flag is not evidence" % flag)
        for k in ("operand_source_today", "operand_source_required"):
            if r.get(k) not in OPERAND_SOURCE:
                rep.err(w, "%s %r" % (k, r.get(k)))
        po = r.get("public_output") or {}
        if po.get("strict_predicate_reads") not in ("out_of_circuit", "in_circuit"):
            rep.err(w, "public_output.strict_predicate_reads %r" % po.get("strict_predicate_reads"))
        for half in ("out_of_circuit", "in_circuit"):
            if not (po.get(half) or {}).get("name"):
                rep.err(w, "public_output.%s has no name -- both objects must be declared even "
                           "when one is not captured" % half)
    return by_t


def seed_id_ok(seed_id, sid, structures_by_id):
    if any(p.match(seed_id) for p in LEGACY_SEED_ID_PATTERNS):
        return True
    if seed_id == sid:
        return True
    if not seed_id.startswith(sid + "_"):
        return False
    tail = seed_id[len(sid) + 1:]
    variants = set(structures_by_id.get(sid, {}).get("variant_suffixes") or [])
    parts = tail.split("_")
    # <id>[_<opcode>][_<variant>]: an opcode is lowercase alnum, a variant must
    # be one the manifest enumerates, so two ports cannot invent different
    # suffixes for the same shape.
    for p in parts:
        if p in variants:
            continue
        if re.match(r"^[a-z0-9]+$", p):
            continue
        return False
    return True


def check_csv(path, structures_by_id, caps_by_target, rep, strict):
    where = os.path.basename(path)
    pub_to_id = {s["published_name"]: sid for sid, s in structures_by_id.items()}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames or []
        for need in ("target", "program_structure", "seed_id"):
            if need not in cols:
                rep.err(where, "missing required column %r" % need)
        for need in ("operand_source", "candidate_class"):
            if need not in cols:
                rep.err(where, "missing required column %r. shared_infrastructure items 3 and 6: "
                               "without it the corpus cannot be compared across targets and the "
                               "catalog inflates its own bug count." % need)
        if strict:
            for need in ("accepted_case_v2", "site_role", "nth", "scored_against"):
                if need not in cols:
                    rep.err(where, "--strict: missing column %r" % need)
        if rep.errors:
            return
        bad_struct, bad_seed, seen_cells, bad_sid = {}, {}, set(), {}
        n = 0
        for row in reader:
            n += 1
            ps = row["program_structure"]
            sid = pub_to_id.get(ps)
            if sid is None:
                bad_struct.setdefault(ps, 0)
                bad_struct[ps] += 1
                continue
            t = row["target"]
            if t not in caps_by_target:
                rep.err(where, "unknown target %r" % t)
                continue
            # The CSV carries structure_id as well as program_structure. They are two names
            # for the same thing and a port that lets them disagree makes every per-structure
            # count meaningless -- and hides a blocked cell behind an unblocked published name.
            row_sid = row.get("structure_id")
            if row_sid and row_sid != sid:
                bad_sid.setdefault((row_sid, ps), 0)
                bad_sid[(row_sid, ps)] += 1
                continue
            if not seed_id_ok(row["seed_id"], sid, structures_by_id):
                bad_seed.setdefault((sid, row["seed_id"]), 0)
                bad_seed[(sid, row["seed_id"])] += 1
            os_ = row.get("operand_source")
            if os_ not in OPERAND_SOURCE:
                rep.err(where, "row %d: operand_source %r" % (n, os_))
            cc = row.get("candidate_class")
            if cc not in CANDIDATE_CLASS:
                rep.err(where, "row %d: candidate_class %r" % (n, cc))
            if strict and row.get("site_role") not in SITE_ROLE:
                rep.err(where, "row %d: site_role %r" % (n, row.get("site_role")))
            seen_cells.add((sid, t, cc))
        for ps, k in sorted(bad_struct.items()):
            rep.err(where, "program_structure %r is not a manifest published_name (%d rows). "
                           "Add the structure to STRUCTURE_MANIFEST.yaml, or use the manifest's "
                           "string; do not invent a name in a driver." % (ps, k))
        for (rsid, ps), k in sorted(bad_sid.items()):
            rep.err(where, "structure_id %r disagrees with program_structure %r, which the "
                           "manifest maps to %r (%d rows). The two must name the same structure."
                    % (rsid, ps, pub_to_id.get(ps), k))
        for (sid, sd), k in sorted(bad_seed.items()):
            rep.err(where, "seed_id %r does not follow the convention for %s "
                           "(<id>[_<opcode>][_<variant>], variants enumerated in the manifest) "
                           "and is not a frozen legacy id (%d rows)" % (sd, sid, k))
        # a row must not claim a probe on a cell the manifest declares blocked
        for sid, t, cc in sorted(seen_cells):
            cell = next((c for c in structures_by_id[sid]["targets"] if c["target"] == t), None)
            if cell is None:
                continue
            if cell["status"] == "blocked" and cc == "probe":
                rep.err(where, "%s on %s is declared BLOCKED (%s) but the CSV emits it as a probe. "
                               "Ship it as candidate_class=control so the negative is measured, "
                               "not counted as coverage." % (sid, t, cell.get("blocker")))
            # candidate_class is per-SITE in a port but per-(structure, target) in the
            # manifest: a structure may declare dead sites (emitted as `control`) and
            # calibration sites (emitted as `calibration`) alongside its probe sites. Only
            # flag a class the manifest cannot account for at all.
            if cell["candidate_class"] != cc and cc not in ("control", "calibration"):
                rep.warn(where, "%s on %s: manifest says candidate_class=%s, CSV says %s"
                         % (sid, t, cell["candidate_class"], cc))
        print("  %s: %d rows" % (where, n))


def check_against_published(path, structures_by_id, rep):
    """Stream the shipped corpus and confirm no published program_structure fell
    out of the manifest.  This is the strongest form of the frozen-name check:
    it compares against the artefact, not against a copy of it."""
    pub = {s["published_name"] for s in structures_by_id.values()}
    seen = set()
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            seen.add(row["program_structure"])
    missing = sorted(seen - pub)
    if missing:
        rep.err(os.path.basename(path),
                "these published program_structure values no longer exist in the manifest: %r"
                % (missing,))
    print("  %s: %d distinct published program_structure values, all present in the manifest"
          % (os.path.basename(path), len(seen)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="*", help="port-emitted candidate CSVs to validate")
    ap.add_argument("--spec", default=SPEC_DIR, help="directory holding the two YAML files")
    ap.add_argument("--strict", action="store_true",
                    help="also require the accepted_case_v2 / site_role / nth / scored_against columns")
    ap.add_argument("--against-published", metavar="CSV",
                    help="stream a shipped corpus and confirm every published program_structure "
                         "value still exists in the manifest")
    ap.add_argument("--emit-json", metavar="OUT",
                    help="write a JSON rendering of the two YAML files (a convenience output, "
                         "never a second source of truth)")
    args = ap.parse_args()

    rep = Report()
    man_path = os.path.join(args.spec, "STRUCTURE_MANIFEST.yaml")
    cap_path = os.path.join(args.spec, "TARGET_CAPABILITIES.yaml")
    try:
        man = load_yaml_subset(man_path)
        caps = load_yaml_subset(cap_path)
    except YamlSubsetError as exc:
        print("FAIL: %s" % exc)
        return 2

    print("checking %s" % man_path)
    by_id = check_manifest(man, rep)
    print("checking %s" % cap_path)
    by_t = check_capabilities(caps, rep)
    print("  %d structures x %d targets = %d cells"
          % (len(by_id), len(by_t), sum(len(s.get("targets") or []) for s in by_id.values())))

    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            json.dump({"structure_manifest": man, "target_capabilities": caps}, fh, indent=1)
        print("  wrote %s" % args.emit_json)

    if args.against_published:
        check_against_published(args.against_published, by_id, rep)
    for path in args.csv:
        check_csv(path, by_id, by_t, rep, args.strict)

    for w in rep.warnings:
        print("WARN  %s" % w)
    for e in rep.errors:
        print("ERROR %s" % e)
    if rep.errors:
        print("FAIL: %d error(s), %d warning(s)" % (len(rep.errors), len(rep.warnings)))
        return 1
    print("OK: %d warning(s)" % len(rep.warnings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
