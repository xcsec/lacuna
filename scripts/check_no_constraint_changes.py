#!/usr/bin/env python3
"""Verify that no LACUNA port modifies a committed constraint system.

LACUNA searches inside image(G), where G is the zkVM's own witness generator. That search is
only meaningful if the committed constraint system C is the unmodified upstream one: if a port
touched an AIR, a constraint file or a PIL file, every result from that port would be a
statement about our constraint system rather than the vendor's.

This script re-derives that claim from the shipped patches. It is deliberately independent of
how the patches were produced, so a reviewer can run it without trusting the build process.

For every ports/<vm>/vendor.patch it flags:
  * a patched FILE whose path looks like constraint code   (air.rs, constraints.rs, *.pil, /air/)
  * an added or removed LINE that looks like constraint code (fn eval, AirBuilder, assert_*, ...)

Exit status 0 means no port touches constraint code. Any hit exits 1 and prints the evidence.

    usage: python3 scripts/check_no_constraint_changes.py [ports_dir]
"""
import os
import re
import sys

CONSTRAINT_FILE = re.compile(r"(^|/)(air|airs|constraints?)\.rs$|\.pil$|/air/|/constraints/", re.I)
CONSTRAINT_LINE = re.compile(
    r"\bfn\s+eval\b"          # the AIR entry point in every plonky3/openvm-style backend
    r"|AirBuilder"            # the builder handed to it
    r"|\bimpl\b.*\bAir\b"     # an AIR implementation
    r"|builder\s*\.\s*assert" # builder.assert_zero / assert_eq / assert_bool
    r"|\bSubAir\b"
    r"|when_transition|when_first_row|when_last_row",
    re.I,
)
# Comments and doc-comments are prose, not constraints. A hook is allowed to *mention* the AIR.
COMMENT = re.compile(r"^[+-]\s*(//|/\*|\*|#)")


def scan(patch_path):
    """Return (patched_files, hits). A hit is (file, kind, evidence)."""
    files, hits, cur, hunk = [], [], None, ""
    with open(patch_path, errors="replace") as fh:
        for line in fh:
            m = re.match(r"^diff --git a/(\S+)", line)
            if m:
                cur = m.group(1)
                files.append(cur)
                if CONSTRAINT_FILE.search(cur):
                    hits.append((cur, "constraint-file", "patched file path matches constraint code"))
                continue
            if line.startswith("@@"):
                hunk = line.strip()
            elif line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                if COMMENT.match(line):
                    continue
                if CONSTRAINT_LINE.search(line):
                    hits.append((cur, "constraint-line", f"{hunk}  ::  {line.rstrip()}"))
    return files, hits


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ports")
    vms = sorted(d for d in os.listdir(root)
                 if os.path.isfile(os.path.join(root, d, "vendor.patch")))
    if not vms:
        print(f"no ports found under {root}", file=sys.stderr)
        return 2

    total_hits = 0
    print(f"checking {len(vms)} ports under {root}\n")
    for vm in vms:
        files, hits = scan(os.path.join(root, vm, "vendor.patch"))
        rev = open(os.path.join(root, vm, "UPSTREAM_REV")).read().strip()[:12]
        status = "OK" if not hits else f"{len(hits)} HIT(S)"
        print(f"  {vm:<8} rev {rev}  {len(files):2} file(s) patched   {status}")
        for f, kind, ev in hits:
            print(f"      ! [{kind}] {f}\n        {ev}")
        total_hits += len(hits)

    print()
    if total_hits:
        print(f"FAIL: {total_hits} patched location(s) look like constraint code.")
        return 1
    print("PASS: no port modifies an AIR, a constraint file or a PIL file.")
    print("      Every patched location is executor or witness-generation code, i.e. G, not C.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
