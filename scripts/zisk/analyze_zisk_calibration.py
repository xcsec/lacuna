#!/usr/bin/env python3
# LACUNA_ARTIFACT_ENV: pass the CSV as $LACUNA_CSV or argv[1].
import os as _os, sys
import csv, statistics as st
CSV=_os.environ.get("LACUNA_CSV") or (sys.argv[1] if len(sys.argv)>1 else "zisk_cpu_calibration.csv")
rows=list(csv.DictReader(open(CSV)))
STAGES=[("s1_replay","S1 replay"),("s2_tracegen","S2 tracegen"),("s3_prove","S3 prove"),("s4_verify","S4 verify"),("other","other"),("total","TOTAL")]
def num(r,k):
    v=r[k]
    return None if v=="NA" else float(v)
print("n rows =", len(rows))
by={}
for r in rows: by.setdefault(r["outcome"],[]).append(r)
for oc in sorted(by):
    rs=by[oc]
    print("\n=== outcome %s  (n=%d) ===" % (oc, len(rs)))
    print("%-14s %14s %14s %14s %14s" % ("stage","mean_cpu_ms","sum_cpu_ms","mean_wall_ms","sum_wall_ms"))
    for pre,lab in STAGES:
        ck = pre+"_cpu_ms" if pre!="total" else "total_cpu_ms"
        wk = pre+"_wall_ms" if pre!="total" else "total_wall_ms"
        if pre=="s1_replay": ck,wk="s1_replay_cpu_ms","s1_replay_wall_ms"
        if pre=="other": ck,wk="other_cpu_ms","other_wall_ms"
        c=[num(r,ck) for r in rs]; w=[num(r,wk) for r in rs]
        c=[x for x in c if x is not None]; w=[x for x in w if x is not None]
        if not c: print("%-14s %14s %14s %14s %14s"%(lab,"NA","NA","NA","NA")); continue
        print("%-14s %14.0f %14.0f %14.0f %14.0f" % (lab, st.mean(c), sum(c), st.mean(w), sum(w)))
print("\n=== overall ===")
for pre,lab in STAGES:
    ck = "total_cpu_ms" if pre=="total" else pre+"_cpu_ms"
    wk = "total_wall_ms" if pre=="total" else pre+"_wall_ms"
    c=[num(r,ck) for r in rows]; w=[num(r,wk) for r in rows]
    c=[x for x in c if x is not None]; w=[x for x in w if x is not None]
    print("%-14s mean_cpu=%10.0f ms  sum_cpu=%11.0f ms  mean_wall=%8.0f ms  sum_wall=%9.0f ms  cpu/wall=%6.1f"
          % (lab, st.mean(c), sum(c), st.mean(w), sum(w), sum(c)/sum(w) if sum(w) else 0))
print("\nper-seed total_cpu_ms mean:")
byS={}
for r in rows: byS.setdefault(r["seed_id"],[]).append(float(r["total_cpu_ms"]))
for k in sorted(byS): print("  %-8s n=%d mean=%.0f ms" % (k,len(byS[k]),st.mean(byS[k])))
print("\nper-template total_cpu_ms mean:")
byT={}
for r in rows: byT.setdefault(r["mutation_template"],[]).append(float(r["total_cpu_ms"]))
for k in sorted(byT): print("  %-8s n=%d mean=%.0f ms" % (k,len(byT[k]),st.mean(byT[k])))
