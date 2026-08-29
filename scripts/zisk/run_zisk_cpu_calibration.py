#!/usr/bin/env python3
# LACUNA_ARTIFACT_ENV: paths come from the environment so this runs anywhere.
#   ZISK_DIR   checkout of the zisk zkVM with the LACUNA port applied
#   LACUNA_WORK scratch directory for inputs and intermediate files (default: $TMPDIR)
#   LACUNA_OUT  output CSV
import os as _os, tempfile as _tempfile
"""LACUNA CPU calibration driver for target=zisk.

External, additive-only: it does NOT modify the ZisK tree. It invokes exactly the same
binaries with exactly the same argv/env as the original enumeration run
(examples/lacuna-eval/tests/lacuna_encoding_enumeration.rs / scratchpad driver), and adds
process-level CPU + wall probes around each pipeline stage.

Stage split:
  S1 = ziskemu subprocess with the wb_perturb hook armed (mutation construction + suffix replay)
  S2 = proofman EXECUTE .. CALCULATING_CONTRIBUTIONS      (minimal trace, count, plan, witness, tables)
  S3 = proofman GENERATING_PROOFS .. GENERATING_INNER_PROOFS
  S4 = proofman VERIFYING_PROOFS .. last log line (incl. global-constraint check)
all three of S2/S3/S4 live inside ONE `cargo-zisk prove -a -y -l` child process; their CPU is
attributed by sampling /proc/<child>/stat (utime+stime, all threads) at 10 ms and interpolating
the cumulative CPU curve at the stage boundaries taken from proofman's own timestamped markers.
The child's exact total CPU comes from os.wait4 rusage.
"""
import os, sys, time, json, subprocess, struct, csv, re, datetime

ZISK = _os.environ.get("ZISK_DIR") or _os.path.expanduser("~/zisk")
CZ   = ZISK + "/target/release/cargo-zisk"
ZE   = ZISK + "/target/release/ziskemu"
ELF  = ZISK + "/examples/lacuna-seed/target/elf/riscv64ima-zisk-zkvm-elf/release/lacuna-seed"
WORK = os.path.dirname(os.path.abspath(__file__))
LOGD = os.path.join(WORK, "logs")
os.makedirs(LOGD, exist_ok=True)
CLK  = os.sysconf('SC_CLK_TCK')
SAMPLE_DT = 0.010

OPS = [("add",0),("and",3),("sll",5),("mul",10),("mulhu",12),("divu",14)]
TEMPLATES = [
  ("E1_add_i0","ENC-E1",[("ZISK_WB_TMPL","E1"),("ZISK_WB_KIND","add"),("ZISK_WB_ARG","0")]),
  ("E1_sub_i0","ENC-E1",[("ZISK_WB_TMPL","E1"),("ZISK_WB_KIND","sub"),("ZISK_WB_ARG","0")]),
  ("E2_zero",  "ENC-E2",[("ZISK_WB_TMPL","E2"),("ZISK_WB_ARG","0")]),
  ("E2_2p63",  "ENC-E2",[("ZISK_WB_TMPL","E2"),("ZISK_WB_ARG","1")]),
  ("E2_max",   "ENC-E2",[("ZISK_WB_TMPL","E2"),("ZISK_WB_ARG","2")]),
  ("E3_j0",    "ENC-E3",[("ZISK_WB_TMPL","E3"),("ZISK_WB_ARG","0")]),
  ("E3_j63",   "ENC-E3",[("ZISK_WB_TMPL","E3"),("ZISK_WB_ARG","63")]),
]
P1 = (0x0123456789ABCDEF, 0x1122334455667788)
P2 = (0xFEDCBA9876543210, 0x0000000012345678)

def write_input(sel,a,b):
    p = os.path.join(WORK, "in_%d.bin" % sel)
    with open(p,'wb') as f:
        f.write(struct.pack('<Q',24)+struct.pack('<Q',sel)+struct.pack('<Q',a)+struct.pack('<Q',b))
    return p

def read_pid_cpu(statp):
    with open(statp) as f: s = f.read()
    rp = s.rfind(')')
    fl = s[rp+2:].split()
    return fl[0], (int(fl[11])+int(fl[12]))*1000.0/CLK   # (state, cpu_ms)

def run_child(argv, extra_env, tag, sample=False):
    env = dict(os.environ)
    env.update(extra_env)
    op = os.path.join(LOGD, tag+".out"); ep = os.path.join(LOGD, tag+".err")
    fo = open(op,'wb'); fe = open(ep,'wb')
    t0 = time.time()
    p = subprocess.Popen(argv, env=env, stdout=fo, stderr=fe)
    statp = "/proc/%d/stat" % p.pid
    samples = []
    if sample:
        while True:
            try:
                st, cpu = read_pid_cpu(statp)
                samples.append((time.time(), cpu))
                if st == 'Z': break
            except (IOError, OSError, IndexError, ValueError):
                break
            time.sleep(SAMPLE_DT)
    pid, status, ru = os.wait4(p.pid, 0)
    t1 = time.time()
    p.returncode = os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else -1
    fo.close(); fe.close()
    cpu_ms = (ru.ru_utime + ru.ru_stime) * 1000.0
    if sample:
        samples.append((t1, cpu_ms))   # exact endpoint from rusage
    return dict(rc=p.returncode, t0=t0, t1=t1, wall_ms=(t1-t0)*1000.0, cpu_ms=cpu_ms,
                samples=samples, out=op, err=ep)

TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z')
def parse_log(path_out, path_err):
    """-> list of (epoch_seconds, line)"""
    ev = []
    for p in (path_out, path_err):
        try: txt = open(p, errors='replace').read()
        except OSError: continue
        for line in txt.splitlines():
            # strip ANSI
            l = re.sub(r'\x1b\[[0-9;]*m', '', line)
            m = TS_RE.match(l)
            if not m: continue
            s = m.group(1)
            frac = s.split('.')[1]
            s2 = s.split('.')[0] + '.' + frac[:6]
            dt = datetime.datetime.strptime(s2, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
            ev.append((dt.timestamp(), l))
    ev.sort()
    return ev

def find_ts(ev, needle, first=True):
    hits = [t for t,l in ev if needle in l]
    if not hits: return None
    return hits[0] if first else hits[-1]

def cpu_at(samples, t):
    if not samples: return None
    if t <= samples[0][0]: return samples[0][1]
    if t >= samples[-1][0]: return samples[-1][1]
    lo, hi = 0, len(samples)-1
    while hi - lo > 1:
        mid = (lo+hi)//2
        if samples[mid][0] <= t: lo = mid
        else: hi = mid
    (ta,ca),(tb,cb) = samples[lo], samples[hi]
    if tb == ta: return ca
    return ca + (cb-ca)*(t-ta)/(tb-ta)

def emu(inp, extra_env, tag):
    r = run_child([ZE,"-e",ELF,"-i",inp,"-c"], extra_env, tag, sample=False)
    out = open(r['out'], errors='replace').read()
    words = []
    for l in out.splitlines():
        l = l.strip()
        if len(l)==8 and all(c in "0123456789abcdefABCDEF" for c in l):
            words.append(int(l,16))
    val = (words[1]<<32)|words[0] if len(words)>=2 else None
    err = open(r['err'], errors='replace').read()
    hits = 0
    if "WB_HITS=" in err:
        try: hits = int(err.split("WB_HITS=")[1].split()[0])
        except Exception: hits = 0
    r['val']=val; r['hits']=hits
    return r

def discover_pc(inp, sentinel, tag):
    r = run_child([ZE,"-e",ELF,"-i",inp], {"ZISK_WB_REPORT":"0x%016x"%sentinel}, tag, sample=False)
    err = open(r['err'], errors='replace').read()
    for l in err.splitlines():
        if "pc=0x" in l:
            return int(l.split("pc=0x")[1].split()[0],16)
    return None

def clear_shm():
    try:
        for n in os.listdir("/dev/shm"):
            if n.startswith("ZISK_"):
                try: os.remove("/dev/shm/"+n)
                except OSError: pass
    except OSError: pass

def prove(inp, extra_env, tag):
    clear_shm()
    r = run_child([CZ,"prove","-e",ELF,"-i",inp,"-a","-y","-l"], extra_env, tag, sample=True)
    txt = open(r['out'], errors='replace').read() + open(r['err'], errors='replace').read()
    r['accept'] = "All proofs were successfully verified" in txt
    r['reject'] = ("were not verified" in txt) or ("Not all global constraints" in txt) \
                  or ("Basic proofs were not verified" in txt)
    r['ev'] = parse_log(r['out'], r['err'])
    return r

def stage_windows(r):
    ev = r['ev']
    w = {}
    w['s2_a'] = find_ts(ev, ">>> EXECUTE")
    w['s2_b'] = find_ts(ev, "<<< CALCULATING_CONTRIBUTIONS", first=False)
    w['s3_a'] = find_ts(ev, ">>> GENERATING_PROOFS")
    w['s3_b'] = find_ts(ev, "<<< GENERATING_INNER_PROOFS", first=False)
    w['s4_a'] = find_ts(ev, ">>> VERIFYING_PROOFS")
    w['s4_b'] = ev[-1][0] if ev else None
    return w

def stage_metrics(r):
    w = stage_windows(r); s = r['samples']
    out = {}
    for k,(a,b) in (('s2',(w['s2_a'],w['s2_b'])), ('s3',(w['s3_a'],w['s3_b'])), ('s4',(w['s4_a'],w['s4_b']))):
        if a is None or b is None or b < a:
            out[k+'_wall'] = None; out[k+'_cpu'] = None
        else:
            out[k+'_wall'] = (b-a)*1000.0
            ca, cb = cpu_at(s,a), cpu_at(s,b)
            out[k+'_cpu'] = None if ca is None else max(0.0, cb-ca)
    out['_w'] = w
    return out

def main():
    t_run0 = time.time()
    rows = []
    meta = {"ops": [], "baselines": []}
    for name, sel in OPS:
        a,b = P2 if name in ("div","divu","rem","remu") else P1
        inp = write_input(sel,a,b)
        h = emu(inp, {}, "honest_emu_%s"%name)
        honest = h['val']
        pc = discover_pc(inp, honest, "pcdisc_%s"%name)
        print("[op] %s sel=%d honest=0x%016x pc=0x%x" % (name, sel, honest, pc), flush=True)
        hb = prove(inp, {}, "honest_prove_%s"%name)
        print("    honest baseline accept=%s wall=%.0fms cpu=%.0fms" % (hb['accept'], hb['wall_ms'], hb['cpu_ms']), flush=True)
        meta["baselines"].append(dict(op=name, accept=hb['accept'], wall_ms=hb['wall_ms'], cpu_ms=hb['cpu_ms']))
        meta["ops"].append(dict(op=name, sel=sel, honest_pv="0x%016x"%honest, pc="0x%x"%pc, input=inp))
        for label, tmpl, extra in TEMPLATES:
            key = "%s:%s" % (name, label)
            c0 = time.time()
            env = {"ZISK_WB_ENABLE":"1", "ZISK_WB_PC":"0x%x"%pc}
            env.update(dict(extra))
            e = emu(inp, env, "emu_%s_%s"%(name,label))
            row = dict(candidate_key=key, seed_id=name, opcode=name, mutation_template=tmpl,
                       mu_label=label)
            if e['hits'] == 0:
                c1 = time.time()
                row.update(outcome="NOOP", failure_stage="replay",
                           s1_replay_wall_ms=round(e['wall_ms']), s1_replay_cpu_ms=round(e['cpu_ms']),
                           s2_tracegen_wall_ms="NA", s2_tracegen_cpu_ms="NA",
                           s3_prove_wall_ms="NA", s3_prove_cpu_ms="NA",
                           s4_verify_wall_ms="NA", s4_verify_cpu_ms="NA",
                           other_wall_ms=round((c1-c0)*1000.0 - e['wall_ms']),
                           other_cpu_ms=0,
                           total_wall_ms=round((c1-c0)*1000.0), total_cpu_ms=round(e['cpu_ms']),
                           hits=0, pv="NA", honest_pv="0x%016x"%honest, accept="NA", cand_t0=c0, cand_t1=c1)
                rows.append(row); print("  %-22s NOOP" % key, flush=True)
                continue
            pr = prove(inp, env, "prove_%s_%s"%(name,label))
            c1 = time.time()
            sm = stage_metrics(pr)
            outcome = "ACCEPT" if pr['accept'] else ("REJECT" if pr['reject'] else "PROVEFAIL")
            fstage  = "NA" if pr['accept'] else ("verify" if pr['reject'] else "prove")
            tot_cpu = e['cpu_ms'] + pr['cpu_ms']
            tot_wall = (c1-c0)*1000.0
            named_cpu = e['cpu_ms'] + sum(v for v in (sm['s2_cpu'],sm['s3_cpu'],sm['s4_cpu']) if v is not None)
            named_wall = e['wall_ms'] + sum(v for v in (sm['s2_wall'],sm['s3_wall'],sm['s4_wall']) if v is not None)
            row.update(outcome=outcome, failure_stage=fstage,
                s1_replay_wall_ms=round(e['wall_ms']), s1_replay_cpu_ms=round(e['cpu_ms']),
                s2_tracegen_wall_ms=("NA" if sm['s2_wall'] is None else round(sm['s2_wall'])),
                s2_tracegen_cpu_ms=("NA" if sm['s2_cpu'] is None else round(sm['s2_cpu'])),
                s3_prove_wall_ms=("NA" if sm['s3_wall'] is None else round(sm['s3_wall'])),
                s3_prove_cpu_ms=("NA" if sm['s3_cpu'] is None else round(sm['s3_cpu'])),
                s4_verify_wall_ms=("NA" if sm['s4_wall'] is None else round(sm['s4_wall'])),
                s4_verify_cpu_ms=("NA" if sm['s4_cpu'] is None else round(sm['s4_cpu'])),
                other_wall_ms=round(tot_wall-named_wall), other_cpu_ms=round(tot_cpu-named_cpu),
                total_wall_ms=round(tot_wall), total_cpu_ms=round(tot_cpu),
                hits=e['hits'], pv=("NA" if e['val'] is None else "0x%016x"%e['val']),
                honest_pv="0x%016x"%honest, accept=pr['accept'], cand_t0=c0, cand_t1=c1,
                prove_cpu_ms=round(pr['cpu_ms']), prove_wall_ms=round(pr['wall_ms']),
                n_samples=len(pr['samples']))
            rows.append(row)
            print("  %-22s %-7s s1=%.0f/%.0f s2=%s/%s s3=%s/%s s4=%s/%s tot=%.0f/%.0f (wall/cpu ms)"
                  % (key, outcome, e['wall_ms'], e['cpu_ms'],
                     row['s2_tracegen_wall_ms'], row['s2_tracegen_cpu_ms'],
                     row['s3_prove_wall_ms'], row['s3_prove_cpu_ms'],
                     row['s4_verify_wall_ms'], row['s4_verify_cpu_ms'],
                     tot_wall, tot_cpu), flush=True)
    t_run1 = time.time()
    HDR = ["candidate_key","seed_id","opcode","mutation_template","outcome","failure_stage",
           "s1_replay_wall_ms","s1_replay_cpu_ms","s2_tracegen_wall_ms","s2_tracegen_cpu_ms",
           "s3_prove_wall_ms","s3_prove_cpu_ms","s4_verify_wall_ms","s4_verify_cpu_ms",
           "other_wall_ms","other_cpu_ms","total_wall_ms","total_cpu_ms"]
    outcsv = _os.environ.get("LACUNA_OUT") or "zisk_cpu_calibration.csv"
    with open(outcsv,"w",newline="") as f:
        w = csv.writer(f); w.writerow(HDR)
        for r in rows: w.writerow([r[k] for k in HDR])
    with open(os.path.join(WORK,"rows_full.json"),"w") as f:
        json.dump({"rows":rows,"meta":meta,"run_wall_s":t_run1-t_run0}, f, indent=1, default=str)
    print("WROTE", outcsv, len(rows), "rows; run wall %.1fs" % (t_run1-t_run0), flush=True)

if __name__ == "__main__":
    main()
