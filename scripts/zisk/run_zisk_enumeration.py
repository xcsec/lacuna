# LACUNA_ARTIFACT_ENV: paths come from the environment so this runs anywhere.
#   ZISK_DIR   checkout of the zisk zkVM with the LACUNA port applied
#   LACUNA_WORK scratch directory for inputs and intermediate files (default: $TMPDIR)
#   LACUNA_OUT  output CSV
import os as _os, tempfile as _tempfile
import os,sys,struct,subprocess,time,json,re
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sem import rv

ZISK=_os.environ.get("ZISK_DIR") or _os.path.expanduser("~/zisk")
CZ=f"{ZISK}/target/release/cargo-zisk"
ZE=f"{ZISK}/target/release/ziskemu"
ELF=f"{ZISK}/examples/lacuna-seed/target/elf/riscv64ima-zisk-zkvm-elf/release/lacuna-seed"
SCRATCH=_os.environ.get("LACUNA_WORK") or _tempfile.mkdtemp(prefix="lacuna_zisk_")
M=(1<<64)-1

P1=(0x0123456789ABCDEF,0x1122334455667788)
P2=(0xFEDCBA9876543210,0x0000000012345678)
# name, selector, (a,b)
OPS=[
 ("add",0,P1),("sub",1,P1),("xor",2,P1),("and",3,P1),("or",4,P1),
 ("sll",5,P1),("srl",6,P1),("sra",7,P1),
 ("mul",10,P1),("mulh",11,P1),("mulhu",12,P1),
 ("addw",17,P1),("subw",18,P1),("mulw",19,P1),
 ("div",13,P2),("divu",14,P2),("rem",15,P2),("remu",16,P2),
]

def mkinput(sel,a,b):
    path=f"{SCRATCH}/in_{sel}.bin"
    with open(path,"wb") as f:
        f.write(struct.pack("<Q",24)+struct.pack("<Q",sel)+struct.pack("<Q",a)+struct.pack("<Q",b))
    return path

def emu_output(inp,env=None):
    e=dict(os.environ); 
    if env: e.update(env)
    t0=time.time()
    r=subprocess.run([ZE,"-e",ELF,"-i",inp,"-c"],capture_output=True,text=True,env=e,timeout=120)
    dt=(time.time()-t0)*1000
    # first 16 hex chars over first two words (LE): out[0..8]
    words=[l.strip() for l in r.stdout.splitlines() if re.fullmatch(r"[0-9a-fA-F]{8}",l.strip())]
    val=None
    if len(words)>=2:
        w0=int(words[0],16); w1=int(words[1],16)
        val=(w1<<32)|w0
    hits=0
    m=re.search(r"WB_HITS=(\d+)",r.stderr)
    if m: hits=int(m.group(1))
    return val,hits,dt,r

def report_pc(inp,sentinel):
    e=dict(os.environ); e["ZISK_WB_REPORT"]=f"0x{sentinel:016x}"
    r=subprocess.run([ZE,"-e",ELF,"-i",inp],capture_output=True,text=True,env=e,timeout=120)
    pcs=re.findall(r"WB_REPORT pc=0x([0-9a-fA-F]+) c=",r.stderr)
    return [int(p,16) for p in pcs]

if __name__=="__main__" and sys.argv[1]=="discover":
    for name,sel,(a,b) in OPS:
        inp=mkinput(sel,a,b)
        exp=rv(name,a,b)
        val,hits,dt,r=emu_output(inp)
        ok = (val==exp)
        pcs=report_pc(inp,exp)
        uniq = len(pcs)==1
        print(f"{name:6s} sel={sel:2d} exp=0x{exp:016x} got={'0x%016x'%val if val is not None else None} match={ok} pcs={len(pcs)} {'0x%x'%pcs[0] if pcs else '-'} uniq={uniq}")

# ---------------- prove phase ----------------
import shutil
CSV_OUT=_os.environ.get("LACUNA_OUT") or _os.path.join(SCRATCH, "E_zisk.csv")
JSON_OUT=_os.environ.get("LACUNA_JSON") or _os.path.join(SCRATCH, "zisk.json")
HEADER="run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,hits,pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,committed_digest,honest_committed_digest,digest_changed"

def git_rev():
    r=subprocess.run(["git","-C",ZISK,"rev-parse","--short","HEAD"],capture_output=True,text=True)
    return r.stdout.strip()

def run_prove(inp,env):
    e=dict(os.environ)
    if env: e.update(env)
    # clean stale shmem (not used on -l path but harmless)
    for f in os.listdir("/dev/shm"):
        if f.startswith("ZISK_"):
            try: os.remove("/dev/shm/"+f)
            except: pass
    t0=time.time()
    r=subprocess.run([CZ,"prove","-e",ELF,"-i",inp,"-a","-y","-l"],capture_output=True,text=True,env=e,timeout=600)
    dt=(time.time()-t0)*1000
    log=r.stdout+"\n"+r.stderr
    accept = "All proofs were successfully verified" in log
    reject = ("were not verified" in log) or ("Not all global constraints" in log) or ("Basic proofs were not verified" in log)
    vt="NA"
    m=re.search(r"VERIFYING_PROOFS \((\d+)ms\)",log)
    if m: vt=m.group(1)
    return accept,reject,dt,vt,log

# template menu: (mu_label, template, kind, arg, envextra)
def templates():
    T=[]
    T.append(("E1_add_i0","ENC-E1","add",0,{"ZISK_WB_TMPL":"E1","ZISK_WB_KIND":"add","ZISK_WB_ARG":"0"}))
    T.append(("E1_sub_i0","ENC-E1","sub",0,{"ZISK_WB_TMPL":"E1","ZISK_WB_KIND":"sub","ZISK_WB_ARG":"0"}))
    T.append(("E2_zero","ENC-E2","boundary",0,{"ZISK_WB_TMPL":"E2","ZISK_WB_ARG":"0"}))
    T.append(("E2_2p63","ENC-E2","boundary",1,{"ZISK_WB_TMPL":"E2","ZISK_WB_ARG":"1"}))
    T.append(("E2_max","ENC-E2","boundary",2,{"ZISK_WB_TMPL":"E2","ZISK_WB_ARG":"2"}))
    T.append(("E3_j0","ENC-E3","xor",0,{"ZISK_WB_TMPL":"E3","ZISK_WB_ARG":"0"}))
    T.append(("E3_j63","ENC-E3","xor",63,{"ZISK_WB_TMPL":"E3","ZISK_WB_ARG":"63"}))
    return T

def csvrow(d):
    return ",".join(str(d.get(k,"NA")) for k in HEADER.split(","))

if __name__=="__main__" and len(sys.argv)>1 and sys.argv[1]=="prove":
    subset=sys.argv[2].split(",") if len(sys.argv)>2 else None
    rev=git_rev()+"+wb-hook"
    run_tag="zisk_wb_"+time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(os.path.dirname(CSV_OUT),exist_ok=True)
    os.makedirs(os.path.dirname(JSON_OUT),exist_ok=True)
    rows=[]
    report={"target":"zisk","revision":rev,"run_tag":run_tag,
      "hook":{"file":"emulator/src/wb_perturb.rs + emulator/src/emu.rs:2781","line":2781,
        "choke_point":"Emu::get_value_to_store (single point; all 5 store_c* variants funnel through it)",
        "notes":"env-gated default OFF; perturbs the architectural write-back value inst_ctx.c returned to every witness-gen pass"},
      "seed_builder":{"how":"single guest, selector-dispatched inline-asm op, commit 8-byte rd",
        "file":"examples/lacuna-seed/src/main.rs","opcodes_covered":[o[0] for o in OPS]},
      "driver":{"file":"scratchpad/driver.py","test_name":"driver.py prove","cargo_command":
        "cargo-zisk prove -e <elf> -i <input> -a -y -l (real proofman GPU inner proofs + verify, no-aggregation)"},
      "prover_config":{"path":"-l emulator (ziskemu lib) witness-gen + proofman GPU STARK inner proofs, no-aggregation (-a), verify (-y)",
        "chips":["Rom","Main","Binary","BinaryExtension","Arith","MemAlign","Mem","InputData","RomData","SpecifiedRanges","VirtualTable0","VirtualTable1","Dma64AlignedMemSet"]},
      "baselines":{"attempted":0,"verified":0,"rejected":0,"rejected_detail":[]},
      "candidates":0,"tracegen_ok":0,"proofs":0,"verifier_accepts":0,"accepted_cases":0,
      "accepted_case_detail":[],"per_opcode_table":[],"blocked":[],"self_corrections":[],"notes":[]}

    oplist=[o for o in OPS if (subset is None or o[0] in subset)]
    with open(CSV_OUT,"w") as f:
        f.write(HEADER+"\n"); f.flush()
        for name,sel,(a,b) in oplist:
            inp=mkinput(sel,a,b)
            exp=rv(name,a,b)
            hon_val,_,hon_dt,_=emu_output(inp)
            pcs=report_pc(inp,exp)
            pc=pcs[0]
            # honest baseline prove
            report["baselines"]["attempted"]+=1
            hacc,hrej,hdt,hvt,hlog=run_prove(inp,None)
            optab={"opcode":name,"pc":"0x%x"%pc,"honest_verified":hacc,"honest_pv":"0x%016x"%hon_val,
                   "candidates":0,"accepts":0,"accepted_cases":0,"rejects":0,"execfail":0}
            if hacc: report["baselines"]["verified"]+=1
            else:
                report["baselines"]["rejected"]+=1
                report["baselines"]["rejected_detail"].append({"opcode":name,"tail":hlog.strip().splitlines()[-3:]})
                optab["baseline_error"]=hlog.strip().splitlines()[-3:]
                report["per_opcode_table"].append(optab); 
                # still record baseline row
                continue
            honest_pv="0x%016x"%hon_val
            for mu_label,tmpl,kind,arg,envx in templates():
                env={"ZISK_WB_ENABLE":"1","ZISK_WB_PC":"0x%x"%pc}; env.update(envx)
                cval,hits,cdt,_=emu_output(inp,env)
                report["candidates"]+=1; optab["candidates"]+=1
                pv="0x%016x"%cval if cval is not None else "NA"
                output_changed = (cval is not None and cval!=hon_val)
                row={"run_tag":run_tag,"target":"zisk","revision":rev,"seed_id":name,
                     "mutation_mode":"writeback-perturb","program_structure":"single-op-commit",
                     "opcode":name,"pc":"0x%x"%pc,"nth":0,"dead":"NA","dead_final":"NA",
                     "site_execs":1,"mu_label":mu_label,"mutation_template":tmpl,"mu_kind":kind,
                     "mu_arg":arg,"hits":hits,"pv_hex":pv,"honest_pv_hex":honest_pv,
                     "output_changed":str(output_changed).lower(),"t_record_ms":int(cdt),
                     "committed_digest":pv,"honest_committed_digest":honest_pv,
                     "digest_changed":str(output_changed).lower()}
                if hits==0:
                    row.update({"outcome":"NOOP","failure_stage":"mutation","accepted_case":"false",
                                "t_prove_ms":"NA","t_verify_ms":"NA","reason":"mutation-did-not-fire"})
                    f.write(csvrow(row)+"\n"); f.flush(); rows.append(row); continue
                acc,rej,pdt,vt,log=run_prove(inp,env)
                report["proofs"]+=1; report["tracegen_ok"]+=1
                row["t_prove_ms"]=int(pdt); row["t_verify_ms"]=vt
                if acc:
                    report["verifier_accepts"]+=1; optab["accepts"]+=1
                    accepted = output_changed and pv!="NA"
                    row.update({"outcome":"ACCEPT","failure_stage":"accepted_proof",
                                "accepted_case":str(accepted).lower(),
                                "reason":"verifier-accepted" if accepted else "accepted-but-output-unchanged"})
                    if accepted:
                        report["accepted_cases"]+=1; optab["accepted_cases"]+=1
                        report["accepted_case_detail"].append({"opcode":name,"mu":mu_label,"pv":pv,"honest":honest_pv})
                elif rej:
                    optab["rejects"]+=1
                    row.update({"outcome":"REJECT","failure_stage":"verify","accepted_case":"false",
                                "reason":"constraint-rejected(global-or-basic)"})
                else:
                    optab["execfail"]+=1
                    tail=" | ".join(log.strip().splitlines()[-2:])[:180].replace(","," ")
                    row.update({"outcome":"EXECFAIL","failure_stage":"prove","accepted_case":"false",
                                "reason":"prove-error:"+tail})
                f.write(csvrow(row)+"\n"); f.flush(); rows.append(row)
            report["per_opcode_table"].append(optab)
            json.dump(report,open(JSON_OUT,"w"),indent=2)
    json.dump(report,open(JSON_OUT,"w"),indent=2)
    print("DONE candidates=%d accepts=%d accepted_cases=%d"%(report["candidates"],report["verifier_accepts"],report["accepted_cases"]))
