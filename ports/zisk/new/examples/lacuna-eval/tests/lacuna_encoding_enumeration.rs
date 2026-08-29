//! Record-layer write-back mutation enumeration on ZisK (RV64IMA, PIL2/proofman).
//!
//! This #[ignore]d test is the in-tree driver. It shells out to the freshly-built
//! `cargo-zisk` and `ziskemu` (both carrying the env-gated `wb_perturb` hook wired at
//! `Emu::get_value_to_store`, emu.rs:2781) to run, per candidate, the REAL prover and the
//! REAL verifier and compare committed public outputs.
//!
//! Choke point (single): every one of the five `store_c*` variants in emu.rs routes the
//! destination value through `Emu::get_value_to_store`, so hooking that one function perturbs
//! every witness-generation pass coherently -- the ZisK analogue of pico `on_reg_write` and
//! nexus `on_write_back`.
//!
//! ACCEPTED CASE == verifier accepted AND the mutation fired (WB_HITS>0) AND the committed
//! public output differs from the honest one and is non-empty. Nothing weaker counts.
//!
//! Run:  cargo test -p lacuna-eval --test lacuna_encoding_enumeration -- --ignored --nocapture
//! (requires ~/.zisk proving key, a GPU, and the seed guest built with `cargo-zisk build`).
//!
//! NOTE: the concrete run that produced data/runs/zisk_seeds/E_zisk.csv was driven
//! by the equivalent Python driver (scratchpad/driver.py) invoking the same binaries+env; this
//! file is the canonical Rust form of that driver.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

/// Path to the zisk checkout with this port applied. Set $ZISK_DIR; the default assumes
/// the checkout sits next to the artifact.
fn zisk_dir() -> String {
    std::env::var("ZISK_DIR").unwrap_or_else(|_| "../zisk".to_string())
}

fn cz() -> String { format!("{}", zisk_dir(), "/target/release/cargo-zisk") }
fn ze() -> String { format!("{}", zisk_dir(), "/target/release/ziskemu") }
fn elf() -> String {
    format!("{}", zisk_dir(), "/examples/lacuna-seed/target/elf/riscv64ima-zisk-zkvm-elf/release/lacuna-seed")
}

fn write_input(dir: &PathBuf, sel: u64, a: u64, b: u64) -> PathBuf {
    let p = dir.join(format!("in_{sel}.bin"));
    let mut v = Vec::new();
    v.extend_from_slice(&24u64.to_le_bytes()); // payload length
    v.extend_from_slice(&sel.to_le_bytes());
    v.extend_from_slice(&a.to_le_bytes());
    v.extend_from_slice(&b.to_le_bytes());
    std::fs::write(&p, v).unwrap();
    p
}

/// Run ziskemu with the given env; return (committed_first_u64, wb_hits).
fn emu(inp: &PathBuf, env: &[(&str, String)]) -> (Option<u64>, u64) {
    let mut c = Command::new(ze());
    c.args(["-e", &elf(), "-i", inp.to_str().unwrap(), "-c"]);
    for (k, v) in env { c.env(k, v); }
    let o = c.output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    let words: Vec<u64> = out.lines()
        .map(|l| l.trim())
        .filter(|l| l.len() == 8 && l.chars().all(|ch| ch.is_ascii_hexdigit()))
        .filter_map(|l| u64::from_str_radix(l, 16).ok())
        .collect();
    let val = if words.len() >= 2 { Some((words[1] << 32) | words[0]) } else { None };
    let err = String::from_utf8_lossy(&o.stderr);
    let hits = err.split("WB_HITS=").nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    (val, hits)
}

/// Real prove (no-aggregation) + verify on the -l emulator path. Returns (accept, reject, ms).
fn prove_verify(inp: &PathBuf, env: &[(&str, String)]) -> (bool, bool, u128) {
    let _ = std::fs::read_dir("/dev/shm").map(|rd| {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("ZISK_") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    });
    let mut c = Command::new(cz());
    c.args(["prove", "-e", &elf(), "-i", inp.to_str().unwrap(), "-a", "-y", "-l"]);
    for (k, v) in env { c.env(k, v); }
    let t = Instant::now();
    let o = c.output().unwrap();
    let ms = t.elapsed().as_millis();
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let accept = log.contains("All proofs were successfully verified");
    let reject = log.contains("were not verified")
        || log.contains("Not all global constraints")
        || log.contains("Basic proofs were not verified");
    (accept, reject, ms)
}

// (name, selector) -- the guest dispatches inline-asm `rd = OP(a,b)` on selector, commits rd.
const OPS: &[(&str, u64)] = &[
    ("add", 0), ("and", 3), ("sll", 5), ("mul", 10), ("mulhu", 12), ("divu", 14),
];

// (label, ZISK_WB_TMPL, extra ZISK_WB_* pairs)
fn templates() -> Vec<(&'static str, Vec<(&'static str, String)>)> {
    vec![
        ("E1_add_i0", vec![("ZISK_WB_TMPL", "E1".into()), ("ZISK_WB_KIND", "add".into()), ("ZISK_WB_ARG", "0".into())]),
        ("E1_sub_i0", vec![("ZISK_WB_TMPL", "E1".into()), ("ZISK_WB_KIND", "sub".into()), ("ZISK_WB_ARG", "0".into())]),
        ("E2_zero",   vec![("ZISK_WB_TMPL", "E2".into()), ("ZISK_WB_ARG", "0".into())]),
        ("E2_2p63",   vec![("ZISK_WB_TMPL", "E2".into()), ("ZISK_WB_ARG", "1".into())]),
        ("E2_max",    vec![("ZISK_WB_TMPL", "E2".into()), ("ZISK_WB_ARG", "2".into())]),
        ("E3_j0",     vec![("ZISK_WB_TMPL", "E3".into()), ("ZISK_WB_ARG", "0".into())]),
        ("E3_j63",    vec![("ZISK_WB_TMPL", "E3".into()), ("ZISK_WB_ARG", "63".into())]),
    ]
}

const P1: (u64, u64) = (0x0123456789ABCDEF, 0x1122334455667788);
const P2: (u64, u64) = (0xFEDCBA9876543210, 0x0000000012345678);

/// Discover the op's pc via a report run keyed on the honest committed value.
fn discover_pc(inp: &PathBuf, sentinel: u64) -> Option<u64> {
    let o = Command::new(ze())
        .args(["-e", &elf(), "-i", inp.to_str().unwrap()])
        .env("ZISK_WB_REPORT", format!("0x{sentinel:016x}"))
        .output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    // report[0] is the executed op instruction (earlier pc); later pcs are the black_box barrier.
    err.lines()
        .filter_map(|l| l.split("pc=0x").nth(1).and_then(|s| s.split_whitespace().next()))
        .filter_map(|s| u64::from_str_radix(s, 16).ok())
        .next()
}

#[test]
#[ignore]
fn lacuna_encoding_enumeration_zisk() {
    let dir = std::env::temp_dir().join("lacuna_zisk");
    std::fs::create_dir_all(&dir).unwrap();
    let mut candidates = 0usize;
    let mut accepts = 0usize;
    let mut accepted_cases = 0usize;

    for (name, sel) in OPS {
        let (a, b) = if matches!(*name, "div" | "divu" | "rem" | "remu") { P2 } else { P1 };
        let inp = write_input(&dir, *sel, a, b);
        let (honest, _) = emu(&inp, &[]);
        let honest = honest.expect("honest committed output");
        let pc = discover_pc(&inp, honest).expect("op pc");

        // honest baseline must verify or the op is excluded from the mutation evaluation
        let (hacc, _, _) = prove_verify(&inp, &[]);
        assert!(hacc, "honest baseline for {name} did not verify");

        for (label, extra) in templates() {
            let mut env: Vec<(&str, String)> = vec![
                ("ZISK_WB_ENABLE", "1".into()),
                ("ZISK_WB_PC", format!("0x{pc:x}")),
            ];
            env.extend(extra.iter().cloned());
            let (cval, hits) = emu(&inp, &env);
            candidates += 1;
            if hits == 0 { continue; } // NOOP: mutation did not fire
            let changed = cval.map(|v| v != honest).unwrap_or(false);
            let (acc, _rej, ms) = prove_verify(&inp, &env);
            if acc { accepts += 1; }
            let accepted_case = acc && changed && cval.is_some();
            if accepted_case { accepted_cases += 1; }
            println!(
                "{name} {label} pc=0x{pc:x} hits={hits} pv={:?} honest=0x{honest:016x} changed={changed} accept={acc} accepted_case={accepted_case} {ms}ms",
                cval.map(|v| format!("0x{v:016x}"))
            );
        }
    }
    println!("candidates={candidates} verifier_accepts={accepts} accepted_cases={accepted_cases}");
}
