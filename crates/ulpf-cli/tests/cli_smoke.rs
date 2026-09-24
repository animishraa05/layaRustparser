//! P10.0 harden smoke tests — each one pins an audit finding against the
//! real `ulpf` binary (debug profile, so clap's duplicate-short-flag debug
//! asserts are live):
//!
//! 1. `evaluate`/`benchmark --help` must not panic on the duplicate `-d`
//!    short flag (was exit 101 in debug builds).
//! 2. `verify` must exit non-zero on tampered/missing input (was exit 0 on
//!    detected tampering — a judge script doing `if ulpf verify` got lied to).
//! 3. The core corpus loader must glob `*.log`/`*.json` instead of a
//!    hardcoded nine-file list, so a new vendor file loads with zero code
//!    changes (and `gt.jsonl` never leaks into the corpus).
//! 4. `ingest` must flush the tail batch on SIGTERM (was: killed process
//!    forfeited every event below the batch threshold — measured 187-event
//!    loss in P9-scale).

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Absolute path to the repo's tracked Parquet fixtures (test cwd is the
/// crate dir, so resolve via CARGO_MANIFEST_DIR).
fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// Debug-build `ulpf` binary (the profile clap debug-asserts run in).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ulpf")
}

/// P10.0-1a: `evaluate --help` used to abort with
/// "Short option names must be unique ... '-d' ... 'data_dir' and 'duration'"
/// (exit 101) in every debug build.
#[test]
fn evaluate_help_parses_in_debug_build() {
    let out = Command::new(bin())
        .args(["evaluate", "--help"])
        .output()
        .expect("spawn ulpf evaluate --help");
    assert!(
        out.status.success(),
        "evaluate --help failed (exit {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// P10.0-1b: same duplicate `-d` in `benchmark`.
#[test]
fn benchmark_help_parses_in_debug_build() {
    let out = Command::new(bin())
        .args(["benchmark", "--help"])
        .output()
        .expect("spawn ulpf benchmark --help");
    assert!(
        out.status.success(),
        "benchmark --help failed (exit {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// P10.0-2a: tracked `block_00000.parquet` is deliberately tampered —
/// `verify` must FAIL with a non-zero exit so automation can trust it.
#[test]
fn verify_tampered_block_exits_nonzero() {
    let out = Command::new(bin())
        .args([
            "verify",
            "--file",
            fixture("data/parquet/block_00000.parquet")
                .to_str()
                .unwrap(),
            "--ledger",
            fixture("data/ledger.jsonl").to_str().unwrap(),
        ])
        .output()
        .expect("spawn ulpf verify (tampered)");
    assert_eq!(
        out.status.code(),
        Some(2),
        "tampered block must exit 2, got {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ALARM") || stdout.contains("integrity is broken"),
        "tamper verdict must still be printed"
    );
}

/// P10.0-2b: the known-good block must keep exiting 0 with the PASS banner.
#[test]
fn verify_valid_block_exits_zero() {
    let out = Command::new(bin())
        .args([
            "verify",
            "--file",
            fixture("data/parquet/block_00001.parquet")
                .to_str()
                .unwrap(),
            "--ledger",
            fixture("data/ledger.jsonl").to_str().unwrap(),
        ])
        .output()
        .expect("spawn ulpf verify (valid)");
    assert_eq!(
        out.status.code(),
        Some(0),
        "valid block must exit 0, got {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"), "PASS banner must be printed");
}

/// P10.0-2c: a missing input is a usage error, distinct from a tamper
/// verdict (exit 1, unchanged from before — pinned so the codes stay 0/1/2).
#[test]
fn verify_missing_file_exits_one() {
    let out = Command::new(bin())
        .args([
            "verify",
            "--file",
            "/nonexistent/block_99999.parquet",
            "--ledger",
            fixture("data/ledger.jsonl").to_str().unwrap(),
        ])
        .output()
        .expect("spawn ulpf verify (missing)");
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing file must exit 1, got {:?}",
        out.status.code()
    );
}

/// P10.0-3: core loader globs. A directory holding ONE unknown-name log file
/// must evaluate (hardcoded list loaded 0 lines → "No logs found" exit 1),
/// and a `gt.jsonl` sidecar in the same dir must be excluded from the corpus.
#[test]
fn core_loader_globs_unknown_file_names() {
    let tmp = std::env::temp_dir().join(format!(
        "ulpf_glob_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(
        tmp.join("totally_new_vendor.log"),
        "<134>Sep 24 10:00:00 newdev %NEW-6-00001: Built inbound connection from 10.1.1.1\n\
         <134>Sep 24 10:00:01 newdev %NEW-6-00002: Teardown connection to 10.1.1.2\n\
         <134>Sep 24 10:00:02 newdev %NEW-6-00003: Built outbound connection from 10.1.1.3\n",
    )
    .unwrap();
    // Sidecar: must be auto-loaded as GT, never counted as corpus lines.
    std::fs::write(
        tmp.join("gt.jsonl"),
        "{\"raw\":\"x\",\"gt_vendor\":\"test\",\"gt_template_tag\":\"t\",\"gt_fields\":{},\"difficulty\":\"easy\",\"origin\":\"test\"}\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .args([
            "evaluate",
            "--engine",
            "baseline",
            "--duration",
            "1",
            "--threads",
            "1",
            "--samples",
            "10",
            "--corpus",
            "core",
            "--data-dir",
            tmp.to_str().unwrap(),
            "--out",
            tmp.join("report.md").to_str().unwrap(),
        ])
        .output()
        .expect("spawn ulpf evaluate (glob loader)");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "glob loader evaluate failed: {:?}\nstdout: {}",
        out.status.code(),
        stdout
    );
    assert!(
        stdout.contains("Loaded 3 diverse"),
        "expected exactly 3 corpus lines (2 gt.jsonl excluded), stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("Loaded 1 sidecar GT overrides"),
        "sidecar gt.jsonl must still auto-load, stdout: {}",
        stdout
    );

    std::fs::remove_dir_all(&tmp).ok();
}

/// P10.0-4: SIGTERM must drain the channel and flush the tail batch into a
/// Parquet block + ledger entry. Batch thresholds are set unreachable
/// (10k events / 60s) so ONLY the graceful flush can persist the 50 lines.
#[test]
fn ingest_sigterm_flushes_tail_batch() {
    let tmp = std::env::temp_dir().join(format!(
        "ulpf_term_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let parquet = tmp.join("parquet");
    let ledger = tmp.join("ledger.jsonl");
    std::fs::create_dir_all(&parquet).unwrap();

    // High, unlikely-to-collide ports; only this test binds them.
    let udp = "127.0.0.1:51410";
    let tcp = "127.0.0.1:51411";

    let mut child = Command::new(bin())
        .args([
            "ingest",
            "--udp",
            udp,
            "--tcp",
            tcp,
            "--parquet-dir",
            parquet.to_str().unwrap(),
            "--ledger",
            ledger.to_str().unwrap(),
            "--batch-size",
            "10000",
            "--batch-timeout",
            "60000",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ulpf ingest");

    // Give the listeners time to bind.
    std::thread::sleep(Duration::from_millis(700));

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
    let line = "<134>Sep 24 10:00:00 cisco-asa %ASA-6-302013: Built inbound TCP connection \
                1234 for outside:198.51.100.7/443 (198.51.100.7/443) to inside:10.1.2.3/51514 \
                (10.1.2.3/51514)\n";
    let mut sent = 0;
    for _ in 0..50 {
        sent += sock.send_to(line.as_bytes(), udp).expect("udp send");
    }
    assert_eq!(sent, 50 * line.len());

    // Let the pipeline drain the socket + channel into the batcher.
    std::thread::sleep(Duration::from_millis(700));

    // SIGTERM (not SIGKILL — the graceful path is exactly what's under test).
    let st = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {}", child.id()))
        .status()
        .expect("send SIGTERM");
    assert!(st.success());

    // Wait (bounded) for a clean exit.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let code = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status.code(),
            None if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100))
            }
            None => {
                let _ = child.kill();
                panic!("ingest did not exit within 10s of SIGTERM");
            }
        }
    };
    assert_eq!(
        code,
        Some(0),
        "ingest must exit 0 after graceful shutdown (tail batch flush)"
    );

    // The ONLY way 50 events reach the ledger here is the shutdown flush.
    let ledger_txt = std::fs::read_to_string(&ledger).unwrap_or_default();
    let leaf_sum: usize = ledger_txt
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("leaf_count").and_then(|n| n.as_u64()))
        .map(|n| n as usize)
        .sum();
    assert_eq!(
        leaf_sum, 50,
        "expected all 50 SIGTERM-drained events in the ledger, got {} ({})",
        leaf_sum, ledger_txt
    );

    std::fs::remove_dir_all(&tmp).ok();
}
