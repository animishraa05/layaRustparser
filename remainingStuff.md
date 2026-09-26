# ULPF — Remaining Stuff (What We Still Need to Build)

> **Status of core:** WORKING. Do not touch unless you own it.
> 3-tier pipeline (LRU + Drain + Laya), OCSF 1.3 4001, Merkle + Parquet, onboard, evaluate — all frozen.
> This file lists everything **around** the core needed for a viable, demoable, SIH-winning system.

Reference proposal: `docs/reference/Ulpf-proposal.pdf`. Real CLI flags: trust `ulpf --help`, not README (README Steps 3/6 are stale).

---

## 0. Done — Do Not Rebuild

| Part | Location | State |
| :--- | :--- | :--- |
| Tier-1 Signature LRU (96% hit, ~1.3µs) | `crates/ulpf-core/src/parser/lru_cache.rs` | Done |
| Tier-2 Drain + anchor tokens (ALLOW vs DENY never merge) | `crates/ulpf-ai/src/drain.rs` | Done |
| Tier-3 Laya out-of-band triage | `crates/ulpf-ai/src/laya.rs`, `pipeline.rs:72-114` | Done |
| Baseline `UniversalParser` + 6 extractors | `crates/ulpf-core/src/parser/` | Done (VCA 78%, needs accuracy help — see §5) |
| RFC 6962 Merkle tree + inclusion/consistency proofs | `crates/ulpf-integrity/src/merkle.rs` | Done, slow — see §2 |
| Parquet writer + ledger + verifier | `storage.rs`, `batcher.rs`, `tamper.rs` | Done, bloated — see §2 |
| Onboarder (3 samples → regex → validate) | `crates/ulpf-ai/src/onboarder.rs` | Done, needs hardening — see §4 |
| Evaluator (`evaluate --engine all`) | `crates/ulpf-ai/src/evaluator.rs` | Done |
| Generator traffic blaster | `crates/ulpf-generator/` | Done, needs batching — see §6 |

---

## 1. Queue — MISSING (highest priority for viability)

We have **no durable queue** today. `run_ingest` uses `mpsc::channel::<String>(50_000)` (`crates/ulpf-cli/src/main.rs:257`).
If parse stalls, packets drop. If process restarts, data is gone.

**Build this:**

- [ ] **Phase 1 (demo-safe, 1 day):** keep in-process channel but fix policy:
  - bounded channel with explicit `try_send` + `busy_drop` counter (never block UDP recv).
  - batch as `Vec<Bytes>` not `Vec<String>` (kill `trimmed.to_string()` per line in `main.rs:279,313` + `socket.rs:117`).
  - expose `queue_depth`, `dropped` in live stats line (`main.rs:353`).
- [ ] **Phase 2 (SIH scale story):** pluggable sink behind a trait:
  ```rust
  trait LogQueue { fn push(&self, b: Bytes) -> Result<()>; fn pop_batch(&self) -> Vec<Bytes>; }
  ```
  Implementations: `MemoryQueue` (default), `RedpandaQueue` or `NatsQueue` (feature-flagged, air-gap optional).
- [ ] Backpressure doc: what happens at 500k EPS burst? Answer: UDP drops at kernel (document `SO_RCVBUF` tuning), TCP applies backpressure, queue sheds with counter. Judges ask this.

**Owner:** 1 person. Files: `crates/ulpf-core/src/ingest/queue.rs` (new), `crates/ulpf-cli/src/main.rs` (wire only).

---

## 2. Integrity + Storage — works, needs 4 fixes

- [ ] **Single-hash pass-through.** Today each byte is hashed 3×: parser SHA (`parser/mod.rs:61`), batcher SHA (`batcher.rs:245`), Merkle leaf SHA (`merkle.rs:95` with `0x00` prefix). Fix: parser computes leaf `Hash` once, `IncomingLog` carries it, batcher only builds upper levels. File: `batcher.rs:240-261`.
- [ ] **Ledger durability.** `append_ledger_entry` (`batcher.rs:293`) does `writeln!+flush`, no `fsync`. Crash = lost anchor. Fix: `file.sync_all()` per flush (1 per 1k events, cheap).
- [ ] **`ulpf prove` subcommand (judge wow-factor).** `inclusion_proof()` exists (`merkle.rs:314`) but no CLI. Add `ulpf prove --file block_00001.parquet --leaf 342 --ledger data/ledger.jsonl` → prints audit path JSON + `verify: true`. Also add `verify --consistency` chaining block N→N+1 via `consistency_proof()` (`merkle.rs:338`).
- [ ] **Parquet schema diet.** `storage.rs:62-73`: `vendor: Utf8` → `Dictionary<Int8,Utf8>`, `raw_hash: Utf8(64 hex)` → `FixedSizeBinary(32)`, remove `Vec<&str>` double-copy in `records_to_batch` (`storage.rs:76`). ~40-50% smaller blocks, faster verify.
- [ ] **Parallel verify.** `verify_records` (`tamper.rs:229`) is single-threaded + hashes twice (`tamper.rs:269,279` — hash once, reuse). Parallelize per-record SHA with rayon.

**Owner:** 1 person. Gate: `ulpf verify` on block_00001 still PASS, block_00000 still FAIL.

---

## 3. Ingestion — biggest demo/benchmark gap

Live ingest **does not use your fast engine**. `run_ingest` (`main.rs:372-401`) runs single-threaded `UniversalParser::parse_lossless` + `DrainMiner::add_log` + `serde_json::to_string` per packet. Benchmark uses `TieredPipeline`. Demo will look slower than slides.

- [ ] Swap ingest loop to per-worker `TieredPipeline::process` (one pipeline per Tokio task, no `Arc` sharing — sharing reintroduces the `Mutex<DrainMiner>` contention at `pipeline.rs:147`).
- [ ] Move Merkle/Parquet flush to dedicated thread via channel (never block parse).
- [ ] Reuse buffers: `Bytes` batches, `recvmmsg`-style reuse of `buf`, set `TCP_NODELAY` on TCP path.
- [ ] CLI cleanup: `benchmark --compare` just forwards to `evaluate` (`main.rs:612-624`) — delete `benchmark`, keep `evaluate`. Fix `-d` clash (`data_dir` vs `duration`, `main.rs:142-193`) that panics debug builds. Add `--json-out` to `verify`/`inspect` for frontend handoff.

**Owner:** 1 person. Gate: `ulpf ingest` + `ulpf-generator --rate 200000` shows EPS matching `evaluate` order of magnitude.

---

## 4. AI (Drain/Laya/Onboarder) — polish, off hot path

- [ ] `ParserDefinition::parse` recompiles `Regex::new` **per event** (`onboarder.rs:166`). Cache with `OnceLock<Regex>`. (Your codegen template already does this — runtime doesn't.)
- [ ] Replace hand-rolled `to_yaml/from_yaml` (`onboarder.rs:51-162`) with `serde_yaml` (pure Rust, air-gapped).
- [ ] Validator requires 100% + IPv4-only (`onboarder.rs:450,471`). Accept `IpAddr` (IPv6), threshold 95% + warnings.
- [ ] Add CEF (`CEF:0|...`) + JSON/EVE synthesizers. Today only flow-arrow / KV / positional (`onboarder.rs:535-553`). Direct VCA lift from 78%.
- [ ] `enforce_capacity` wipes the whole registry when >100 (`onboarder.rs:807-812`). Real LRU eviction + persist `data/parsers/*.json` with version field.
- [ ] Laya does ~50× `contains()` + `to_ascii_lowercase()` alloc per call (`laya.rs:356-456`). Single Aho-Corasick pass, no alloc. Cap Tier-3 `cluster_samples` HashMap (`pipeline.rs:76`) — unbounded growth on evasion bursts.

**Owner:** 1 person. Gate: `cargo test -p ulpf-ai` green + `test_drain_unique_event_patterns_anchor_tokens` still passes.

---

## 5. Accuracy — VCA 78% is the ceiling on every slide

- [ ] Finish CEF extractor (`extractors/cef.rs` is untracked — wire + test it).
- [ ] IPv6 paths in all extractors + onboarder validator.
- [ ] Strict PAN-OS 60-col CSV + Suricata `simd-json` fast path.
- [ ] 5+ new sample lines per vendor in `crates/ulpf-core/tests/parser_tests.rs` with SHA-256 preservation asserts.
- Target: VCA 78% → 95%. Nothing else lifts GA/F1 more.

**Owner:** can split across P3/P4 people or 1 dedicated person.

---

## 6. Generator + Perf nits (cheap)

- [ ] UDP: one `send()` per packet (`ulpf-generator/src/main.rs:328`). Batch with `sendmmsg` or raise default `--batch-size 64` → 256.
- [ ] TCP: set `TCP_NODELAY`, reuse `send_buf` (already done) + add `--pprof` flamegraph flag.
- [ ] Pipeline P0s from prior review (do after §§1-3): thread-local Drain miners + merge, byte-scanner masker replacing 10× regex (`drain.rs:512-630`), fused signature+classifier single pass, thread-local LRU (current `RwLock::read` per hit + FIFO-not-LRU bug at `lru_cache.rs:175,62`), binary `[u8;32]` hash + coarse timestamp.

---

## 7. Frontend — what makes it presentable (no hot-path access)

**Rule:** frontend never touches Rust internals. It reads only: `eval_*.json` (`evaluate --json-out`), `data/ledger.jsonl`, `verify --json-out`, Parquet via DuckDB.

Pages (any stack — suggested Next.js + Tailwind + DuckDB-wasm, or Tauri if offline-strict):

1. **Live:** EPS chart, p50/p99, queue depth/dropped, vendor mix. Source: ingest stats stdout → websocket, or poll `serve /metrics`.
2. **Search:** SQL box over `data/parquet/*.parquet` (`SELECT * WHERE disposition='Blocked' LIMIT 100`), show raw + OCSF side-by-side + SHA + UUIDv7.
3. **Integrity:** block list from ledger, per-block PASS/FAIL badge, "Tamper" button (calls `ulpf tamper`), "Verify" re-run, proof viewer (`ulpf prove` output: leaf → siblings → root).
4. **Onboard wizard:** paste 3-5 lines → POST to `serve /onboard` → show regex + validation % + field map → "Hot-load" button.
5. **Benchmarks:** render `evaluate --engine all --json-out` as the README scorecard table + latency chart. This is your SIH slide 5, live.

- [ ] `ulpf serve` (new, small): `GET /metrics`, `GET /blocks`, `GET /prove/:block/:leaf`, `POST /onboard`. Axum, <300 lines. This is the only backend the frontend talks to.
- [ ] SIEM forwarder (optional but strong): tail `ledger.jsonl` → push new blocks to Kafka/Elastic/ClickHouse. Proves "Efficient SIEM integration" requirement.

**Owners:** 2 people (API + UI). Contract file to agree on first: `docs/INTEGRATION_CONTRACTS.md` (Parquet schema, ledger line format, CLI JSON shapes, port 5140 wire format).

---

## 8. Suggested 6-person split (no merge conflicts)

| # | Person | Owns | Done = |
|---|--------|------|--------|
| 1 | Queue + Ingest | §1, §3 | `ingest` uses TieredPipeline/worker, queue metrics in stats |
| 2 | Integrity + Storage | §2 | `prove` works, fsync on, schema diet, verify still PASS/FAIL correctly |
| 3 | AI + Accuracy | §4, §5 | OnceLock regex, CEF/IPv6/JSON, VCA ≥90% |
| 4 | API + Sink | `ulpf serve`, forwarder | UI can fetch /metrics /blocks /prove |
| 5 | Frontend | §7 UI | 5 pages live against local `data/` |
| 6 | Docs + Demo | SRS, slides, video | `scripts/run_demo.sh` green end-to-end (ingest→tamper→verify ALARM→onboard→evaluate) |

---

## 9. Demo-day checklist (run from repo root, release binary)

```bash
cargo build --release
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out eval_hardcore_report.md
./target/release/ulpf verify --file data/parquet/block_00001.parquet --ledger data/ledger.jsonl  # must PASS
./target/release/ulpf verify --file data/parquet/block_00000.parquet --ledger data/ledger.jsonl  # must FAIL (intentionally tampered)
./target/release/ulpf onboard --sample sample_new_firewall.log --vendor custom_fw
./target/release/ulpf inspect --file data/parquet/block_00001.parquet --count 1
```

**Warnings:** `scripts/run_demo.sh` is non-destructive (writes scratch `data/demo/`); `evaluate`/`benchmark` run in debug since P10.0 (release stays the intended eval mode); `populate_datasets.py` writes repo-relative (`ULPF_OUT_DIR` overrides).

---

## 10. Cleanup backlog (do once, before SIH freeze)

- [x] Delete or archive 33 root `patch_*.py` / `fix_*.py` (done — deleted, were applied + untracked). Moved `Ulpf -1.pdf` → `docs/reference/Ulpf-proposal.pdf` (done).
- [x] Consolidate `docs/`: kept latest `DETAILED_*` (has the theory-vs-flaws-vs-production walkthrough) as `docs/ARCHITECTURE_FINAL.md`; archived stale `ARCHITECTURE.md` + overlapping `SIH_EVALUATION_DOSSIER.md` + `SIMPLIFIED_*` to `docs/archive/` (done).
- [x] Move `Ulpf -1.pdf` → `docs/reference/Ulpf-proposal.pdf` (done).
- [ ] Untrack generated PDFs or move to `docs/releases/`. Only one `*_template.html` should survive (two still in `docs/`).
- [ ] Untrack or relocate `eval_hardcore_report.md` (regenerated every run) → `docs/benchmarks/`.
