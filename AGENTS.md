# AGENTS.md — ULPF (Universal Log Pre-processing Framework)

Compact agent handbook for this Rust workspace. `README.md` and `docs/` have full docs — but **some README CLI examples are stale, trust `ulpf --help`** (see Gotchas). There is **no pre-commit or typecheck config**; run the local verification gate before every commit, and CI mirrors it on push/PR (with documented skips like the known flaky benchmark test). If local and CI disagree, CI is authoritative for mergeability.

## Non-negotiable invariants

1. **Air-gapped:** zero runtime network calls (no external APIs, telemetry, model downloads). Release binary stays **< 35 MB** (currently ~18 MB).
2. **Lossless provenance:** the raw log line is preserved byte-for-byte in storage (`raw_log` column), `raw_hash` = SHA-256(raw), event IDs are UUIDv7. Never truncate or re-encode raw input.
3. **Action inviolability:** security actions (`ALLOW`/`PERMIT`/`ACCEPT` vs `DENY`/`DROP`/`BLOCK`/`REJECT`) must never merge into one template cluster. Anchor tokens are enforced in `crates/ulpf-ai/src/drain.rs` and tested in `crates/ulpf-ai/tests/ai_tests.rs::test_drain_unique_event_patterns_anchor_tokens`.
4. **Zero-copy hot path:** parsing/ingestion uses `&[u8]`/`&str` slices; no `to_string()`/`format!`/`String::from` on per-packet paths.
5. **Tier-3 stays out-of-band:** novel-cluster triage runs over bounded `crossbeam-channel`s and must never block line-rate ingest.

## Crate map

Workspace of 5 crates (root `Cargo.toml`, edition 2021, pinned toolchain via `rust-toolchain.toml` to 1.96.0):

| Crate | Role |
| :--- | :--- |
| `crates/ulpf-core` | Sockets, Aho-Corasick `Classifier`, zero-copy vendor extractors, OCSF schema, `SignatureLruCache` |
| `crates/ulpf-integrity` | RFC 6962 Merkle tree, dual-trigger batcher (1,000 events / 2,000 ms), Parquet writer, tamper verifier |
| `crates/ulpf-ai` | `DrainMiner`, `LayaDecisionEngine`, `Onboarder`, `TieredPipeline` (3-tier), `EvaluatorEngine` |
| `crates/ulpf-generator` | Traffic blaster binary `ulpf-generator` |
| `crates/ulpf-cli` | Binary `ulpf`; subcommands: `ingest`, `verify`, `onboard`, `benchmark`, `evaluate`, `scorecard`, `inspect`, `tamper` |

Real entrypoints: `crates/ulpf-cli/src/main.rs`, `crates/ulpf-generator/src/main.rs`. Key wiring: `ulpf-ai/src/pipeline.rs` (Tier1 LRU → Tier2 Drain → Tier3 Laya), `ulpf-core/src/parser/mod.rs` (baseline `UniversalParser`), `ulpf-integrity/src/storage.rs` (Arrow schema: `event_id, block_id, leaf_index, timestamp, vendor, raw_log, raw_hash, ocsf_json`).

## Commands (all verified locally)

```bash
# Verification gate — run in this order before every commit. CI mirrors this on push/PR (minus documented CI-only skips).
cargo clippy --workspace --all-targets -- -A clippy::too_many_arguments -A clippy::field_reassign_with_default -D warnings
cargo fmt --all -- --check
cargo test --workspace        # ~131 tests and growing; ai/duel suites dominate runtime

# Focused runs
cargo test -p ulpf-core --test parser_tests <test_name_substr>
cargo test -p ulpf-ai drain_                       # substring filter across that crate

# Build + evaluate both engines (must be release — see Gotchas)
cargo build --release
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out eval_hardcore_report.md
```

**The two `-A` clippy flags are required.** Plain `cargo clippy -- -D warnings` fails on `field_reassign_with_default` (ulpf-core) and `too_many_arguments`.

Performance gates when touching hot path or miner: p50 < 5.0 µs, LRU hit rate > 90%, Action Inviolability 100%, Grouping Accuracy > 90%.

## Gotchas (would bite you without this)

- **`cargo run -p ulpf-cli -- evaluate|benchmark` in debug builds:** the old duplicate `-d` short flag (`data_dir` vs `duration`) that tripped clap debug-asserts was removed in P10.0 — debug now works. Release is still the intended eval mode (numbers are what count).
- **CLI defaults assume cwd = repo root** (`data/raw`, `data/parquet`, `data/ledger.jsonl`). Run binaries from the root or pass explicit paths.
- **`ulpf --help` is authoritative for flags; README quick-start flags verified correct** (a pre-slim drift note about `ingest --proto`/`onboard --name` retired with the slim — the examples it cited no longer exist).
- **`scripts/run_demo.sh` is now non-destructive (P10.0):** it writes to scratch `data/demo/` (gitignored), never the tracked `data/parquet/` fixtures. `scripts/simulate_tamper.py` still mutates the Parquet block it is pointed at — the no-arg default is the intentionally-tampered `data/parquet/block_00000.parquet`; pass an explicit path for anything else.
- **Tracked fixtures are deliberately odd:** `data/parquet/block_00000.parquet` is *intentionally* tampered (`ulpf verify` must FAIL on it); `block_00001.parquet` is the valid one. Don't "fix" block 0.
- **Known flaky test under load:** `ulpf-core/tests/parser_tests.rs::test_classification_sub_microsecond_benchmark` asserts < 2 µs/classification in a *debug* build and can fail on busy machines. Re-run before assuming you broke something.
- **Dataset generator paths are repo-relative (P10.0):** `scripts/populate_datasets.py` writes to `<repo>/data/raw` (override with `ULPF_OUT_DIR`); `ulpf-generator`'s `locate_data_dir` only probes repo-relative `data/raw` candidates — the old `/home/human/...` foreign fallback was removed.
- **`.gitignore` ignores `*.log`** with explicit whitelists (`data/raw/*`, `sample_new_firewall.log`); new raw datasets under other paths need a negation rule to be tracked. `data/parsers/*.{json,yaml}` (onboarder output) is intentionally ignored.

## Extension recipes

**New vendor parser:**
1. Add variant to `VendorFormat` in `ulpf-core/src/parser/classifier.rs`.
2. Register its identifying prefix in `Classifier::new()`.
3. Create zero-copy extractor in `crates/ulpf-core/src/parser/extractors/<vendor>.rs` (map to OCSF 4001), export from `extractors/mod.rs`.
4. Wire into `UniversalParser::parse()` in `ulpf-core/src/parser/mod.rs`.
5. Add 5+ realistic sample lines to `crates/ulpf-core/tests/parser_tests.rs`; assert field accuracy and byte-for-byte SHA-256 preservation.

**New OCSF class:** define in `ulpf-core/src/schema/ocsf.rs` (must carry `metadata` with `raw_data`, `raw_hash`, `event_id`, `ingest_time`); update Arrow schema in `ulpf-integrity/src/storage.rs` if new top-level columns are needed.

**Benchmark regression check:** whenever touching the parsing hot path, Drain miner, or pipeline, run the `evaluate --engine all` command above and compare against `eval_hardcore_report.md` (regenerating it is expected; it's tracked).
