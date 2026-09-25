# Contributing to ULPF

6-person SIH team workflow. Read `AGENTS.md` (invariants + gotchas) and `remainingStuff.md` (who owns what) first.

## How work flows (read this before anything else)

1. **Pick an issue** labeled `status: unclaimed` (filter by `area/*` for your lane). Read its acceptance criteria — that is the definition of done.
2. **Claim it:** comment `/claim`. The bot assigns you and flips it to `status: claimed`. One issue per person at a time. Stuck > 1 day or blocked? Comment, or `/unclaim` to release it.
3. **Branch:** `feat/<issue-number>-<slug>` (e.g. `feat/12-serve-api`) from latest `master`. No direct pushes to `master`.
4. **PR:** template auto-fills. Fill "Closes #N", verification, and a requested reviewer (`@animishraa05` or `@sudobhavik` — prefer someone fresh to the area). CI + CodeRabbit review first; fix bot nits before humans look.
5. **Review:** every PR needs 1 human approval + green CI (enforced by ruleset). The `needs-reviewer` label clears on first review. Human checks architecture + invariants; bot checks style/nits.
6. **Merge:** squash-merge, delete the branch. Issue closes automatically via `Closes #N`.

Moved from the old URL? Point your clone at the org:

```bash
git remote set-url origin https://github.com/guptchar/layaRustparser.git
```

## Setup

```bash
git clone https://github.com/guptchar/layaRustparser.git
cd layaRustparser
cargo build --release
```

Run everything from the repo root: CLI defaults assume `data/raw`, `data/parquet`, `data/ledger.jsonl`.

## Branches

- Short-lived `feat/<topic>` or `fix/<topic>` branches, PR to `main`. No direct pushes to `main`.
- One owner per area (see `remainingStuff.md` §8). Don't touch another owner's hot path without asking.
- PRs need: green CI, `cargo fmt` clean, tests for new behavior (RED → GREEN → REFACTOR).

## Verification gate (run in this order, no CI will save you locally)

```bash
cargo clippy --workspace --all-targets -- -A clippy::too_many_arguments -A clippy::field_reassign_with_default -D warnings
cargo fmt --all -- --check
cargo test --workspace
```

Performance gates when touching parse/miner/pipeline: p50 < 5.0 µs, LRU hit rate > 90%,
Action Inviolability 100%, Grouping Accuracy > 90%. Check with:

```bash
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out eval_hardcore_report.md
```

## Gotchas that have bitten us (see `AGENTS.md` for the full list)

- `scripts/run_demo.sh` is non-destructive: scratch output goes to `data/demo/` (gitignored), never the tracked fixtures. `scripts/simulate_tamper.py` still mutates whatever block it's pointed at — pass an explicit path.
- `data/parquet/block_00000.parquet` is **intentionally tampered** (`verify` must FAIL). Don't "fix" it.
- Debug builds work for all subcommands (old `-d` flag clash fixed); release is still required for meaningful benchmark numbers.
- `scripts/populate_datasets.py` writes repo-relative (`ULPF_OUT_DIR` overrides). No foreign hardcoded paths anymore.
- Flaky under load: `test_classification_sub_microsecond_benchmark` can fail on busy machines. Re-run before assuming breakage.
- If README and `ulpf --help` disagree on flags, `--help` wins.

## PR checklist

- [ ] Gate above is green
- [ ] New behavior has tests; anchor-token inviolability test still passes
- [ ] No `to_string()`/`format!` on per-packet hot paths
- [ ] No runtime network calls (air-gap invariant), binary stays < 35 MB
- [ ] Raw log preserved byte-for-byte + SHA-256 intact
