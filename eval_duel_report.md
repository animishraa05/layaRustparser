# ULPF Duel — vanilla Drain vs 3-tier pipeline

**What this is:** measurement evidence surfaced by `ulpf scorecard`. The duel is **not a gate** — the scorecard's six gates are unchanged by it.

## Engines

- **vanilla Drain** (`Engine A`) — `DrainMiner::new(DrainConfig { anchors_enabled: false, ..Default::default() })`: stock Drain (depth-4 prefix tree, similarity threshold, max 100 children) with ULPF's anchor subsystem switched off — no anchor vocabulary, no syslog-tag homogeneity (P6.1), no key-aware class partition (P7.2).
- **3-tier pipeline** (`Engine B`) — `TieredPipeline::new()` as shipped (Tier-1 signature LRU → Tier-2 anchored Drain → Tier-3 Laya). Quality rows are graded **out-of-band** with a parallel `DrainMiner::new(DrainConfig::default())` fed the same lines — the evaluator's convention: the pipeline exposes no per-line cluster id. Capability rows (panics, lossless SHA-256) come from real `TieredPipeline::process()` calls over every line.
- Both engines share ULPF's tokenizer (`mask_line` + `DrainMiner::tokenize`), so every delta isolates clustering policy, not preprocessing.

## Metrics

- **GA (grouping accuracy)** = Σ over clusters of the cluster's majority ground-truth class count ÷ total lines (the evaluator's exact formula).
- **PA (parsing accuracy)** = lines whose mined template reproduces the ground-truth template as an exact **token suffix** after canonicalisation: whitespace-normalised token sequences, any digit-bearing token compared as `<*>` (tokenizer alignment between ULPF's masker and LogPAI's), trailing `,;:` ignored.
- **FTA (template F1, set-level)** = F1 over unique templates — precision = unique mined templates that suffix-match some ground-truth template; recall = unique ground-truth templates reproduced by some mined template.
- **Action violations** = clusters holding both allow-side (`Allowed`) and deny-side (`Blocked`/`Dropped`) dispositions.

## Fixtures

- **R1 probe** — `data/raw/duel/security_probe.log`, 12 authored lines (3 families × 2 actions × 2 instances), full-template sidecar GT.
- **R2 fuzzed** — `data/raw/adversarial/`, 757 mutated lines, tag-level sidecar GT (PA/FTA not graded).
- **R3 BGL / R3 TBird** — LogHub BGL_2k and Thunderbird_2k samples vendored under `data/raw/duel/` (attribution: `data/raw/duel/README.md`).

## Results

| Round | Lines | GT classes | Engine | Clusters | GA % | PA % | FTA % | Violations |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| R1 probe | 12 | 6 | vanilla Drain | 3 | 50.00 | 50.00% | 50.00% | 3 |
| R1 probe | 12 | 6 | 3-tier | 6 | 100.00 | 100.00% | 100.00% | 0 |
| R2 fuzzed | 757 | 19 | vanilla Drain | 53 | 71.73 | n/a | n/a | 17 |
| R2 fuzzed | 757 | 19 | 3-tier | 81 | 98.41 | n/a | n/a | 10 |
| R3 BGL | 2000 | 120 | vanilla Drain | 57 | 83.50 | 32.80% | 67.75% | n/a |
| R3 BGL | 2000 | 120 | 3-tier | 61 | 83.95 | 34.10% | 70.53% | n/a |
| R3 TBird | 2000 | 149 | vanilla Drain | 60 | 82.25 | 48.10% | 30.41% | n/a |
| R3 TBird | 2000 | 149 | 3-tier | 63 | 83.55 | 49.00% | 33.21% | n/a |

**3-tier capability over all duel lines:** lossless 4769/4769 (`raw_hash` == SHA-256(raw)), panics 0.

## Round notes

- **R2 fuzzed** — sidecar GT is tag-level: PA/FTA not graded
- **R3 BGL** — LogPAI EventTemplate is content-only: PA/FTA use token-suffix match
- **R3 TBird** — LogPAI EventTemplate is content-only: PA/FTA use token-suffix match

## Disclosures

- **Winner on GA:** 3-tier 4 / vanilla 0 of 4 rounds (exact ties uncounted).
- **Tokenizer alignment, not LogPAI parity:** absolute PA/FTA levels are not comparable to published LogPAI numbers — their per-dataset preprocessor differs (LogPAI maps `2005.06.03` to `<*>` where ULPF yields `<*>.06.03`). Only the vanilla-vs-3-tier delta under one shared tokenizer is claimed here.
- **Mixed-action clusters remain (finding, not tuned away):** R2 fuzzed (vanilla 17, 3-tier 10) — a relay prefix or mid-line CR keeps a space in the payload, the tokenizer then fuses the record into one token, and the buried action word never reaches the anchor vocabulary, so cross-action merges stay possible. The scorecard gate `Action inviolability (ALLOW/DENY)` is the bare-token canary (a weaker, pre-existing check); corpus-wide disposition purity is this duel's stricter, newly measured metric. No tokenizer or threshold was changed in response to this result — such a fix must be validated on data the code has never seen.
- The frozen holdout corpus is never read by the duel — holdout inputs stay untouched.
- Speed is out of scope: `ulpf scorecard` already reports latency and throughput for both engines.
