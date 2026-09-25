# Accuracy scorecards by corpus, latency spectrum & forensic guarantees

> Moved from README §4–§6 during the README slim-down (nothing deleted).
> Each table is a verbatim summary of the linked report's §1 scorecard.
> Columns: **Baseline** = frozen Aho-Corasick `UniversalParser`;
> **3-Tier** = `LRU + Drain + Laya`.

## How every metric is measured (the rulers)

Each metric below shows how it is graded: the exact definition, the line in [`crates/ulpf-ai/src/evaluator.rs`](../crates/ulpf-ai/src/evaluator.rs) that implements it, and the ground truth it is compared against:

| Metric | Ruler (exact definition) | Code | Ground truth |
| :--- | :--- | :--- | :--- |
| **VCA** (vendor classification) | explicit label map, never fuzzy: the predicted vendor must contain — or be contained by — the GT label; a parsed `unknown` never satisfies a named GT vendor | `:1764–1783` | sidecar `gt_vendor`, else in-line derivation (`:1696–1703`) |
| **GA** (grouping accuracy, LogPai) | per engine cluster, count the records sharing that cluster's majority GT template tag; GA = Σ(majority) / N | `:1928–1959` | the same per-line GT template tag |
| **TA** (template accuracy) | `template_is_valid`: the cluster template must be a non-empty **exact token-aligned generalization** of the record's own masked line — same token count, every non-`<*>` token identical at its position, syslog GT tag (`%ASA-6-302013:`) preserved verbatim. **Token-F1 ≡ 1.0 — no similarity threshold** | `:1618–1640` | per-line GT tag (sidecar or in-line) |
| **Field accuracy ×5** (src/dst IP, src/dst port, protocol) | extracted value must appear **verbatim** in the raw line; an honest `null` grades correct *only* when the raw line carries no such marker (P5 null-correct rule); protocol may match by name or IANA number | `:1796–1891` | the raw bytes themselves — plus sidecar `gt_fields` where a sidecar exists |
| **"Macro F1"** † | arithmetic **mean of those five field accuracies** | `:1970` | — |
| **Disposition** | strict string equality against GT when the line carries a label; an unlabeled line grades correct only if the engine emits a non-`Unknown` disposition | `:1893–1918` | sidecar `gt_disposition`, else in-line action keywords |
| **Action inviolability** | `verify_action_preservation()` — no Drain cluster may hold both an allow-class and a deny-class anchor token → 100 or 0, never in between | `:1972–1976` | the anchor vocabulary itself |
| **Sidecar field grading** | null-vs-wrong discipline: a non-null expectation grades correct/wrong; an honest null counts as null — never silently skipped | `:2004` (`grade_gt_fields`) | `gt.jsonl` sidecars (adversarial · holdout · full), keyed by verbatim raw line |
| **Lossless SHA-256 / UUIDv7** | `raw_hash == SHA-256(raw)` recomputed per line; `event_id` parses as a UUID | `:1786–1792` | the raw bytes |

**Ground-truth policy:** where a sidecar exists it wins over in-line derivation (`:1693–1703`), because fuzz mutations destroy the in-line markers. On the adversarial and holdout corpora the sidecar is therefore the only reliable ground truth left. The core corpus (1,720 lines) has no sidecar; its GT comes from the lines themselves. Sidecars exist for adversarial (757), holdout (200) and full-scale (224,657 — see the 1,000,000-correct-field table in the README headline results).

† **About the name "Macro F1":** it is not a precision/recall F1. The number is the mean of five exact-match field accuracies (`evaluator.rs:1970`), so read it as **mean field accuracy**. The old name stays only so the README, the reports and the matrix all match the generated output.

## 4.1 Core corpus — 1,720 committed fixture lines · [`eval_hardcore_report.md`](../eval_hardcore_report.md)

| Metric | Baseline | 3-Tier | Delta |
| :--- | ---: | ---: | :---: |
| Vendor Classification (VCA) | 100.00% | **100.00%** | = |
| Grouping Accuracy (GA, Loghub-2.0) | 100.00% | **100.00%** | = |
| Template Accuracy (TA) | 100.00% | **100.00%** | = |
| Field Extraction Macro F1 † (IP/port/proto) | 100.00% | **100.00%** | = |
| Disposition Resolution (OCSF action) | 100.00% | **100.00%** | = |
| Action Inviolability | N/A | **100% preserved** | met |
| Unique templates (compression) | 1,407 | **73** | **19.3× fewer** |
| Audit-dump mismatches | — | **0 / 1,720** | clean |

## 4.2 Full scale — 224,657 lines / 183 MB · [`eval_full_report.md`](../eval_full_report.md)

| Metric | Baseline | 3-Tier | Delta |
| :--- | ---: | ---: | :---: |
| Throughput | 395,842 EPS | **849,481 EPS** | **2.15×** |
| Data bandwidth | 77.68 MB/s | **237.26 MB/s** | **3.05×** |
| VCA / GA / TA / F1 / Disposition | 100 / 100 / 100 / 100 / 100 % | **100 / 100 / 100 / 100 / 100 %** | = (ceiling) |
| Unique templates | 137,986 | **32** | **4,312× compression** |
| Sidecar GT (5 field keys) | — | **1,000,000 correct · 0 wrong** | exact match |
| Audit-dump mismatches | — | **0 / 224,657** | clean |

## 4.3 Adversarial corpus (deterministic fuzz) · [`eval_adversarial_report.md`](../eval_adversarial_report.md)

| Metric | Baseline | 3-Tier | Note |
| :--- | ---: | ---: | :--- |
| VCA | 96.30% | 96.30% | mutated vendor prefixes — parity |
| GA | 100.00% | 98.41% | −1.59 pt: deny-class variants only (see README limitations) |
| TA / F1 / Disposition | 100 / 97.15 / 93.53 % | **100** / 97.15 / 93.53 % | parity |
| Action Inviolability | N/A | **100% preserved** | anchor tokens held under fuzz |
| GT fields wrong | 1,524 | **1,524 (identical)** | fuzzer-caused; engine delta = 0 |

## 4.4 Frozen holdout (unseen vendors, executed once at P8) · [`eval_holdout_report.md`](../eval_holdout_report.md)

| Metric | Baseline | 3-Tier |
| :--- | ---: | ---: |
| VCA (unseen vendors) | 0.00% | **40.00%** |
| GT fields correct | 0 | **320** |
| GT fields wrong | 720 | **400** (−44%) |
| TA | 100.00% | **100.00%** |
| Field F1 † | 64.00% | **80.00%** |

> The holdout is **frozen**: never regenerated, never re-run post-freeze. Its report timestamp (`2026-09-24T09:41:32Z`) is the audit trail.

## Latency spectrum & template compression

Full-scale percentile sweep ([`eval_full_report.md`](../eval_full_report.md) §2):

| Percentile | Baseline | 3-Tier | Reduction |
| :--- | ---: | ---: | ---: |
| p1 (fastest 1%) | 512.25 µs | **5.97 µs** | −98.8% |
| **p50 (median)** | 1,104.72 µs | **7.28 µs** | **−99.3%** |
| p90 | 1,377.28 µs | **8.12 µs** | −99.4% |
| p99 | 1,510.92 µs | **10.97 µs** | −99.3% |
| p99.9 | 1,729.33 µs | **14.93 µs** | −99.1% |
| worst case | 4,328.61 µs | **50.08 µs** | −98.8% |

**Template compression** (why a SIEM would care): 224,657 raw lines collapse to **32 Drain templates** (baseline naive-split: 137,986) — a **4,312× reduction** in downstream indexing cost with TA held at 100% (every template still generalizes correctly against its masked line).

## Robustness & forensic guarantees

From §1b of each report. Each row is a pass/fail gate:

| Guarantee | Core | Full | Adversarial | How it's enforced |
| :--- | :---: | :---: | :---: | :--- |
| Format recognised (not `unknown`) | 1,720 | 224,657 | 729/757 | pinned parse order + classifier prefixes |
| No panic | 1,720 | 224,657 | 757 | `catch_unwind` around every parse |
| Lossless SHA-256 match | 1,720 | 224,657 | 757 | `raw_hash == SHA-256(raw_log)` verified per line |
| Action Inviolability | 100% | 100% | 100% | Drain anchor tokens + dedicated tests |

### Cryptographic chain of custody

```console
$ ulpf verify --file data/parquet/block_00001.parquet --ledger data/ledger.jsonl
  Ledger Merkle Root     : 398e59a6304ea9fa83b3d9eb5f0739bf081a01ce4d34e30e5c320040fd9e69a8
  Computed Merkle Root   : 398e59a6304ea9fa83b3d9eb5f0739bf081a01ce4d34e30e5c320040fd9e69a8
   [PASS] 100% CRYPTOGRAPHIC INTEGRITY VERIFIED (RFC 6962)
$ echo $?
0

$ ulpf verify --file data/parquet/block_00000.parquet --ledger data/ledger.jsonl
  Ledger Merkle Root     : e12dfacf15b6cc84fcedf91aeb3119f7d8c7a638e2c7e9541b9bb02d12833b72
  Computed Merkle Root   : a94c909a2404f7f022bcc4a428f1d815711c2472a020e8f462330c914493efe8
   [ALARM] FORENSIC TAMPERING DETECTED! INTEGRITY COMPROMISED!
$ echo $?
2
```

Machine-readable exit codes (**P10.0**): **`0` = valid · `1` = missing input / IO error · `2` = tamper detected**. (`block_00000.parquet` is *deliberately* tampered in-repo so the failure path is demonstrable out of the box; `block_00001.parquet` is the valid control.)

The live ingest chain at full scale wrote **186 Parquet blocks with 186/186 verifying PASS** ([`FULL_DATASET_RESULTS.md`](../FULL_DATASET_RESULTS.md) §4) — SIGTERM flushes the in-flight batch, closing the tail-loss window found during P9.
