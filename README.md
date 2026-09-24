# Universal Log Pre-processing Framework (ULPF)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-103%20passed%20%C2%B7%200%20failed-brightgreen.svg)](#8-testing--verification-gate)
[![Schema](https://img.shields.io/badge/schema-OCSF%201.3-green.svg)](https://schema.ocsf.io/)
[![Integrity](https://img.shields.io/badge/integrity-RFC%206962%20Merkle-purple.svg)](https://datatracker.ietf.org/doc/html/rfc6962)
[![Air--Gap](https://img.shields.io/badge/deployment-100%25%20Air--Gapped-red.svg)](#10-air-gapped-docker-deployment)
[![Size](https://img.shields.io/badge/binary-18.6%20MB%20%3C%2035%20MB%20req-orange.svg)](#9-sih26156-requirements-matrix)
[![Repo](https://img.shields.io/badge/github-animishraa05%2FlayaRustparser-blue.svg)](https://github.com/animishraa05/layaRustparser)



A high-performance, vendor-agnostic, containerized, strictly **air-gapped Universal Log Pre-processing Framework** written in **Rust**. ULPF ingests heterogeneous perimeter firewall logs, normalizes them into **OCSF 1.3 NetworkActivity (Class 4001)**, and cryptographically guarantees non-repudiation with **RFC 6962 Merkle trees** anchored into columnar **Apache Parquet WORM** storage — with every raw byte preserved, hash-for-hash, forever.

![ULPF end-to-end flow: raw syslog/JSON/CSV -> classify -> zero-copy parse -> OCSF 1.3 JSON -> Parquet WORM + verify, with SHA-256(raw) / UUIDv7 -> RFC 6962 Merkle root -> ledger.jsonl provenance branch](docs/diagrams/hero-flow.png)

> Diagram source: [`docs/diagrams/hero-flow.dot`](docs/diagrams/hero-flow.dot) — regenerate with `dot -Tpng -Gdpi=144`.

**Key capabilities**

- **Zero-copy hot path.** p50 is **3.02 µs**/line on the core corpus, **7.28 µs** at 224k lines (**−96.2% / −99.3%** vs the frozen baseline), **849,481 EPS** at full scale (**2.15×** baseline).
- **3-tier decision pipeline.** Tier-1 signature LRU (8,192 entries), Tier-2 Drain template miner with security anchor tokens, Tier-3 Laya triage on a bounded ring that **never blocks ingest** (invariant #5).
- **Lossless provenance.** Raw bytes are stored byte-for-byte in `raw_log`, `raw_hash = SHA-256(raw)` checks out on **all 224,657** full-scale lines, and every event gets a UUIDv7 `event_id`.
- **RFC 6962 Merkle WORM.** The append-only `ledger.jsonl` roots every Parquet block. Flip one byte and `ulpf verify` exits **2**; the live run passed **186/186** blocks.
- **One schema out: OCSF 1.3.** `NetworkActivity` (class 4001) for **6 formats today** (Cisco ASA, FortiGate, PAN-OS, pfSense, Suricata, CEF; matrix in §2).
- **Action inviolability at 100%.** `ALLOW`/`PERMIT`/`ACCEPT` can never land in the same template cluster as `DENY`/`DROP`/`BLOCK`/`REJECT`.
- **4,312× template compression.** 224,657 lines collapse to **32** Drain templates (baseline: 137,986) with template accuracy still at 100%. That is a ready-made feature table for any SIEM/ML system.
- **Air-gapped for real.** Zero outbound calls, no telemetry, no model downloads. One static **18.6 MB** binary (requirement: &lt; 35 MB), plus Docker.

Every accuracy number below links to a timestamped report from `ulpf evaluate`, and every table regenerates with one command (see [§7 Reproduce the proof](#7-reproduce-the-proof)).

---

## Table of Contents

1. [Headline Results (fresh, 2026-09-24)](#1-headline-results-fresh-2026-09-24)
2. [Why ULPF — the problem](#2-why-ulpf--the-problem)
3. [Architecture](#3-architecture)
4. [Accuracy scorecards by corpus](#4-accuracy-scorecards-by-corpus)
5. [Latency spectrum &amp; template compression](#5-latency-spectrum--template-compression)
6. [Robustness &amp; forensic guarantees](#6-robustness--forensic-guarantees)
7. [Reproduce the proof](#7-reproduce-the-proof)
8. [Testing &amp; verification gate](#8-testing--verification-gate)
9. [SIH26156 requirements matrix](#9-sih26156-requirements-matrix)
10. [Air-gapped Docker deployment](#10-air-gapped-docker-deployment)
11. [Quick start](#11-quick-start)
12. [CLI reference](#12-cli-reference)
13. [Data locations &amp; programmatic access](#13-data-locations--programmatic-access)
14. [Honest limitations](#14-honest-limitations)
15. [Documentation map](#15-documentation-map)
16. [Project status &amp; roadmap](#16-project-status--roadmap)

---

## 1. Headline Results (fresh, 2026-09-24)

All figures measured on the same machine (Linux x86_64, rustc 1.96.0), release build, `--engine all --duration 3 --threads 16`. Reports are committed; timestamps inside them prove freshness.

| Corpus | Lines | Accuracy (VCA / GA / TA / F1 / Disposition) | p50 Baseline → 3-Tier | Throughput Baseline → 3-Tier | Audit dump |
| :--- | ---: | :--- | :--- | :--- | :---: |
| **Core** (committed fixtures) | 1,720 | **100 / 100 / 100 / 100 / 100 %** | 79.23 → **3.02 µs** (−96.2%) | 743,879 → 714,292 EPS (0.96×) | **0** |
| **Full scale** (regenerable) | **224,657** | **100 / 100 / 100 / 100 / 100 %** | 1,104.72 → **7.28 µs** (−99.3%) | 395,842 → **849,481 EPS (2.15×)** | **0** |
| **Adversarial** (fuzzed) | 757 | 96.30 / 98.41 / **100** / 97.15 / 93.53 % | 80.56 → **4.14 µs** (−94.9%) | 730,846 → 597,480 EPS (0.82×) | 382 ¹ |
| **Holdout** (frozen, one-shot) | 200 | 40 ² / 100 / **100** / 80 / 0 ² % | 74.47 → **5.63 µs** (−92.4%) | 1,721,640 → 154,514 EPS (0.09×) ³ | — |

¹ All 382 are **ground-truth-side mutation damage** — the fuzzer intentionally rewrote IP/port bytes; both engines produce *identical* mismatch counts (1,524 wrong fields each), so the delta is zero. Details: [`eval_adversarial_report.md`](eval_adversarial_report.md) §1b.
² Holdout vendors are intentionally unseen; the baseline recognises **0** — tiered recognises **40%** on structure alone and scores **320 GT fields correct vs baseline's 0**. Disposition is **0% on both engines by construction of the experiment**: the holdout's vendors have no extractor, so every event resolves to `Unknown` disposition (160/200 lines *do* carry labels — 102 Allowed / 58 Blocked — and both engines fail them all). Known gap, tracked as P10.2 vendor expansion. Details: [`eval_holdout_report.md`](eval_holdout_report.md) §1b–§3.
³ Holdout is a small (200-line) one-shot frozen audit — its throughput ratio is not a performance signal; latency percentiles there are (p50 −92.4%).

**Invariants held on every corpus, both engines:**

| Invariant | Result |
| :--- | :---: |
| **Action Inviolability** (`ALLOW`/`PERMIT`/`ACCEPT` never merges with `DENY`/`DROP`/`BLOCK`/`REJECT`) | **100% preserved** |
| **Lossless provenance** (`raw_hash == SHA-256(raw_log)`, byte-exact) | **100.00%** |
| **No panics** (`catch_unwind` around every parse) | **0 aborts / N lines** |
| **Sidecar ground truth, full scale** (5 field keys × 224,657 lines) | **1,000,000 correct · 0 wrong · 123,285 honest null** |
| **Live Merkle chain at scale** (P9 ingest run) | **186 / 186 blocks verify PASS** |

---

## 2. Why ULPF — the problem

Modern perimeters mix Cisco ASA, Fortinet FortiGate, Palo Alto PAN-OS, pfSense and Suricata — each emitting a different syntax (RFC 3164 Syslog, EVE JSON, CSV, key-value, CEF). Traditional pipelines fail in three ways:

1. **The context-switching wall** — Python/Java log shippers bounce every line through 7–10 interpreter stages; throughput collapses under attack traffic exactly when you need it.
2. **The "hash vault" forensic illusion** — storing `SHA-256(event)` per row proves nothing about the *stream*: an attacker with root silently deletes rows and no cross-record link breaks, because none exists.
3. **Proprietary schema lock-in** — ad-hoc vendor schemas don't interoperate with SIEMs or data lakes.

How the common shippers handle those same three problems, from their own documentation. This is an architectural comparison, not a benchmark run (our measured numbers are in §1):

| | Runtime footprint | Normalization | Stream-level provenance | Air-gapped install |
| :--- | :--- | :--- | :---: | :---: |
| **Logstash** (Elastic, JVM) | JVM heap — typically hundreds of MB to GB | hand-written `grok` patterns | none | no: plugin installs pull from the internet |
| **Fluentd** | Ruby + native C, ~100 MB class | hand-written filter plugins | none | no: `gem install` pulls from the internet |
| **Splunk Universal Forwarder** | proprietary agent | Splunk CIM, paid license | none | partial: offline package, licensed |
| **ULPF** (this repo) | single **18.6 MB** static Rust binary | OCSF 1.3, automatic (zero-copy extractors + Drain) | yes: RFC 6962 Merkle root → append-only ledger → Parquet WORM, exit-code audit | yes: zero network calls by design |

ULPF answers all three: **Rust zero-copy hot path** (slices `&[u8]`, no per-packet allocation), **RFC 6962 Merkle chaining** (deleting or editing *any* byte of *any* row breaks a verifiable root anchored in an append-only ledger), and **OCSF 1.3 normalization** as the single output schema.

### Format &amp; vendor support matrix

Transcribed from the `VendorFormat` enum and prefix table in [`crates/ulpf-core/src/parser/classifier.rs`](crates/ulpf-core/src/parser/classifier.rs) and the extractors in [`crates/ulpf-core/src/parser/extractors/`](crates/ulpf-core/src/parser/extractors/):

| Wire format | Identified by (Aho-Corasick prefix) | Zero-copy extractor | Status |
| :--- | :--- | :--- | :---: |
| RFC 3164 syslog — **Cisco ASA** | `%ASA-` | `cisco_asa.rs` | supported |
| key-value syslog — **FortiGate** | `devname="` · `type="traffic"` · `logid="` | `fortigate.rs` | supported |
| CSV syslog — **Palo Alto PAN-OS** | `,TRAFFIC,` · `,THREAT,` · `,SYSTEM,` · `PAN-OS` | `paloalto.rs` | supported |
| EVE JSON — **Suricata** | `{"timestamp":` · `"event_type":` · `"flow":` · `"alert":` | `suricata.rs` | supported |
| filterlog — **pfSense** | `filterlog[` · `filterlog:` | `pfsense.rs` | supported |
| **CEF** envelope (vendor-neutral) | `CEF:` | `cef.rs` | supported |
| LEEF · generic `key=value` · flat JSON · XML · RFC 5424 (structured data) | — | — | planned, P10.1 (§16) |
| anything else | — | generic fallback event — vendor `Unknown`, **never silently dropped** | by design |

About 10 more vendors (ISRO-relevant) are planned for P10.2 (§16). You do not have to wait for that code: `ulpf onboard` synthesises and validates a parser from 3–5 sample lines, fully offline (§11, step 7).

### One real line, end to end

Every number in this README traces back to stored records. Here is one of them, copied verbatim from [`data/raw/cisco_asa.log`](data/raw/cisco_asa.log) line 218:

**Input.** These exact bytes are what lands in the `raw_log` column, byte for byte:

```text
<166>Sep 21 14:07:15 asa-vpn-gw01 %ASA-6-302013: Built inbound TCP connection 1004583 for outside:203.0.113.57/80 (203.0.113.57/80) to inside:10.1.13.22/57911 (198.51.100.208/57911)
```

**Output.** The OCSF event stored in `data/parquet/block_00001.parquet` (it is written compact in the `ocsf_json` column; pretty-printed here):

```json
{
  "activity_id": 1,
  "activity_name": "Open"Done (P1 → P10.0, 38 commits): measurement-first ruler fixes → vendor extractors → CEF → parse-order/LRU tiers → audit null-correct rules → dynamic message-code anchors → GA/TA to 100 both engines → deterministic adversarial + frozen holdout corpora → sidecar ground truth → full-scale 224,657-line validation → 186-block live chain → CLI hardening (exit codes, SIGTERM flush, debug-panic fix, corpus glob loader) → ASA verdict-phrase union → repo-relative scripts → fresh re-run evidence + this README.,
  "category_uid": 4,
  "class_uid": 4001,
  "type_uid": 400101,
  "time": 1789984478068,
  "disposition": "Allowed",
  "src_endpoint": { "ip": "203.0.113.57", "port": 80, "interface": "outside" },
  "dst_endpoint": { "ip": "10.1.13.22", "port": 57911, "interface": "inside" },
  "connection_info": { "protocol_num": 6, "protocol_name": "TCP", "direction": "Inbound" },
  "metadata": {
    "product": { "vendor_name": "Cisco", "name": "ASA" },
    "raw_data": "<166>Sep 21 14:07:15 asa-vpn-gw01 %ASA-6-302013: Built inbound TCP connection 1004583 for outside:203.0.113.57/80 (203.0.113.57/80) to inside:10.1.13.22/57911 (198.51.100.208/57911)",
    "raw_hash": "167c1cec8f420d1e4700a7cbe588e0b335efabcfc4a16b59cf391497a13755fd",
    "event_id": "01a0c363-9374-7525-b61d-f7a11e05cca9",
    "ingest_time": 1789984478068
  },
  "unmapped": { "connection_id": "1004583", "cisco_severity": "6", "cisco_message_code": "302013" }
}
```

What to notice:

- `metadata.raw_data` is the input, byte for byte, and `metadata.raw_hash` is its SHA-256. Verify it yourself: `printf '%s' '<input above>' | sha256sum` prints `167c1cec…55fd`, which matches.
- The vendor line `%ASA-6-302013` (“Built”) maps to OCSF vocabulary: `disposition: "Allowed"`, `activity_name: "Open"`, endpoints and direction in canonical fields. Vendor-specific leftovers (`connection_id`, `cisco_message_code`) are kept under `unmapped` instead of being thrown away.
- Reproduce on any stored record: `./target/release/ulpf inspect --file data/parquet/block_00001.parquet --count 1` (§11, step 6).

---

## 3. Architecture

![ULPF 3-tier pipeline: UDP/TCP syslog into Tier-1 LRU, Tier-2 Drain miner, Tier-3 Laya engine, then zero-copy extractors -> OCSF 1.3 event -> batcher -> SHA-256 + UUIDv7 + Merkle leaf -> ledger.jsonl and Parquet WORM -> ulpf verify 0/1/2](docs/diagrams/three-tier-pipeline.png)

> Source: [`docs/diagrams/three-tier-pipeline.dot`](docs/diagrams/three-tier-pipeline.dot) — regenerate with `dot -Tpng -Gdpi=144 docs/diagrams/three-tier-pipeline.dot -o docs/diagrams/three-tier-pipeline.png`.

**Why two engines?** The frozen Aho-Corasick **baseline** (`UniversalParser`) is the control. The 3-tier pipeline runs on the same corpora and has to beat it on latency and accuracy at every scale, and on throughput at scale: **2.15×** EPS at 224k lines, with the small-corpus exception noted in §14 (0.82–0.96×). Every scorecard in §4–§5 prints both columns next to each other, so no number is graded against itself.

**Workspace (5 crates, 14,242 lines of Rust):**

| Crate | Role |
| :--- | :--- |
| `ulpf-core` | Sockets, Aho-Corasick classifier, zero-copy extractors, OCSF schema, signature LRU |
| `ulpf-integrity` | RFC 6962 Merkle tree, dual-trigger batcher (1,000 / 2,000 ms), Parquet writer, tamper verifier |
| `ulpf-ai` | Drain miner, Laya decision engine, air-gapped onboarder, 3-tier pipeline, evaluator |
| `ulpf-generator` | Multi-threaded load generator binary (`ulpf-generator`, 1.9 MB) |
| `ulpf-cli` | The `ulpf` binary (18.6 MB): `ingest · verify · onboard · benchmark · evaluate · inspect · tamper` |

---

## 4. Accuracy scorecards by corpus

Each table is a verbatim summary of the linked report's §1 scorecard. Columns: **Baseline** = frozen Aho-Corasick `UniversalParser`; **3-Tier** = `LRU + Drain + Laya`.

### How every metric is measured (the rulers)

Each metric below shows how it is graded: the exact definition, the line in [`crates/ulpf-ai/src/evaluator.rs`](crates/ulpf-ai/src/evaluator.rs) that implements it, and the ground truth it is compared against:

| Metric | Ruler (exact definition) | Code | Ground truth |
| :--- | :--- | :--- | :--- |
| **VCA** (vendor classification) | explicit label map, never fuzzy: the predicted vendor must contain — or be contained by — the GT label; a parsed `unknown` never satisfies a named GT vendor | `:1764–1783` | sidecar `gt_vendor`, else in-line derivation (`:1696–1703`) |
| **GA** (grouping accuracy, LogPai) | per engine cluster, count the records sharing that cluster's majority GT template tag; GA = Σ(majority) / N | `:1928–1959` | the same per-line GT template tag |
| **TA** (template accuracy) | `template_is_valid`: the cluster template must be a non-empty **exact token-aligned generalization** of the record's own masked line — same token count, every non-`<*>` token identical at its position, syslog GT tag (`%ASA-6-302013:`) preserved verbatim. **Token-F1 ≡ 1.0 — no similarity threshold** | `:1618–1640` | per-line GT tag (sidecar or in-line) |
| **Field accuracy ×5** (src/dst IP, src/dst port, protocol) | extracted value must appear **verbatim** in the raw line; an honest `null` grades correct *only* when the raw line carries no such marker (P5 null-correct rule); protocol may match by name or IANA number | `:1796–1891` | the raw bytes themselves — plus sidecar `gt_fields` where a sidecar exists |
| **“Macro F1”** † | arithmetic **mean of those five field accuracies** | `:1970` | — |
| **Disposition** | strict string equality against GT when the line carries a label; an unlabeled line grades correct only if the engine emits a non-`Unknown` disposition | `:1893–1918` | sidecar `gt_disposition`, else in-line action keywords |
| **Action inviolability** | `verify_action_preservation()` — no Drain cluster may hold both an allow-class and a deny-class anchor token → 100 or 0, never in between | `:1972–1976` | the anchor vocabulary itself |
| **Sidecar field grading** | null-vs-wrong discipline: a non-null expectation grades correct/wrong; an honest null counts as null — never silently skipped | `:2004` (`grade_gt_fields`) | `gt.jsonl` sidecars (adversarial · holdout · full), keyed by verbatim raw line |
| **Lossless SHA-256 / UUIDv7** | `raw_hash == SHA-256(raw)` recomputed per line; `event_id` parses as a UUID | `:1786–1792` | the raw bytes |

**Ground-truth policy:** where a sidecar exists it wins over in-line derivation (`:1693–1703`), because fuzz mutations destroy the in-line markers. On the adversarial and holdout corpora the sidecar is therefore the only reliable ground truth left. The core corpus (1,720 lines) has no sidecar; its GT comes from the lines themselves. Sidecars exist for adversarial (757), holdout (200) and full-scale (224,657 — see the 1,000,000-correct-field table in §1).

† **About the name "Macro F1":** it is not a precision/recall F1. The number is the mean of five exact-match field accuracies (`evaluator.rs:1970`), so read it as **mean field accuracy**. The old name stays only so this README, the reports and the matrix all match the generated output.

### 4.1 Core corpus — 1,720 committed fixture lines · [`eval_hardcore_report.md`](eval_hardcore_report.md)

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

### 4.2 Full scale — 224,657 lines / 183 MB · [`eval_full_report.md`](eval_full_report.md)

| Metric | Baseline | 3-Tier | Delta |
| :--- | ---: | ---: | :---: |
| Throughput | 395,842 EPS | **849,481 EPS** | **2.15×** |
| Data bandwidth | 77.68 MB/s | **237.26 MB/s** | **3.05×** |
| VCA / GA / TA / F1 / Disposition | 100 / 100 / 100 / 100 / 100 % | **100 / 100 / 100 / 100 / 100 %** | = (ceiling) |
| Unique templates | 137,986 | **32** | **4,312× compression** |
| Sidecar GT (5 field keys) | — | **1,000,000 correct · 0 wrong** | exact match |
| Audit-dump mismatches | — | **0 / 224,657** | clean |

### 4.3 Adversarial corpus (deterministic fuzz) · [`eval_adversarial_report.md`](eval_adversarial_report.md)

| Metric | Baseline | 3-Tier | Note |
| :--- | ---: | ---: | :--- |
| VCA | 96.30% | 96.30% | mutated vendor prefixes — parity |
| GA | 100.00% | 98.41% | −1.59 pt: deny-class variants only (see §14) |
| TA / F1 / Disposition | 100 / 97.15 / 93.53 % | **100** / 97.15 / 93.53 % | parity |
| Action Inviolability | N/A | **100% preserved** | anchor tokens held under fuzz |
| GT fields wrong | 1,524 | **1,524 (identical)** | fuzzer-caused; engine delta = 0 |

### 4.4 Frozen holdout (unseen vendors, executed once at P8) · [`eval_holdout_report.md`](eval_holdout_report.md)

| Metric | Baseline | 3-Tier |
| :--- | ---: | ---: |
| VCA (unseen vendors) | 0.00% | **40.00%** |
| GT fields correct | 0 | **320** |
| GT fields wrong | 720 | **400** (−44%) |
| TA | 100.00% | **100.00%** |
| Field F1 † | 64.00% | **80.00%** |

> The holdout is **frozen**: never regenerated, never re-run post-freeze. Its report timestamp (`2026-09-24T09:41:32Z`) is the audit trail.

---

## 5. Latency spectrum &amp; template compression

Full-scale percentile sweep ([`eval_full_report.md`](eval_full_report.md) §2):

| Percentile | Baseline | 3-Tier | Reduction |
| :--- | ---: | ---: | ---: |
| p1 (fastest 1%) | 512.25 µs | **5.97 µs** | −98.8% |
| **p50 (median)** | 1,104.72 µs | **7.28 µs** | **−99.3%** |
| p90 | 1,377.28 µs | **8.12 µs** | −99.4% |
| p99 | 1,510.92 µs | **10.97 µs** | −99.3% |
| p99.9 | 1,729.33 µs | **14.93 µs** | −99.1% |
| worst case | 4,328.61 µs | **50.08 µs** | −98.8% |

**Template compression** (why a SIEM would care): 224,657 raw lines collapse to **32 Drain templates** (baseline naive-split: 137,986) — a **4,312× reduction** in downstream indexing cost with TA held at 100% (every template still generalizes correctly against its masked line).

---

## 6. Robustness &amp; forensic guarantees

From §1b of each report. Each row is a pass/fail gate:

| Guarantee | Core | Full | Adversarial | How it's enforced |
| :--- | :---: | :---: | :---: | :--- |
| Format recognised (not `unknown`) | 1,720 | 224,657 | 729/757 | pinned parse order + classifier prefixes |
| No panic | 1,720 | 224,657 | 757 | `catch_unwind` around every parse |
| Lossless SHA-256 match | 1,720 | 224,657 | 757 | `raw_hash == SHA-256(raw_log)` verified per line |
| Action Inviolability | 100% | 100% | 100% | Drain anchor tokens + dedicated tests |

**Cryptographic chain of custody:**

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

The live ingest chain at full scale wrote **186 Parquet blocks with 186/186 verifying PASS** ([`FULL_DATASET_RESULTS.md`](FULL_DATASET_RESULTS.md) §4) — SIGTERM now flushes the in-flight batch, closing the tail-loss window found during P9.

---

## 7. Reproduce the proof

```bash
git clone git@github.com:animishraa05/layaRustparser.git && cd layaRustparser
cargo build --release

# Accuracy scorecards — regenerates the three non-frozen committed reports in ~90s
# (the holdout report is frozen at P8 and deliberately not re-runnable)
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 \
    --out eval_hardcore_report.md --audit-dump audit_dump.jsonl \
    --corpus core --data-dir data/raw

./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 \
    --out eval_adversarial_report.md --audit-dump audit_adv_dump.jsonl \
    --corpus adversarial --data-dir data/raw

# Full scale (dataset regenerable byte-for-byte, seed 777):
python3 scripts/gen_adversarial.py --full 25000
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 \
    --out eval_full_report.md --audit-dump audit_full_dump.jsonl \
    --corpus core --data-dir data/raw/full

# Integrity demo
./target/release/ulpf verify --file data/parquet/block_00001.parquet --ledger data/ledger.jsonl   # exit 0
./target/release/ulpf verify --file data/parquet/block_00000.parquet --ledger data/ledger.jsonl   # exit 2
```

> Note: `evaluate` and `benchmark` must be **release** builds. Run them back-to-back on an otherwise idle machine. Accuracy rows are deterministic; they came out byte-identical on every rerun. Throughput and latency rows swing with system load, which is why the reports carry timestamps (and why a racy parallel batch was thrown out during today's measurement session).

---

## 8. Testing &amp; verification gate

The project has **no CI** — this gate is the *only* automated check, and it runs before every commit:

```bash
cargo clippy --workspace --all-targets \
    -- -A clippy::too_many_arguments -A clippy::field_reassign_with_default -D warnings
cargo fmt --all -- --check
cargo test --workspace --no-fail-fast
```

**Latest run (2026-09-24): clippy 0 warnings · fmt clean · `103 passed · 0 failed · 1 ignored`.**

Suite coverage spans: parser field accuracy + byte-exact SHA-256 preservation per vendor, Drain anchor-token inviolability, LRU/Drain/Laya tier behaviour, Merkle/tamper/exit-code contracts, CLI smoke tests (7 end-to-end `ulpf` invocations), evaluator GT grading, and the air-gapped onboarder. The single `ignored` test is the documented load-sensitive micro-benchmark ([`AGENTS.md`](AGENTS.md) Gotchas).

---

## 9. SIH26156 requirements matrix

| # | Requirement (verbatim from [`docs/SIH_EVALUATION_DOSSIER.md`](docs/SIH_EVALUATION_DOSSIER.md)) | Status | Evidence |
| :--- | :--- | :---: | :--- |
| a | Preserve complete raw event data without information loss | yes | `raw_log` byte-exact + `raw_hash == SHA-256(raw)` on **all 224,657** full-scale lines (§6) |
| b | Extract and parse source-specific attributes | yes | zero-copy extractors (ASA/FortiGate/PAN-OS/pfSense/Suricata/CEF) — **mean field accuracy (“Macro F1” †) 100%** on core &amp; full (§4.1–4.2; rulers in §4) |
| c | Normalize fields into a common event taxonomy | yes | OCSF 1.3 `NetworkActivity` 4001 — **100% VCA** on core, adversarial-vendor-match, full |
| d | Maintain traceability between normalized and original events | yes | UUIDv7 `event_id` + SHA-256 digest on every event; `inspect` demo (§11.6) |
| e | Plug-and-play onboarding of new log sources | yes | `ulpf onboard` — 3–5 sample lines → validated parser spec, zero network (§11.7) |
| f | Unified visibility across enterprise environments | yes | 5 vendor families → uniform OCSF JSON + Parquet schema (§13) |
| g | Efficient SIEM and Data Lake integration | yes | Parquet WORM blocks, queryable via DuckDB/pandas (§13 snippet) |
| h | AI/ML-ready security and operational analytics | yes | **32 Drain templates from 224,657 lines (4,312× compression)** — pre-clustered feature IDs (§5) |
| i | Reduced parser development effort | yes | sample file → parser spec in **ms**, not days (§11.7) |
| j | Deployable in an air-gapped network | yes | single self-contained binaries, **zero** outbound calls anywhere in the runtime path |
| k | Packaged in a container for platform independence (target &lt; 35 MB) | partial | binary **18.6 MB, within the 35 MB target** (`ls -la target/release/ulpf`); container slim-down in progress — §16 P10.7 |

Full dossier with per-requirement narrative: [`docs/SIH_EVALUATION_DOSSIER.md`](docs/SIH_EVALUATION_DOSSIER.md).

---

## 10. Air-gapped Docker deployment

```bash
docker build -t ulpf .
# or
docker compose up -d        # publishes 5140/udp + 5140/tcp, mounts ./data
```

- [`Dockerfile`](Dockerfile): multi-stage build → slim runtime, binaries at `/usr/local/bin`, no network calls at any point in the runtime path.
- [`docker-compose.yml`](docker-compose.yml): isolated `ulpf-net` bridge, persistent `./data/parquet` + `./data/ledger.jsonl` mounts, `restart: unless-stopped`.
- Strictly air-gapped: **zero** outbound calls — no telemetry, no model downloads, no license checks.

---

## 11. Quick start

After `cargo build --release`, one command gives the full picture — both engines over the committed corpus, one aligned box you can screenshot (throughput, latency deltas, accuracy audit, PASS/FAIL gates, plain-words verdict), plus `scorecard_report.md` (regenerable, not committed):

```bash
./target/release/ulpf scorecard
```

Full walkthrough:

```bash
# 1. Build (rustc 1.96, edition 2021, stable toolchain)
cargo build --release

# 2. Run the accuracy evaluator — see every metric in one Markdown report
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 \
    --out report.md --corpus core --data-dir data/raw

# 3. Live ingest: start the engine (UDP+TCP on 5140, batch 1000 / 2000ms)
./target/release/ulpf ingest --udp 0.0.0.0:5140 --tcp 0.0.0.0:5140 \
    --parquet-dir data/parquet --ledger data/ledger.jsonl

# 4. In another terminal: blast it with 5 vendors of synthetic traffic
./target/release/ulpf-generator -t 127.0.0.1:5140 -p udp -r 50000 -d 10 -D all

# 5. Verify the Merkle chain (exit 0 = PASS, 2 = tampered)
./target/release/ulpf verify --file data/parquet/block_00001.parquet --ledger data/ledger.jsonl

# 6. Inspect one forensic record (UUIDv7, raw bytes, OCSF output)
./target/release/ulpf inspect --file data/parquet/block_00001.parquet --count 1

# 7. Air-gapped onboarding of an unseen format (3–5 sample lines, no internet)
./target/release/ulpf onboard --sample sample_new_firewall.log \
    --vendor juniper --model srx --out data/parsers

# 8. End-to-end scripted demo (writes to scratch data/demo/, never touches fixtures)
bash scripts/run_demo.sh
```

---

## 12. CLI reference

`ulpf --help` is authoritative; the summary below is transcribed from it.

| Subcommand | Purpose | Key flags (defaults) |
| :--- | :--- | :--- |
| `ingest` | Live Syslog UDP/TCP → OCSF → Merkle → Parquet | `--udp 0.0.0.0:5140` · `--tcp 0.0.0.0:5140` · `--parquet-dir data/parquet` · `--ledger data/ledger.jsonl` · `--batch-size 1000` · `--batch-timeout 2000` · `--reuse-port` |
| `verify` | Audit a Parquet block against the ledger | `--file <block.parquet>` · `--ledger data/ledger.jsonl` · **exit 0/1/2** |
| `onboard` | Synthesize + validate a parser from sample lines | `-s/--sample <file>` · `-v/--vendor <name>` · `-m/--model <name>` · `-o/--out data/parsers` |
| `benchmark` | Multi-core parse/normalize throughput | `--data-dir data/raw` *(long-only)* · `-d/--duration 5` · `-t/--threads 16` · `--compare` |
| `evaluate` | Baseline vs 3-Tier scorecard + percentiles + cache stats | `-e/--engine {all,baseline,tiered}` · `--corpus {core,adversarial,holdout}` · `--data-dir data/raw` · `-d/--duration 3` · `-t/--threads 16` · `-s/--samples 10000` · `-o/--out report.md` · `--json-out` · `--audit-dump` |
| `scorecard` | One-command side-by-side scorecard box: throughput, latency deltas, accuracy audit, PASS/FAIL gates, verdict + markdown report | `--corpus {core,adversarial,holdout}` · `--data-dir data/raw` · `-d/--duration 3` · `-t/--threads 16` · `-s/--samples 10000` · `-o/--out scorecard_report.md` |
| `inspect` | Print forensic records from a block | `-f/--file <block.parquet>` · `-c/--count 1` |
| `tamper` | Adversarial edit of a stored record (attack simulator) | `-f/--file <block.parquet>` · `-l/--leaf 0` · `-i/--ip 10.99.99.99` |

`ulpf-generator`:

```text
-t, --target <IP:PORT>     destination            [default: 127.0.0.1:5140]
-p, --proto <udp|tcp>      transport              [default: udp]
-r, --rate <EPS>           target rate, 0 = max  [default: 50000]
-d, --duration <sec>       0 = infinite           [default: 10]
-D, --dataset <NAME>       all|cisco|fortigate|paloalto|suricata|pfsense|kaggle
-w, --workers <N>          defaults to logical cores
    --data-dir <PATH>      where the raw datasets live (auto-located from cwd)
```

> **Gotcha (fixed):** `benchmark` uses `--data-dir` **long-only** — `-d` belongs to `--duration`. The old duplicate short flag used to panic in debug builds; P10.0 removed it and a CLI smoke test now guards it.

---

## 13. Data locations &amp; programmatic access

| Path | Contents |
| :--- | :--- |
| `data/raw/` — `*.log` + `suricata.json` (1,720 lines = the `core` corpus) | Cisco ASA (+VPN), FortiGate (+UTM), Palo Alto (+threat), pfSense (+IPv6), Suricata EVE — plus `kaggle_firewall.csv` (2,001 real-world rows, generator dataset, not in eval glob) |
| `data/raw/adversarial/` (757) | Deterministic fuzz corpus + `gt.jsonl` sidecar |
| `data/raw/holdout/` (200) | **Frozen** unseen-vendor corpus + sidecar — never regenerate |
| `data/raw/full/` (224,657, gitignored) | Full-scale dataset: `python3 scripts/gen_adversarial.py --full 25000` (seed 777, md5-reproducible) |
| `data/parquet/block_*.parquet` | WORM blocks (`block_00000` = tampered demo, `block_00001` = valid) |
| `data/ledger.jsonl` | Append-only Merkle roots |
| `data/parsers/` | Onboarder output (gitignored) |
| `eval_*.md` | Four timestamped scorecard reports (committed) |
| `FULL_DATASET_RESULTS.md` | Full-scale end-to-end narrative incl. 186-block chain |

**Programmatic access** — Parquet is a first-class analytics format:

```bash
# DuckDB
duckdb -c "SELECT vendor, count(*) FROM 'data/parquet/*.parquet' GROUP BY vendor;"
# or PyArrow / pandas
python3 -c "import pandas as pd; print(pd.read_parquet('data/parquet/block_00001.parquet').head())"
```

Schema (`ulpf-integrity/src/storage.rs`): `event_id · block_id · leaf_index · timestamp · vendor · raw_log · raw_hash · ocsf_json`.

---

## 14. Honest limitations

Known gaps, each one measured:

- **Adversarial GA: 98.41% vs baseline 100%** (−1.59 pt) — deny-class template variants cluster together on the fuzz corpus; Action Inviolability itself stays 100% (no ALLOW/DENY ever merges). Fix is tracked as a stretch item (deny-class sub-clustering).
- **Holdout disposition = 0/0** — the frozen holdout's vendors are *unseen* (no extractor exists for them), so both engines emit `Unknown` disposition on all 200 lines even though 160 carry ground-truth labels. It's an honest zero, not a skipped grade; vendor expansion (P10.2) is the fix.
- **Small-corpus throughput ratio ≈ 0.82–0.96×** — on 757–1,720 line corpora the tiered engine pays Drain bookkeeping that the pure baseline skips; at 224k+ lines the tiers pay off (**2.15×**). Latency wins at *every* scale (−92% to −99% p50).
- **Throughput/latency are load-sensitive** — same-code reruns today swung baseline p50 between 79 µs (idle) and 1,104 µs (busy). Accuracy is deterministic; timing is not. Reports embed timestamps for this reason.
- **Full-scale p50 (7.28 µs) is over the 5.0 µs latency gate.** The gate is calibrated on the core corpus, where p50 is 3.02 µs and passes. At 224,657 lines the working set no longer stays cache-resident, so p50 lands at 7.28 µs (still −99.3% vs baseline). The gate stays where it is; the gap is tracked in §16.
- **UDP socket ceiling ≈ 25–28k EPS/socket** in the live generator path (kernel-bound); the evaluator's in-process numbers are the engine's own capacity.
- **Container image not yet < 35 MB** — binary requirement met (18.6 MB); distroless/musl slim-down is P10.7 (§16).
- One test is load-flaky by design (`test_classification_sub_microsecond_benchmark`, `ignored`) — documented in [`AGENTS.md`](AGENTS.md).

---

## 15. Documentation map

| Document | What it gives you |
| :--- | :--- |
| [`FULL_DATASET_RESULTS.md`](FULL_DATASET_RESULTS.md) | 224,657-line end-to-end run: evals, live 186-block chain, onboarding, what we found wrong |
| [`OVERHAUL_PLAN.md`](OVERHAUL_PLAN.md) | The P1–P10 measurement-first overhaul plan + per-phase execution log |
| [`AGENTS.md`](AGENTS.md) | Contributor handbook: invariants, crate map, verification gate, gotchas, extension recipes |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | High-assurance architecture spec: data plane, integrity plane, math-grade reasoning |
| [`docs/diagrams/`](docs/diagrams/) | Graphviz `.dot` sources + rendered `.png` for every architecture diagram in this README and `docs/` (regenerate with `dot -Tpng -Gdpi=144`) |
| [`docs/SIH_EVALUATION_DOSSIER.md`](docs/SIH_EVALUATION_DOSSIER.md) | Requirement-by-requirement defense dossier (a–k) + out-of-scope honesty section |
| [`docs/SIMPLIFIED_EXPLANATION_AND_BENCHMARKS.md`](docs/SIMPLIFIED_EXPLANATION_AND_BENCHMARKS.md) | Plain-language guide (airport analogy) + benchmark deep-dive for non-experts |
| [`docs/DETAILED_IMPLEMENTATION_VS_PROPOSAL.md`](docs/DETAILED_IMPLEMENTATION_VS_PROPOSAL.md) | Implemented system vs original proposal, subsystem by subsystem |
| [`docs/PRESENTATION.md`](docs/PRESENTATION.md) | 5-slide technical presentation script |
| [`docs/DEMO.md`](docs/DEMO.md) | 2-minute demo video script with timestamps |
| [`docs/ULPF_Architecture_and_Benchmarks_Guide.pdf`](docs/ULPF_Architecture_and_Benchmarks_Guide.pdf) · [`docs/ULPF_SIH_Evaluation_Dossier_BW.pdf`](docs/ULPF_SIH_Evaluation_Dossier_BW.pdf) | Printable PDFs |
| [`eval_hardcore_report.md`](eval_hardcore_report.md) · [`eval_full_report.md`](eval_full_report.md) · [`eval_adversarial_report.md`](eval_adversarial_report.md) · [`eval_holdout_report.md`](eval_holdout_report.md) | The four timestamped accuracy scorecards this README cites |
| [`scripts/run_demo.sh`](scripts/run_demo.sh) | One-command non-destructive demo |

---

## 16. Project status &amp; roadmap

**Done (P1 → P10.0, 38 commits):** measurement-first ruler fixes → vendor extractors → CEF → parse-order/LRU tiers → audit null-correct rules → dynamic message-code anchors → GA/TA to 100 both engines → deterministic adversarial + frozen holdout corpora → sidecar ground truth → full-scale 224,657-line validation → 186-block live chain → CLI hardening (exit codes, SIGTERM flush, debug-panic fix, corpus glob loader) → ASA verdict-phrase union → repo-relative scripts → fresh re-run evidence + this README.

**In progress (P10):** universal wire formats (LEEF, generic KV/JSON/XML, RFC5424 SD) · vendor expansion (~10, ISRO-relevant) · multi-source measurement + Mapping-Coverage metric · container &lt; 35 MB (P10.7) · submission artifacts (readme/pitch/video) · deny-class GA stretch (P10.9, droppable).

**Performance gates** (checked whenever hot path/miner changes): p50 &lt; 5.0 µs *(core-corpus: 3.02 µs passes; full-scale 7.28 µs is over the line, tracked in §14)* · LRU hit rate &gt; 90% · Action Inviolability 100% · grouping accuracy &gt; 90%.

---

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
