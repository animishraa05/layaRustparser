# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T09:41:32.506663733+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 200 logs (27.04 KB)  
**Corpus Kind:** `holdout` (core = fixed file set, adversarial/holdout = sidecar-GT corpora)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **1721640 EPS** | **154514 EPS** | **0.09x** |
| **Data Bandwidth (MB/s)** | **227.32 MB/s** | **20.40 MB/s** | **0.09x** |
| **Median Latency (p50)** | 74.47 µs | **5.63 µs** | **-92.4%** |
| **99th %ile Latency (p99)** | 133.95 µs | **12.49 µs** | **-90.7%** |
| **Vendor Classification (VCA)** | **0.00%** | **40.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **100.00%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **100.00%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **45** | **6** | Strictly Fewer vs Naive Baseline (§5.2) |
| **Field Extraction Macro F1** | **64.00%** | **80.00%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **0.00%** | **0.00%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 1b. Corpus Robustness Scorecard (P7)

| Robustness Dimension | Baseline | 3-Tier (`LRU+Drain+Laya`) | Gate Meaning |
| :--- | ---: | ---: | :--- |
| **Lines Audited** | 200 | 200 | Full corpus, every line scored |
| **Format Recognized** | 0 | 80 | Vendor routed to a known format (not `unknown`) |
| **No Panic** | 200 | 200 | `catch_unwind` parse, zero aborts |
| **Lossless (SHA-256 match)** | 200 | 200 | `raw_hash` == SHA-256(raw), byte-exact |
| **Sidecar GT fields graded** | 720 | 720 | Non-null expectations (correct + wrong) |
| **GT fields correct** | 0 | 320 | Engine matched the expectation |
| **GT fields wrong** | 720 | 400 | Contradicted expectation (strictly worse than null) |
| **GT fields null (honest)** | 280 | 280 | No expectation — excluded from wrong |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 67.45 µs | 4.66 µs | -93.1% |
| **p50 (Median)** | 74.47 µs | 5.63 µs | -92.4% |
| **p90** | 95.42 µs | 7.99 µs | -91.6% |
| **p99** | 133.95 µs | 12.49 µs | -90.7% |
| **p99.9 (Three Nines)** | 195.30 µs | 39.79 µs | -79.6% |
| **Worst Case (Max)** | 296.51 µs | 59.65 µs | -79.9% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 0.00% | 40.00% | ≥ Baseline (parity, §5.1) |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 100.00% | ≥ Naive Baseline (§5.2) |
| **Loghub Template Accuracy (TA %)** | 100.00% | 100.00% | > Naive Baseline (§5.2); ≥ at 100% ceiling (see §5.2 amendment) |
| **Source IP Accuracy** | 20.0% | 60.0% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Destination IP Accuracy** | 20.0% | 60.0% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Source Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Destination Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Protocol Disambiguation** | 80.0% | 80.0% | OCSF 4001; null correct without protocol evidence (P5) |
| **Disposition Resolution Accuracy** | 0.00% | 0.00% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

