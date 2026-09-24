# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T10:13:02.024786685+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 10799 logs (2988.72 KB)  
**Corpus Kind:** `core` (core = fixed file set, adversarial/holdout = sidecar-GT corpora)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **950035 EPS** | **931260 EPS** | **0.98x** |
| **Data Bandwidth (MB/s)** | **256.76 MB/s** | **251.82 MB/s** | **0.98x** |
| **Median Latency (p50)** | 76.28 µs | **2.46 µs** | **-96.8%** |
| **99th %ile Latency (p99)** | 121.03 µs | **6.81 µs** | **-94.4%** |
| **Vendor Classification (VCA)** | **100.00%** | **100.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **100.00%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **100.00%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **8056** | **32** | Strictly Fewer vs Naive Baseline (§5.2) |
| **Field Extraction Macro F1** | **100.00%** | **100.00%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **100.00%** | **100.00%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 1b. Corpus Robustness Scorecard (P7)

| Robustness Dimension | Baseline | 3-Tier (`LRU+Drain+Laya`) | Gate Meaning |
| :--- | ---: | ---: | :--- |
| **Lines Audited** | 10799 | 10799 | Full corpus, every line scored |
| **Format Recognized** | 10799 | 10799 | Vendor routed to a known format (not `unknown`) |
| **No Panic** | 10799 | 10799 | `catch_unwind` parse, zero aborts |
| **Lossless (SHA-256 match)** | 10799 | 10799 | `raw_hash` == SHA-256(raw), byte-exact |
| **Sidecar GT fields graded** | 48000 | 48000 | Non-null expectations (correct + wrong) |
| **GT fields correct** | 48000 | 48000 | Engine matched the expectation |
| **GT fields wrong** | 0 | 0 | Contradicted expectation (strictly worse than null) |
| **GT fields null (honest)** | 5995 | 5995 | No expectation — excluded from wrong |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 68.65 µs | 1.49 µs | -97.8% |
| **p50 (Median)** | 76.28 µs | 2.46 µs | -96.8% |
| **p90** | 90.35 µs | 4.25 µs | -95.3% |
| **p99** | 121.03 µs | 6.81 µs | -94.4% |
| **p99.9 (Three Nines)** | 160.34 µs | 13.17 µs | -91.8% |
| **Worst Case (Max)** | 280.58 µs | 34.60 µs | -87.7% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 100.00% | 100.00% | ≥ Baseline (parity, §5.1) |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 100.00% | ≥ Naive Baseline (§5.2) |
| **Loghub Template Accuracy (TA %)** | 100.00% | 100.00% | > Naive Baseline (§5.2); ≥ at 100% ceiling (see §5.2 amendment) |
| **Source IP Accuracy** | 100.0% | 100.0% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Destination IP Accuracy** | 100.0% | 100.0% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Source Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Destination Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Protocol Disambiguation** | 100.0% | 100.0% | OCSF 4001; null correct without protocol evidence (P5) |
| **Disposition Resolution Accuracy** | 100.00% | 100.00% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

