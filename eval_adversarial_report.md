# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T09:41:59.599229068+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 757 logs (326.88 KB)  
**Corpus Kind:** `adversarial` (core = fixed file set, adversarial/holdout = sidecar-GT corpora)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **830410 EPS** | **749848 EPS** | **0.90x** |
| **Data Bandwidth (MB/s)** | **349.89 MB/s** | **315.96 MB/s** | **0.90x** |
| **Median Latency (p50)** | 76.83 µs | **2.96 µs** | **-96.1%** |
| **99th %ile Latency (p99)** | 119.30 µs | **8.75 µs** | **-92.7%** |
| **Vendor Classification (VCA)** | **96.30%** | **96.30%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **98.41%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **100.00%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **625** | **81** | Strictly Fewer vs Naive Baseline (§5.2) |
| **Field Extraction Macro F1** | **95.01%** | **95.01%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **93.53%** | **93.53%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 1b. Corpus Robustness Scorecard (P7)

| Robustness Dimension | Baseline | 3-Tier (`LRU+Drain+Laya`) | Gate Meaning |
| :--- | ---: | ---: | :--- |
| **Lines Audited** | 757 | 757 | Full corpus, every line scored |
| **Format Recognized** | 729 | 729 | Vendor routed to a known format (not `unknown`) |
| **No Panic** | 757 | 757 | `catch_unwind` parse, zero aborts |
| **Lossless (SHA-256 match)** | 757 | 757 | `raw_hash` == SHA-256(raw), byte-exact |
| **Sidecar GT fields graded** | 3110 | 3110 | Non-null expectations (correct + wrong) |
| **GT fields correct** | 1467 | 1467 | Engine matched the expectation |
| **GT fields wrong** | 1643 | 1643 | Contradicted expectation (strictly worse than null) |
| **GT fields null (honest)** | 675 | 675 | No expectation — excluded from wrong |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 68.63 µs | 1.56 µs | -97.7% |
| **p50 (Median)** | 76.83 µs | 2.96 µs | -96.1% |
| **p90** | 89.92 µs | 5.28 µs | -94.1% |
| **p99** | 119.30 µs | 8.75 µs | -92.7% |
| **p99.9 (Three Nines)** | 150.01 µs | 14.41 µs | -90.4% |
| **Worst Case (Max)** | 223.23 µs | 31.70 µs | -85.8% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 96.30% | 96.30% | ≥ Baseline (parity, §5.1) |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 98.41% | ≥ Naive Baseline (§5.2) |
| **Loghub Template Accuracy (TA %)** | 100.00% | 100.00% | > Naive Baseline (§5.2); ≥ at 100% ceiling (see §5.2 amendment) |
| **Source IP Accuracy** | 92.7% | 92.7% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Destination IP Accuracy** | 92.7% | 92.7% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Source Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Destination Port Accuracy** | 97.6% | 97.6% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Protocol Disambiguation** | 91.9% | 91.9% | OCSF 4001; null correct without protocol evidence (P5) |
| **Disposition Resolution Accuracy** | 93.53% | 93.53% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

