# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T07:39:57.591645733+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **712824 EPS** | **697315 EPS** | **0.98x** |
| **Data Bandwidth (MB/s)** | **242.49 MB/s** | **237.18 MB/s** | **0.98x** |
| **Median Latency (p50)** | 73.46 µs | **3.59 µs** | **-95.1%** |
| **99th %ile Latency (p99)** | 111.36 µs | **8.15 µs** | **-92.7%** |
| **Vendor Classification (VCA)** | **100.00%** | **100.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **100.00%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **100.00%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **1081** | **55** | Strictly Fewer vs Naive Baseline (§5.2) |
| **Field Extraction Macro F1** | **100.00%** | **100.00%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **100.00%** | **100.00%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 66.73 µs | 1.47 µs | -97.8% |
| **p50 (Median)** | 73.46 µs | 3.59 µs | -95.1% |
| **p90** | 89.81 µs | 5.48 µs | -93.9% |
| **p99** | 111.36 µs | 8.15 µs | -92.7% |
| **p99.9 (Three Nines)** | 146.97 µs | 13.41 µs | -90.9% |
| **Worst Case (Max)** | 218.97 µs | 40.34 µs | -81.6% |

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

