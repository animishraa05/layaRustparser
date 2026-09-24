# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T05:25:31.999432894+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **97468 EPS** | **645360 EPS** | **6.62x** |
| **Data Bandwidth (MB/s)** | **33.14 MB/s** | **219.45 MB/s** | **6.62x** |
| **Median Latency (p50)** | 161.82 µs | **5.99 µs** | **-96.3%** |
| **99th %ile Latency (p99)** | 1261.81 µs | **17.95 µs** | **-98.6%** |
| **Vendor Classification (VCA)** | **96.00%** | **96.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **93.31%** | **96.92%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **38.31%** | **91.69%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **12** | **35** | Fewer = Better Generalization |
| **Field Extraction Macro F1** | **89.62%** | **89.62%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **89.85%** | **89.85%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 89.71 µs | 2.75 µs | -96.9% |
| **p50 (Median)** | 161.82 µs | 5.99 µs | -96.3% |
| **p90** | 865.91 µs | 8.95 µs | -99.0% |
| **p99** | 1261.81 µs | 17.95 µs | -98.6% |
| **p99.9 (Three Nines)** | 1452.97 µs | 30.74 µs | -97.9% |
| **Worst Case (Max)** | 1730.51 µs | 54.56 µs | -96.8% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 96.00% | 96.00% | > 95.0% |
| **LogPai Grouping Accuracy (GA %)** | 93.31% | 96.92% | > 90.0% |
| **Loghub Template Accuracy (TA %)** | 38.31% | 91.69% | > 85.0% |
| **Source IP Accuracy** | 93.2% | 93.2% | Ground Truth Exact |
| **Destination IP Accuracy** | 93.2% | 93.2% | Ground Truth Exact |
| **Source Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Destination Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Protocol Disambiguation** | 93.2% | 93.2% | OCSF 1.3 Schema 4001 |
| **Disposition Resolution Accuracy** | 89.85% | 89.85% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

