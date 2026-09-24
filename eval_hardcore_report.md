# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T06:02:51.521629683+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **821242 EPS** | **668349 EPS** | **0.81x** |
| **Data Bandwidth (MB/s)** | **279.24 MB/s** | **227.27 MB/s** | **0.81x** |
| **Median Latency (p50)** | 67.75 µs | **3.45 µs** | **-94.9%** |
| **99th %ile Latency (p99)** | 95.60 µs | **9.71 µs** | **-89.8%** |
| **Vendor Classification (VCA)** | **96.00%** | **96.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **96.92%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **91.69%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **1081** | **35** | Fewer = Better Generalization |
| **Field Extraction Macro F1** | **90.18%** | **90.18%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **96.00%** | **96.00%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 64.13 µs | 1.45 µs | -97.7% |
| **p50 (Median)** | 67.75 µs | 3.45 µs | -94.9% |
| **p90** | 74.48 µs | 5.39 µs | -92.8% |
| **p99** | 95.60 µs | 9.71 µs | -89.8% |
| **p99.9 (Three Nines)** | 138.64 µs | 19.44 µs | -86.0% |
| **Worst Case (Max)** | 209.84 µs | 34.97 µs | -83.3% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 96.00% | 96.00% | > 95.0% |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 96.92% | > 90.0% |
| **Loghub Template Accuracy (TA %)** | 100.00% | 91.69% | > 85.0% |
| **Source IP Accuracy** | 96.0% | 96.0% | Ground Truth Exact |
| **Destination IP Accuracy** | 93.2% | 93.2% | Ground Truth Exact |
| **Source Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Destination Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Protocol Disambiguation** | 93.2% | 93.2% | OCSF 1.3 Schema 4001 |
| **Disposition Resolution Accuracy** | 96.00% | 96.00% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

