# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T06:45:43.460491086+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **714739 EPS** | **688307 EPS** | **0.96x** |
| **Data Bandwidth (MB/s)** | **243.08 MB/s** | **234.10 MB/s** | **0.96x** |
| **Median Latency (p50)** | 76.74 µs | **3.69 µs** | **-95.2%** |
| **99th %ile Latency (p99)** | 138.47 µs | **8.56 µs** | **-93.8%** |
| **Vendor Classification (VCA)** | **100.00%** | **100.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **96.92%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **91.69%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **1081** | **35** | Fewer = Better Generalization |
| **Field Extraction Macro F1** | **94.18%** | **94.18%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **100.00%** | **100.00%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 67.41 µs | 1.51 µs | -97.8% |
| **p50 (Median)** | 76.74 µs | 3.69 µs | -95.2% |
| **p90** | 96.44 µs | 5.25 µs | -94.6% |
| **p99** | 138.47 µs | 8.56 µs | -93.8% |
| **p99.9 (Three Nines)** | 184.11 µs | 14.54 µs | -92.1% |
| **Worst Case (Max)** | 263.55 µs | 27.57 µs | -89.5% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 100.00% | 100.00% | > 95.0% |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 96.92% | > 90.0% |
| **Loghub Template Accuracy (TA %)** | 100.00% | 91.69% | > 85.0% |
| **Source IP Accuracy** | 100.0% | 100.0% | Ground Truth Exact |
| **Destination IP Accuracy** | 97.2% | 97.2% | Ground Truth Exact |
| **Source Port Accuracy** | 88.3% | 88.3% | Valid Port Range |
| **Destination Port Accuracy** | 88.3% | 88.3% | Valid Port Range |
| **Protocol Disambiguation** | 97.2% | 97.2% | OCSF 1.3 Schema 4001 |
| **Disposition Resolution Accuracy** | 100.00% | 100.00% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

