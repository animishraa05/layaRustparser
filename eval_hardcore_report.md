# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T06:28:29.521854663+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **756212 EPS** | **628853 EPS** | **0.83x** |
| **Data Bandwidth (MB/s)** | **257.13 MB/s** | **213.83 MB/s** | **0.83x** |
| **Median Latency (p50)** | 72.43 µs | **3.81 µs** | **-94.7%** |
| **99th %ile Latency (p99)** | 123.04 µs | **9.78 µs** | **-92.1%** |
| **Vendor Classification (VCA)** | **96.00%** | **96.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **96.92%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **91.69%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **1081** | **35** | Fewer = Better Generalization |
| **Field Extraction Macro F1** | **90.18%** | **92.58%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **96.00%** | **97.85%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 64.38 µs | 1.57 µs | -97.6% |
| **p50 (Median)** | 72.43 µs | 3.81 µs | -94.7% |
| **p90** | 86.21 µs | 6.07 µs | -93.0% |
| **p99** | 123.04 µs | 9.78 µs | -92.1% |
| **p99.9 (Three Nines)** | 181.40 µs | 34.06 µs | -81.2% |
| **Worst Case (Max)** | 266.95 µs | 189.49 µs | -29.0% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 96.00% | 96.00% | > 95.0% |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 96.92% | > 90.0% |
| **Loghub Template Accuracy (TA %)** | 100.00% | 91.69% | > 85.0% |
| **Source IP Accuracy** | 96.0% | 100.0% | Ground Truth Exact |
| **Destination IP Accuracy** | 93.2% | 97.2% | Ground Truth Exact |
| **Source Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Destination Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Protocol Disambiguation** | 93.2% | 97.2% | OCSF 1.3 Schema 4001 |
| **Disposition Resolution Accuracy** | 96.00% | 97.85% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

