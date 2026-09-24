# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T05:34:34.867227483+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **832212 EPS** | **688706 EPS** | **0.83x** |
| **Data Bandwidth (MB/s)** | **282.98 MB/s** | **234.20 MB/s** | **0.83x** |
| **Median Latency (p50)** | 70.72 µs | **3.62 µs** | **-94.9%** |
| **99th %ile Latency (p99)** | 112.17 µs | **10.01 µs** | **-91.1%** |
| **Vendor Classification (VCA)** | **96.00%** | **96.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **96.92%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **91.69%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **1081** | **35** | Fewer = Better Generalization |
| **Field Extraction Macro F1** | **89.62%** | **89.62%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **93.15%** | **93.15%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 64.90 µs | 1.62 µs | -97.5% |
| **p50 (Median)** | 70.72 µs | 3.62 µs | -94.9% |
| **p90** | 82.28 µs | 5.25 µs | -93.6% |
| **p99** | 112.17 µs | 10.01 µs | -91.1% |
| **p99.9 (Three Nines)** | 147.38 µs | 16.71 µs | -88.7% |
| **Worst Case (Max)** | 213.21 µs | 32.35 µs | -84.8% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 96.00% | 96.00% | > 95.0% |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 96.92% | > 90.0% |
| **Loghub Template Accuracy (TA %)** | 100.00% | 91.69% | > 85.0% |
| **Source IP Accuracy** | 93.2% | 93.2% | Ground Truth Exact |
| **Destination IP Accuracy** | 93.2% | 93.2% | Ground Truth Exact |
| **Source Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Destination Port Accuracy** | 84.3% | 84.3% | Valid Port Range |
| **Protocol Disambiguation** | 93.2% | 93.2% | OCSF 1.3 Schema 4001 |
| **Disposition Resolution Accuracy** | 93.15% | 93.15% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

