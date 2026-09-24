# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T07:13:12.227784065+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 1300 logs (452.68 KB)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **709209 EPS** | **692271 EPS** | **0.98x** |
| **Data Bandwidth (MB/s)** | **241.22 MB/s** | **235.47 MB/s** | **0.98x** |
| **Median Latency (p50)** | 76.91 µs | **3.73 µs** | **-95.2%** |
| **99th %ile Latency (p99)** | 177.73 µs | **13.47 µs** | **-92.4%** |
| **Vendor Classification (VCA)** | **100.00%** | **100.00%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **96.92%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **91.69%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **1081** | **35** | Strictly Fewer vs Naive Baseline (§5.2) |
| **Field Extraction Macro F1** | **100.00%** | **100.00%** | IP/Port/Proto Extraction |
| **Disposition Resolution Accuracy** | **100.00%** | **100.00%** | OCSF Action Mapping |
| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 68.52 µs | 1.49 µs | -97.8% |
| **p50 (Median)** | 76.91 µs | 3.73 µs | -95.2% |
| **p90** | 91.67 µs | 6.87 µs | -92.5% |
| **p99** | 177.73 µs | 13.47 µs | -92.4% |
| **p99.9 (Three Nines)** | 267.39 µs | 33.44 µs | -87.5% |
| **Worst Case (Max)** | 422.92 µs | 63.84 µs | -84.9% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 100.00% | 100.00% | ≥ Baseline (parity, §5.1) |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 96.92% | ≥ Naive Baseline (§5.2) |
| **Loghub Template Accuracy (TA %)** | 100.00% | 91.69% | > Naive Baseline (§5.2) |
| **Source IP Accuracy** | 100.0% | 100.0% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Destination IP Accuracy** | 100.0% | 100.0% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Source Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Destination Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Protocol Disambiguation** | 100.0% | 100.0% | OCSF 4001; null correct without protocol evidence (P5) |
| **Disposition Resolution Accuracy** | 100.00% | 100.00% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

