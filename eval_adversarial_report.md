# ULPF Hardcore Architectural & Accuracy Telemetry Report

**Timestamp:** 2026-09-24T12:43:10.735653313+00:00  
**Environment:** Linux (x86_64, 16 Cores) | **Workers:** 16 parallel threads  
**Duration:** 3s per engine | **Corpus:** 757 logs (326.88 KB)  
**Corpus Kind:** `adversarial` (core = fixed file set, adversarial/holdout = sidecar-GT corpora)  

---

## 1. Executive Telemetry & Accuracy Scorecard

| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |
| :--- | :---: | :---: | :---: |
| **Throughput (EPS)** | **730846 EPS** | **597480 EPS** | **0.82x** |
| **Data Bandwidth (MB/s)** | **307.85 MB/s** | **251.62 MB/s** | **0.82x** |
| **Median Latency (p50)** | 80.56 µs | **4.14 µs** | **-94.9%** |
| **99th %ile Latency (p99)** | 173.91 µs | **22.05 µs** | **-87.3%** |
| **Vendor Classification (VCA)** | **96.30%** | **96.30%** | Ground-Truth Exact Match |
| **Grouping Accuracy (GA %)** | **100.00%** | **98.41%** | Loghub-2.0 Standard |
| **Template Accuracy (TA %)** | **100.00%** | **100.00%** | Template Validity (generalization-correct vs masked line) |
| **Oracle GA Ceiling (GT-hash, unfair)** | **100.00%** | **100.00%** | Labeled Ceiling — Not a Fair Baseline |
| **Unique Templates (compression)** | **625** | **81** | Strictly Fewer vs Naive Baseline (§5.2) |
| **Field Extraction Macro F1** | **97.15%** | **97.15%** | IP/Port/Proto Extraction |
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
| **GT fields correct** | 1586 | 1586 | Engine matched the expectation |
| **GT fields wrong** | 1524 | 1524 | Contradicted expectation (strictly worse than null) |
| **GT fields wrong by key** | dst_ip 556, dst_port 43, protocol 203, src_ip 679, src_port 43 | dst_ip 556, dst_port 43, protocol 203, src_ip 679, src_port 43 | Diagnostic: where mismatches concentrate (not a gate metric) |
| **GT fields null (honest)** | 675 | 675 | No expectation — excluded from wrong |

## 2. Microsecond Latency Spectrum

| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |
| :--- | :---: | :---: | :---: |
| **p1 (Fastest 1%)** | 69.91 µs | 1.85 µs | -97.4% |
| **p50 (Median)** | 80.56 µs | 4.14 µs | -94.9% |
| **p90** | 111.59 µs | 8.24 µs | -92.6% |
| **p99** | 173.91 µs | 22.05 µs | -87.3% |
| **p99.9 (Three Nines)** | 234.08 µs | 40.66 µs | -82.6% |
| **Worst Case (Max)** | 450.09 µs | 61.36 µs | -86.4% |

## 3. Academic Accuracy & Quality Breakdown

| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |
| :--- | :---: | :---: | :---: |
| **Vendor Classification Accuracy** | 96.30% | 96.30% | ≥ Baseline (parity, §5.1) |
| **LogPai Grouping Accuracy (GA %)** | 100.00% | 98.41% | ≥ Naive Baseline (§5.2) |
| **Loghub Template Accuracy (TA %)** | 100.00% | 100.00% | > Naive Baseline (§5.2); ≥ at 100% ceiling (see §5.2 amendment) |
| **Source IP Accuracy** | 96.3% | 96.3% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Destination IP Accuracy** | 96.3% | 96.3% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |
| **Source Port Accuracy** | 100.0% | 100.0% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Destination Port Accuracy** | 97.6% | 97.6% | Valid Port Range; null correct only when raw lacks port evidence (P5) |
| **Protocol Disambiguation** | 95.5% | 95.5% | OCSF 4001; null correct without protocol evidence (P5) |
| **Disposition Resolution Accuracy** | 93.53% | 93.53% | Security Invariant |
| **Lossless Cryptographic SHA-256** | 100.00% | 100.00% | 100.0% Required |

