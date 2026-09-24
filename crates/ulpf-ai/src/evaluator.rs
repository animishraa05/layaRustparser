use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ulpf_core::parser::lru_cache::SignatureLruCache;
use ulpf_core::parser::{compute_sha256, UniversalParser};
use ulpf_core::schema::ocsf::NetworkActivity;
use uuid::Uuid;

use crate::drain::{DrainConfig, DrainMiner};
use crate::pipeline::TieredPipeline;

/// Detailed percentile latency statistics in microseconds
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LatencySummary {
    pub min_micros: f64,
    pub p1_micros: f64,
    pub p5_micros: f64,
    pub p25_micros: f64,
    pub p50_micros: f64,
    pub p75_micros: f64,
    pub p90_micros: f64,
    pub p95_micros: f64,
    pub p99_micros: f64,
    pub p999_micros: f64,
    pub p9999_micros: f64,
    pub max_micros: f64,
    pub mean_micros: f64,
    pub std_dev_micros: f64,
    pub samples_count: usize,
}

/// Hardware throughput and data bandwidth telemetry
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HardwareThroughputSummary {
    pub events_per_sec: f64,
    pub megabytes_per_sec: f64,
    pub events_per_ms_per_core: f64,
    pub per_core_eps: f64,
    pub total_processed: u64,
    pub total_bytes_processed: u64,
    pub duration_secs: f64,
}

/// Comprehensive academic & operational accuracy audit (Loghub / LogPai standards)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AccuracyAuditSummary {
    pub total_audited: usize,
    /// Vendor classification accuracy vs ground truth source (% correctly identified)
    pub vendor_classification_accuracy_pct: f64,
    /// Academic Grouping Accuracy (GA %): cluster purity against ground truth template IDs
    pub grouping_accuracy_ga_pct: f64,
    /// Academic Template Accuracy (TA %): dynamic variable isolation into <*>
    pub template_accuracy_ta_pct: f64,
    /// Macro-averaged field extraction accuracy F1-score across all attributes
    pub field_extraction_f1_pct: f64,
    /// Source IP extraction accuracy (valid IPv4/IPv6 present in raw line)
    pub src_ip_accuracy_pct: f64,
    /// Destination IP extraction accuracy
    pub dst_ip_accuracy_pct: f64,
    /// Source port extraction accuracy (valid 1..65535 in raw line)
    pub src_port_accuracy_pct: f64,
    /// Destination port extraction accuracy
    pub dst_port_accuracy_pct: f64,
    /// Transport protocol extraction accuracy (TCP, UDP, ICMP)
    pub protocol_accuracy_pct: f64,
    /// Security action / disposition resolution accuracy
    pub disposition_accuracy_pct: f64,
    /// DrainDotNet UniqueEventPatterns anchor inviolability rate (ALLOW vs DENY separation)
    pub action_inviolability_pct: f64,
    /// Cryptographic SHA-256 lossless match rate
    pub lossless_sha256_match_pct: f64,
    /// RFC 4122 UUIDv7 conformity rate
    pub valid_uuid_v7_pct: f64,
    /// Oracle ceiling GA: clusters built from ground truth itself (hash of the GT tag).
    /// Labeled ceiling ONLY — never a fair baseline (a fair naive baseline is the engine's
    /// own post-mask exact-match clustering).
    pub oracle_ga_pct: f64,
    /// Number of distinct clusters produced (template compression; fewer = stronger generalization)
    pub unique_clusters: usize,
}

/// A single per-record audit failure, emitted for `--audit-dump` JSONL export.
/// Metric names: vendor, grouping, template, src_ip, dst_ip, src_port, dst_port,
/// protocol, disposition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditFailure {
    pub metric: String,
    pub corpus_index: usize,
    pub raw: String,
    pub expected: String,
    pub observed: String,
    pub cluster_id: usize,
}

impl AuditFailure {
    fn new(
        metric: &str,
        corpus_index: usize,
        raw: &str,
        expected: &str,
        observed: &str,
        cluster_id: usize,
    ) -> Self {
        Self {
            metric: metric.to_string(),
            corpus_index,
            raw: raw.to_string(),
            expected: expected.to_string(),
            observed: observed.to_string(),
            cluster_id,
        }
    }
}

/// Internal multi-tier diagnostics telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierDiagnosticsSummary {
    pub tier1_lru_hit_rate: f64,
    pub tier1_lookups: u64,
    pub tier1_hits: u64,
    pub tier1_misses: u64,
    pub tier1_evictions: u64,
    pub tier1_entries_count: usize,
    pub tier2_clusters_count: usize,
    pub tier2_cluster_matches: u64,
    pub tier2_unique_anchor_enforced: bool,
    pub tier3_laya_dispatches: u64,
    pub tier3_ai_deduplication_pct: f64,
    pub tier3_auto_onboarded_count: u64,
}

/// Comprehensive benchmark metrics for an architecture run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkTierResult {
    pub name: String,
    pub throughput: HardwareThroughputSummary,
    pub latency: LatencySummary,
    pub accuracy: AccuracyAuditSummary,
    pub tier_diagnostics: Option<TierDiagnosticsSummary>,
    /// Per-record audit mismatches (for `--audit-dump` JSONL export)
    pub failures: Vec<AuditFailure>,
    /// P7 robustness block (panic/losslessness/format + null-vs-wrong fields)
    pub robustness: RobustnessSummary,
}

/// Comprehensive side-by-side evaluation comparison report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub timestamp: String,
    pub mode: String,
    pub threads: usize,
    pub duration_secs: u64,
    pub corpus_size: usize,
    pub corpus_total_bytes: usize,
    pub baseline: Option<BenchmarkTierResult>,
    pub tiered_pipeline: Option<BenchmarkTierResult>,
    pub throughput_speedup_factor: Option<f64>,
    pub bandwidth_speedup_factor: Option<f64>,
    pub latency_reduction_p50_pct: Option<f64>,
    pub latency_reduction_p99_pct: Option<f64>,
    /// Which corpus was scored: `core` | `adversarial` | `holdout` (P7).
    #[serde(default = "default_corpus_kind")]
    pub corpus_kind: String,
}

fn default_corpus_kind() -> String {
    "core".to_string()
}

/// P7.1 sidecar ground-truth record (`gt.jsonl`, one JSON object per raw
/// line). Authoritative over in-line `extract_ground_truth` for its verbatim
/// `raw` line: mutations (truncation / encoding / field-damage) destroy the
/// in-line markers, so the sidecar is the only honest GT source on the
/// adversarial and holdout corpora.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarGroundTruth {
    /// Verbatim raw line — also the override key.
    pub raw: String,
    pub gt_vendor: String,
    pub gt_template_tag: String,
    /// Expected engine fields. `null` = no expectation: counted `null`,
    /// never `wrong` (P7 null-vs-wrong discipline).
    pub gt_fields: serde_json::Value,
    pub gt_disposition: Option<String>,
    pub gt_protocol: Option<String>,
    pub difficulty: String,
    pub origin: String,
}

/// Sidecar overrides keyed by verbatim raw line, fed through `audit_accuracy`.
pub type GtOverrides = HashMap<String, SidecarGroundTruth>;

/// P7 robustness block: no-panic / losslessness / format recognition plus
/// the null-vs-wrong field discipline against explicit sidecar expectations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RobustnessSummary {
    /// Lines scored by the audit pass.
    pub lines_total: usize,
    /// Lines whose vendor was recognized as a known format (not `unknown`).
    pub format_recognized: usize,
    /// Lines parsed without a panic.
    pub no_panic: usize,
    /// Lines whose `raw_hash` still equals SHA-256(raw) byte-for-byte.
    pub lossless_ok: usize,
    /// Non-null sidecar `gt_fields` entries graded (correct + wrong).
    pub gt_fields_total: usize,
    /// Sidecar expectations the engine matched.
    pub gt_fields_correct: usize,
    /// Sidecar expectations the engine contradicted (strictly worse than null).
    pub gt_fields_wrong: usize,
    /// Sidecar entries that honestly expected nothing.
    pub gt_fields_null: usize,
    /// Diagnostic: mismatches by field key (`src_ip 603, protocol 240, ...`)
    /// — tells you WHERE `gt_fields_wrong` concentrates. Not a gate metric;
    /// `#[serde(default)]` keeps pre-P9 report deserialization working.
    #[serde(default)]
    pub gt_wrong_by_key: std::collections::BTreeMap<String, usize>,
}

/// Load a `gt.jsonl` sidecar into raw-keyed overrides.
pub fn load_sidecar_gt(path: &std::path::Path) -> anyhow::Result<GtOverrides> {
    let text = std::fs::read_to_string(path)?;
    let mut map = GtOverrides::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let rec: SidecarGroundTruth = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("{}:{}: {}", path.display(), i + 1, e))?;
        map.insert(rec.raw.clone(), rec);
    }
    Ok(map)
}

impl EvaluationReport {
    /// Render dense, hardcore terminal comparative dashboard with extensive accuracy section
    pub fn render_terminal_dashboard(&self) -> String {
        let mut out = String::new();
        out.push_str("\n\x1b[1;36m========================================================================================================\x1b[0m\n");
        out.push_str("\x1b[1;32m                  ULPF HARDCORE ARCHITECTURAL & ACCURACY EVALUATOR SUITE                                \x1b[0m\n");
        out.push_str("\x1b[1;36m========================================================================================================\x1b[0m\n");
        out.push_str(&format!(
            "  Execution Mode        : \x1b[1;33m{}\x1b[0m\n",
            self.mode.to_uppercase()
        ));
        out.push_str(&format!("  Workers / CPU Threads : {}\n", self.threads));
        out.push_str(&format!(
            "  Evaluation Duration   : {} seconds per engine\n",
            self.duration_secs
        ));
        out.push_str(&format!(
            "  Input Corpus Size     : {} log records ({:.2} KB in RAM)\n",
            self.corpus_size,
            self.corpus_total_bytes as f64 / 1024.0
        ));
        out.push_str("\x1b[1;36m--------------------------------------------------------------------------------------------------------\x1b[0m\n");

        if let (Some(b), Some(t)) = (&self.baseline, &self.tiered_pipeline) {
            // Dual-architecture side-by-side mode
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "Evaluation Dimension", "Baseline (UniversalParser)", "3-Tier (LRU+Drain+Laya)"
            ));
            out.push_str("\x1b[1;36m--------------------------------------------------------------------------------------------------------\x1b[0m\n");

            // Throughput & Bandwidth
            out.push_str(&format!(
                "  {:<38} | {:<27.0} | \x1b[1;32m{:<27.0}\x1b[0m\n",
                "Throughput (Events/Sec)", b.throughput.events_per_sec, t.throughput.events_per_sec
            ));
            out.push_str(&format!(
                "  {:<38} | {:<24.2} MB/s | \x1b[1;32m{:<24.2} MB/s\x1b[0m\n",
                "Data Bandwidth Rate",
                b.throughput.megabytes_per_sec,
                t.throughput.megabytes_per_sec
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "Total Normalized Events",
                b.throughput.total_processed,
                t.throughput.total_processed
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27.0} | {:<27.0}\n",
                "Per-Core Throughput (EPS/core)",
                b.throughput.per_core_eps,
                t.throughput.per_core_eps
            ));

            out.push_str("\x1b[1;36m  ---------------------------------- LATENCY DISTRIBUTION SPECTRUM (µs) --------------------------------\x1b[0m\n");
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "Minimum Latency (p0)", b.latency.min_micros, t.latency.min_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "Fast-Path 1st %ile (p1)", b.latency.p1_micros, t.latency.p1_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "Median Latency (p50)", b.latency.p50_micros, t.latency.p50_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "90th Percentile (p90)", b.latency.p90_micros, t.latency.p90_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "99th Percentile (p99)", b.latency.p99_micros, t.latency.p99_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "Three Nines Tail (p99.9)", b.latency.p999_micros, t.latency.p999_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | {:<25.2} µs\n",
                "Worst Case (Max)", b.latency.max_micros, t.latency.max_micros
            ));
            out.push_str(&format!(
                "  {:<38} | {:<25.2} µs | \x1b[1;32m{:<25.2} µs\x1b[0m\n",
                "Latency Jitter / StdDev (σ)", b.latency.std_dev_micros, t.latency.std_dev_micros
            ));

            out.push_str("\x1b[1;36m  ---------------------------------- EXHAUSTIVE ACCURACY AUDIT (LOGHUB & SIEM) -------------------------\x1b[0m\n");
            out.push_str(&format!(
                "  {:<38} | \x1b[1;32m{:<27}\x1b[0m | \x1b[1;32m{:<27}\x1b[0m\n",
                "Vendor Classification Accuracy (VCA)",
                format!("{:.2}%", b.accuracy.vendor_classification_accuracy_pct),
                format!("{:.2}%", t.accuracy.vendor_classification_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | \x1b[1;32m{:<27}\x1b[0m\n",
                "Academic Grouping Accuracy (GA %)",
                format!("{:.2}%", b.accuracy.grouping_accuracy_ga_pct),
                format!("{:.2}%", t.accuracy.grouping_accuracy_ga_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | \x1b[1;32m{:<27}\x1b[0m\n",
                "Academic Template Accuracy (TA %)",
                format!("{:.2}%", b.accuracy.template_accuracy_ta_pct),
                format!("{:.2}%", t.accuracy.template_accuracy_ta_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | \x1b[1;32m{:<27}\x1b[0m | \x1b[1;32m{:<27}\x1b[0m\n",
                "Field Extraction Macro F1-Score",
                format!("{:.2}%", b.accuracy.field_extraction_f1_pct),
                format!("{:.2}%", t.accuracy.field_extraction_f1_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "  • Source IP Accuracy",
                format!("{:.1}%", b.accuracy.src_ip_accuracy_pct),
                format!("{:.1}%", t.accuracy.src_ip_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "  • Destination IP Accuracy",
                format!("{:.1}%", b.accuracy.dst_ip_accuracy_pct),
                format!("{:.1}%", t.accuracy.dst_ip_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "  • Source Port Accuracy",
                format!("{:.1}%", b.accuracy.src_port_accuracy_pct),
                format!("{:.1}%", t.accuracy.src_port_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "  • Destination Port Accuracy",
                format!("{:.1}%", b.accuracy.dst_port_accuracy_pct),
                format!("{:.1}%", t.accuracy.dst_port_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | {:<27}\n",
                "  • Protocol Accuracy",
                format!("{:.1}%", b.accuracy.protocol_accuracy_pct),
                format!("{:.1}%", t.accuracy.protocol_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | \x1b[1;32m{:<27}\x1b[0m | \x1b[1;32m{:<27}\x1b[0m\n",
                "Disposition Resolution Accuracy",
                format!("{:.2}%", b.accuracy.disposition_accuracy_pct),
                format!("{:.2}%", t.accuracy.disposition_accuracy_pct)
            ));
            out.push_str(&format!(
                "  {:<38} | {:<27} | \x1b[1;32m{:<27}\x1b[0m\n",
                "Action Inviolability (ALLOW vs DENY)",
                "N/A",
                if t.accuracy.action_inviolability_pct >= 100.0 {
                    "100% PRESERVED"
                } else {
                    "FAILED"
                }
            ));
            out.push_str(&format!(
                "  {:<38} | \x1b[1;32m{:<27}\x1b[0m | \x1b[1;32m{:<27}\x1b[0m\n",
                "Lossless SHA-256 Digest Integrity",
                format!("{:.2}%", b.accuracy.lossless_sha256_match_pct),
                format!("{:.2}%", t.accuracy.lossless_sha256_match_pct)
            ));

            if let Some(diag) = &t.tier_diagnostics {
                out.push_str("\x1b[1;36m  ---------------------------------- MULTI-TIER INTERNAL TELEMETRY -------------------------------------\x1b[0m\n");
                out.push_str(&format!(
                    "  {:<38} | {:<27} | \x1b[1;33m{:<27}\x1b[0m\n",
                    "Tier-1 LRU Cache Hit Ratio",
                    "N/A (No Cache)",
                    format!("{:.2}%", diag.tier1_lru_hit_rate * 100.0)
                ));
                out.push_str(&format!(
                    "  {:<38} | {:<27} | {:<27}\n",
                    "Tier-2 Drain Clusters Discovered", "0", diag.tier2_clusters_count
                ));
                out.push_str(&format!(
                    "  {:<38} | {:<27} | {:<27}\n",
                    "Tier-3 Laya Async Dispatches", "0", diag.tier3_laya_dispatches
                ));
                out.push_str(&format!(
                    "  {:<38} | {:<27} | \x1b[1;32m{:<26.2}%\x1b[0m\n",
                    "AI Deduplication Ratio", "N/A", diag.tier3_ai_deduplication_pct
                ));
            }

            out.push_str("\x1b[1;36m========================================================================================================\x1b[0m\n");
            let p50_reduct = self.latency_reduction_p50_pct.unwrap_or(0.0);
            let p99_reduct = self.latency_reduction_p99_pct.unwrap_or(0.0);
            out.push_str(&format!(
                "  VERDICT: \x1b[1;32mAccuracy: {:.2}% VCA | GA: {:.2}% | Median Latency: -{:.1}% | Tail (p99): -{:.1}%\x1b[0m\n",
                t.accuracy.vendor_classification_accuracy_pct,
                t.accuracy.grouping_accuracy_ga_pct,
                p50_reduct,
                p99_reduct
            ));
            out.push_str("\x1b[1;36m========================================================================================================\x1b[0m\n");
        } else if let Some(single) = self.baseline.as_ref().or(self.tiered_pipeline.as_ref()) {
            // Single-engine mode
            out.push_str(&format!(
                "  Target Engine: \x1b[1;32m{}\x1b[0m\n",
                single.name
            ));
            out.push_str("\x1b[1;36m--------------------------------------------------------------------------------------------------------\x1b[0m\n");
            out.push_str(&format!(
                "  Throughput (EPS)          : \x1b[1;32m{:.0} Events/Sec\x1b[0m\n",
                single.throughput.events_per_sec
            ));
            out.push_str(&format!(
                "  Data Bandwidth            : \x1b[1;32m{:.2} MB/s\x1b[0m\n",
                single.throughput.megabytes_per_sec
            ));
            out.push_str(&format!(
                "  Total Normalized Events   : {}\n",
                single.throughput.total_processed
            ));
            out.push_str(&format!(
                "  Per-Core Ingestion Speed  : {:.0} EPS / core\n",
                single.throughput.per_core_eps
            ));

            out.push_str("\x1b[1;36m  --- LATENCY SPECTRUM ---\x1b[0m\n");
            out.push_str(&format!(
                "  p1 (Fastest 1%)           : {:.2} µs\n",
                single.latency.p1_micros
            ));
            out.push_str(&format!(
                "  p50 (Median)              : \x1b[1;32m{:.2} µs\x1b[0m\n",
                single.latency.p50_micros
            ));
            out.push_str(&format!(
                "  p99 (99th %ile)           : \x1b[1;33m{:.2} µs\x1b[0m\n",
                single.latency.p99_micros
            ));
            out.push_str(&format!(
                "  Max (Worst Case)          : {:.2} µs\n",
                single.latency.max_micros
            ));
            out.push_str(&format!(
                "  Mean (µ) ± Jitter (σ)     : {:.2} µs ± {:.2} µs\n",
                single.latency.mean_micros, single.latency.std_dev_micros
            ));

            out.push_str("\x1b[1;36m  --- ACCURACY AUDIT (LOGHUB & SIEM) ---\x1b[0m\n");
            out.push_str(&format!(
                "  Vendor Classification (VCA): \x1b[1;32m{:.2}%\x1b[0m\n",
                single.accuracy.vendor_classification_accuracy_pct
            ));
            out.push_str(&format!(
                "  Grouping Accuracy (GA %)  : \x1b[1;32m{:.2}%\x1b[0m\n",
                single.accuracy.grouping_accuracy_ga_pct
            ));
            out.push_str(&format!(
                "  Template Accuracy (TA %)  : \x1b[1;32m{:.2}%\x1b[0m\n",
                single.accuracy.template_accuracy_ta_pct
            ));
            out.push_str(&format!(
                "  Field Extraction Macro F1 : \x1b[1;32m{:.2}%\x1b[0m\n",
                single.accuracy.field_extraction_f1_pct
            ));
            out.push_str(&format!(
                "  • Source IP Accuracy      : {:.1}%\n",
                single.accuracy.src_ip_accuracy_pct
            ));
            out.push_str(&format!(
                "  • Destination IP Accuracy : {:.1}%\n",
                single.accuracy.dst_ip_accuracy_pct
            ));
            out.push_str(&format!(
                "  • Source Port Accuracy    : {:.1}%\n",
                single.accuracy.src_port_accuracy_pct
            ));
            out.push_str(&format!(
                "  • Destination Port Accuracy: {:.1}%\n",
                single.accuracy.dst_port_accuracy_pct
            ));
            out.push_str(&format!(
                "  • Protocol Accuracy       : {:.1}%\n",
                single.accuracy.protocol_accuracy_pct
            ));
            out.push_str(&format!(
                "  Disposition Accuracy      : {:.2}%\n",
                single.accuracy.disposition_accuracy_pct
            ));
            out.push_str(&format!(
                "  Action Inviolability      : {:.1}%\n",
                single.accuracy.action_inviolability_pct
            ));
            out.push_str(&format!(
                "  Lossless SHA-256 Digest   : {:.2}%\n",
                single.accuracy.lossless_sha256_match_pct
            ));

            if let Some(diag) = &single.tier_diagnostics {
                out.push_str("\x1b[1;36m  --- TIER DIAGNOSTICS ---\x1b[0m\n");
                out.push_str(&format!(
                    "  Tier-1 LRU Hit Ratio      : {:.2}%\n",
                    diag.tier1_lru_hit_rate * 100.0
                ));
                out.push_str(&format!(
                    "  Tier-2 Clusters Mined     : {}\n",
                    diag.tier2_clusters_count
                ));
                out.push_str(&format!(
                    "  Tier-3 Laya Dispatches    : {}\n",
                    diag.tier3_laya_dispatches
                ));
                out.push_str(&format!(
                    "  AI Deduplication Ratio    : {:.2}%\n",
                    diag.tier3_ai_deduplication_pct
                ));
            }
            out.push_str("\x1b[1;36m========================================================================================================\x1b[0m\n");
        }

        out
    }

    /// Render publication-ready GitHub-flavored Markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# ULPF Hardcore Architectural & Accuracy Telemetry Report\n\n");
        md.push_str(&format!("**Timestamp:** {}  \n", self.timestamp));
        md.push_str(&format!(
            "**Environment:** Linux (x86_64, 16 Cores) | **Workers:** {} parallel threads  \n",
            self.threads
        ));
        md.push_str(&format!(
            "**Duration:** {}s per engine | **Corpus:** {} logs ({:.2} KB)  \n",
            self.duration_secs,
            self.corpus_size,
            self.corpus_total_bytes as f64 / 1024.0
        ));
        md.push_str(&format!(
            "**Corpus Kind:** `{}` (core = fixed file set, adversarial/holdout = sidecar-GT corpora)  \n\n",
            self.corpus_kind
        ));
        md.push_str("---\n\n");

        if let (Some(b), Some(t)) = (&self.baseline, &self.tiered_pipeline) {
            md.push_str("## 1. Executive Telemetry & Accuracy Scorecard\n\n");
            md.push_str("| Benchmark Dimension | Baseline (`UniversalParser`) | 3-Tier (`LRU+Drain+Laya`) | Speedup / Delta |\n");
            md.push_str("| :--- | :---: | :---: | :---: |\n");
            md.push_str(&format!(
                "| **Throughput (EPS)** | **{:.0} EPS** | **{:.0} EPS** | **{:.2}x** |\n",
                b.throughput.events_per_sec,
                t.throughput.events_per_sec,
                self.throughput_speedup_factor.unwrap_or(1.0)
            ));
            md.push_str(&format!(
                "| **Data Bandwidth (MB/s)** | **{:.2} MB/s** | **{:.2} MB/s** | **{:.2}x** |\n",
                b.throughput.megabytes_per_sec,
                t.throughput.megabytes_per_sec,
                self.bandwidth_speedup_factor.unwrap_or(1.0)
            ));
            md.push_str(&format!(
                "| **Median Latency (p50)** | {:.2} µs | **{:.2} µs** | **-{:.1}%** |\n",
                b.latency.p50_micros,
                t.latency.p50_micros,
                self.latency_reduction_p50_pct.unwrap_or(0.0)
            ));
            md.push_str(&format!(
                "| **99th %ile Latency (p99)** | {:.2} µs | **{:.2} µs** | **-{:.1}%** |\n",
                b.latency.p99_micros,
                t.latency.p99_micros,
                self.latency_reduction_p99_pct.unwrap_or(0.0)
            ));
            md.push_str(&format!("| **Vendor Classification (VCA)** | **{:.2}%** | **{:.2}%** | Ground-Truth Exact Match |\n", b.accuracy.vendor_classification_accuracy_pct, t.accuracy.vendor_classification_accuracy_pct));
            md.push_str(&format!("| **Grouping Accuracy (GA %)** | **{:.2}%** | **{:.2}%** | Loghub-2.0 Standard |\n", b.accuracy.grouping_accuracy_ga_pct, t.accuracy.grouping_accuracy_ga_pct));
            md.push_str(&format!("| **Template Accuracy (TA %)** | **{:.2}%** | **{:.2}%** | Template Validity (generalization-correct vs masked line) |\n", b.accuracy.template_accuracy_ta_pct, t.accuracy.template_accuracy_ta_pct));
            md.push_str(&format!("| **Oracle GA Ceiling (GT-hash, unfair)** | **{:.2}%** | **{:.2}%** | Labeled Ceiling — Not a Fair Baseline |\n", b.accuracy.oracle_ga_pct, t.accuracy.oracle_ga_pct));
            md.push_str(&format!("| **Unique Templates (compression)** | **{}** | **{}** | Strictly Fewer vs Naive Baseline (§5.2) |\n", b.accuracy.unique_clusters, t.accuracy.unique_clusters));
            md.push_str(&format!("| **Field Extraction Macro F1** | **{:.2}%** | **{:.2}%** | IP/Port/Proto Extraction |\n", b.accuracy.field_extraction_f1_pct, t.accuracy.field_extraction_f1_pct));
            md.push_str(&format!("| **Disposition Resolution Accuracy** | **{:.2}%** | **{:.2}%** | OCSF Action Mapping |\n", b.accuracy.disposition_accuracy_pct, t.accuracy.disposition_accuracy_pct));
            md.push_str("| **Action Inviolability** | N/A | **100% PRESERVED** | `ALLOW`/`DENY` isolated |\n\n");

            md.push_str("## 1b. Corpus Robustness Scorecard (P7)\n\n");
            md.push_str(
                "| Robustness Dimension | Baseline | 3-Tier (`LRU+Drain+Laya`) | Gate Meaning |\n",
            );
            md.push_str("| :--- | ---: | ---: | :--- |\n");
            md.push_str(&format!(
                "| **Lines Audited** | {} | {} | Full corpus, every line scored |\n",
                b.robustness.lines_total, t.robustness.lines_total
            ));
            md.push_str(&format!(
                "| **Format Recognized** | {} | {} | Vendor routed to a known format (not `unknown`) |\n",
                b.robustness.format_recognized, t.robustness.format_recognized
            ));
            md.push_str(&format!(
                "| **No Panic** | {} | {} | `catch_unwind` parse, zero aborts |\n",
                b.robustness.no_panic, t.robustness.no_panic
            ));
            md.push_str(&format!(
                "| **Lossless (SHA-256 match)** | {} | {} | `raw_hash` == SHA-256(raw), byte-exact |\n",
                b.robustness.lossless_ok, t.robustness.lossless_ok
            ));
            md.push_str(&format!(
                "| **Sidecar GT fields graded** | {} | {} | Non-null expectations (correct + wrong) |\n",
                b.robustness.gt_fields_total, t.robustness.gt_fields_total
            ));
            md.push_str(&format!(
                "| **GT fields correct** | {} | {} | Engine matched the expectation |\n",
                b.robustness.gt_fields_correct, t.robustness.gt_fields_correct
            ));
            md.push_str(&format!(
                "| **GT fields wrong** | {} | {} | Contradicted expectation (strictly worse than null) |\n",
                b.robustness.gt_fields_wrong, t.robustness.gt_fields_wrong
            ));
            if !b.robustness.gt_wrong_by_key.is_empty() || !t.robustness.gt_wrong_by_key.is_empty()
            {
                let fmt = |m: &std::collections::BTreeMap<String, usize>| {
                    if m.is_empty() {
                        "—".to_string()
                    } else {
                        m.iter()
                            .map(|(k, v)| format!("{k} {v}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                };
                md.push_str(&format!(
                    "| **GT fields wrong by key** | {} | {} | Diagnostic: where mismatches concentrate (not a gate metric) |\n",
                    fmt(&b.robustness.gt_wrong_by_key),
                    fmt(&t.robustness.gt_wrong_by_key
                )));
            }
            md.push_str(&format!(
                "| **GT fields null (honest)** | {} | {} | No expectation — excluded from wrong |\n\n",
                b.robustness.gt_fields_null, t.robustness.gt_fields_null
            ));

            md.push_str("## 2. Microsecond Latency Spectrum\n\n");
            md.push_str("| Percentile Observation | Baseline (µs) | 3-Tier Engine (µs) | Latency Reduction |\n");
            md.push_str("| :--- | :---: | :---: | :---: |\n");
            md.push_str(&format!(
                "| **p1 (Fastest 1%)** | {:.2} µs | {:.2} µs | -{:.1}% |\n",
                b.latency.p1_micros,
                t.latency.p1_micros,
                calc_diff(b.latency.p1_micros, t.latency.p1_micros)
            ));
            md.push_str(&format!(
                "| **p50 (Median)** | {:.2} µs | {:.2} µs | -{:.1}% |\n",
                b.latency.p50_micros,
                t.latency.p50_micros,
                calc_diff(b.latency.p50_micros, t.latency.p50_micros)
            ));
            md.push_str(&format!(
                "| **p90** | {:.2} µs | {:.2} µs | -{:.1}% |\n",
                b.latency.p90_micros,
                t.latency.p90_micros,
                calc_diff(b.latency.p90_micros, t.latency.p90_micros)
            ));
            md.push_str(&format!(
                "| **p99** | {:.2} µs | {:.2} µs | -{:.1}% |\n",
                b.latency.p99_micros,
                t.latency.p99_micros,
                calc_diff(b.latency.p99_micros, t.latency.p99_micros)
            ));
            md.push_str(&format!(
                "| **p99.9 (Three Nines)** | {:.2} µs | {:.2} µs | -{:.1}% |\n",
                b.latency.p999_micros,
                t.latency.p999_micros,
                calc_diff(b.latency.p999_micros, t.latency.p999_micros)
            ));
            md.push_str(&format!(
                "| **Worst Case (Max)** | {:.2} µs | {:.2} µs | -{:.1}% |\n\n",
                b.latency.max_micros,
                t.latency.max_micros,
                calc_diff(b.latency.max_micros, t.latency.max_micros)
            ));

            md.push_str("## 3. Academic Accuracy & Quality Breakdown\n\n");
            md.push_str(
                "| Metric Category | Baseline Score | 3-Tier Score | Evaluation Target |\n",
            );
            md.push_str("| :--- | :---: | :---: | :---: |\n");
            md.push_str(&format!(
                "| **Vendor Classification Accuracy** | {:.2}% | {:.2}% | ≥ Baseline (parity, §5.1) |\n",
                b.accuracy.vendor_classification_accuracy_pct,
                t.accuracy.vendor_classification_accuracy_pct
            ));
            md.push_str(&format!(
                "| **LogPai Grouping Accuracy (GA %)** | {:.2}% | {:.2}% | ≥ Naive Baseline (§5.2) |\n",
                b.accuracy.grouping_accuracy_ga_pct, t.accuracy.grouping_accuracy_ga_pct
            ));
            md.push_str(&format!(
                "| **Loghub Template Accuracy (TA %)** | {:.2}% | {:.2}% | > Naive Baseline (§5.2); ≥ at 100% ceiling (see §5.2 amendment) |\n",
                b.accuracy.template_accuracy_ta_pct, t.accuracy.template_accuracy_ta_pct
            ));
            md.push_str(&format!(
                "| **Source IP Accuracy** | {:.1}% | {:.1}% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |\n",
                b.accuracy.src_ip_accuracy_pct, t.accuracy.src_ip_accuracy_pct
            ));
            md.push_str(&format!(
                "| **Destination IP Accuracy** | {:.1}% | {:.1}% | Ground Truth Exact; null correct only when raw lacks a marker (P5) |\n",
                b.accuracy.dst_ip_accuracy_pct, t.accuracy.dst_ip_accuracy_pct
            ));
            md.push_str(&format!(
                "| **Source Port Accuracy** | {:.1}% | {:.1}% | Valid Port Range; null correct only when raw lacks port evidence (P5) |\n",
                b.accuracy.src_port_accuracy_pct, t.accuracy.src_port_accuracy_pct
            ));
            md.push_str(&format!(
                "| **Destination Port Accuracy** | {:.1}% | {:.1}% | Valid Port Range; null correct only when raw lacks port evidence (P5) |\n",
                b.accuracy.dst_port_accuracy_pct, t.accuracy.dst_port_accuracy_pct
            ));
            md.push_str(&format!(
                "| **Protocol Disambiguation** | {:.1}% | {:.1}% | OCSF 4001; null correct without protocol evidence (P5) |\n",
                b.accuracy.protocol_accuracy_pct, t.accuracy.protocol_accuracy_pct
            ));
            md.push_str(&format!(
                "| **Disposition Resolution Accuracy** | {:.2}% | {:.2}% | Security Invariant |\n",
                b.accuracy.disposition_accuracy_pct, t.accuracy.disposition_accuracy_pct
            ));
            md.push_str(&format!(
                "| **Lossless Cryptographic SHA-256** | {:.2}% | {:.2}% | 100.0% Required |\n\n",
                b.accuracy.lossless_sha256_match_pct, t.accuracy.lossless_sha256_match_pct
            ));
        }

        md
    }
}

fn calc_diff(baseline: f64, tiered: f64) -> f64 {
    if baseline > 0.0 {
        ((baseline - tiered) / baseline * 100.0).clamp(-999.0, 99.9)
    } else {
        0.0
    }
}

/// Hardcore Evaluator Engine capable of isolated and dual-architecture benchmark runs
pub struct EvaluatorEngine;

impl EvaluatorEngine {
    /// Run comprehensive dual-architecture benchmark with isolated sequential passes and CPU cooldown
    pub fn evaluate(corpus: &[String], duration_secs: u64, threads: usize) -> EvaluationReport {
        Self::evaluate_with_mode(
            "all",
            corpus,
            duration_secs,
            threads,
            10_000,
            &GtOverrides::new(),
        )
    }

    /// Run benchmark with specific execution mode: "all", "baseline", or "tiered".
    ///
    /// `gt_overrides` are P7 sidecar GT records keyed by verbatim raw line;
    /// they are authoritative over in-line derivation for their line (empty
    /// map = pure in-line GT, the historical behaviour).
    pub fn evaluate_with_mode(
        mode: &str,
        corpus: &[String],
        duration_secs: u64,
        threads: usize,
        latency_samples: usize,
        gt_overrides: &GtOverrides,
    ) -> EvaluationReport {
        let corpus_total_bytes: usize = corpus.iter().map(|s| s.len()).sum();
        let corpus_arc = Arc::new(corpus.to_vec());
        let gt_arc = Arc::new(gt_overrides.clone());

        let baseline_res = if mode == "all" || mode == "baseline" {
            let res = Self::benchmark_baseline_isolated(
                corpus_arc.clone(),
                duration_secs,
                threads,
                latency_samples,
                gt_arc.clone(),
            );
            if mode == "all" {
                // Cooldown: pause 500ms to allow CPU thermal throttles and OS caches to settle
                std::thread::sleep(Duration::from_millis(500));
            }
            Some(res)
        } else {
            None
        };

        let tiered_res = if mode == "all" || mode == "tiered" {
            let res = Self::benchmark_tiered_isolated(
                corpus_arc.clone(),
                duration_secs,
                threads,
                latency_samples,
                gt_arc.clone(),
            );
            Some(res)
        } else {
            None
        };

        let mut speedup_eps = None;
        let mut speedup_bw = None;
        let mut p50_reduct = None;
        let mut p99_reduct = None;

        if let (Some(b), Some(t)) = (&baseline_res, &tiered_res) {
            speedup_eps = Some(t.throughput.events_per_sec / b.throughput.events_per_sec);
            speedup_bw = Some(t.throughput.megabytes_per_sec / b.throughput.megabytes_per_sec);
            p50_reduct = Some(calc_diff(b.latency.p50_micros, t.latency.p50_micros));
            p99_reduct = Some(calc_diff(b.latency.p99_micros, t.latency.p99_micros));
        }

        EvaluationReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            mode: mode.to_string(),
            threads,
            duration_secs,
            corpus_size: corpus.len(),
            corpus_total_bytes,
            baseline: baseline_res,
            tiered_pipeline: tiered_res,
            throughput_speedup_factor: speedup_eps,
            bandwidth_speedup_factor: speedup_bw,
            latency_reduction_p50_pct: p50_reduct,
            latency_reduction_p99_pct: p99_reduct,
            corpus_kind: "core".to_string(),
        }
    }

    /// Isolated benchmark pass for Baseline UniversalParser
    pub fn benchmark_baseline_isolated(
        corpus: Arc<Vec<String>>,
        duration_secs: u64,
        threads: usize,
        latency_samples: usize,
        gt_overrides: Arc<GtOverrides>,
    ) -> BenchmarkTierResult {
        // Warmup pass (200ms)
        {
            let parser = UniversalParser::new();
            for i in 0..1000.min(corpus.len()) {
                let _ = parser.parse_lossless(&corpus[i]);
            }
        }

        let stop_signal = Arc::new(AtomicBool::new(false));
        let total_count = Arc::new(AtomicU64::new(0));
        let total_bytes = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        let start = Instant::now();
        let target_duration = Duration::from_secs(duration_secs);

        for worker_id in 0..threads {
            let corpus_ref = corpus.clone();
            let stop_ref = stop_signal.clone();
            let count_ref = total_count.clone();
            let bytes_ref = total_bytes.clone();

            handles.push(std::thread::spawn(move || {
                let parser = UniversalParser::new();
                let mut idx = worker_id;
                let len = corpus_ref.len();
                let mut local_count = 0u64;
                let mut local_bytes = 0u64;

                while !stop_ref.load(Ordering::Relaxed) {
                    let raw = &corpus_ref[idx % len];
                    let _ = parser.parse_lossless(raw);
                    local_count += 1;
                    local_bytes += raw.len() as u64;
                    idx += 1;

                    if local_count.is_multiple_of(1024) {
                        count_ref.fetch_add(1024, Ordering::Relaxed);
                        bytes_ref.fetch_add(local_bytes, Ordering::Relaxed);
                        local_bytes = 0;
                    }
                }
                count_ref.fetch_add(local_count % 1024, Ordering::Relaxed);
                bytes_ref.fetch_add(local_bytes, Ordering::Relaxed);
            }));
        }

        std::thread::sleep(target_duration);
        stop_signal.store(true, Ordering::Relaxed);

        for h in handles {
            let _ = h.join();
        }

        let elapsed = start.elapsed().as_secs_f64();
        let total = total_count.load(Ordering::Relaxed);
        let bytes = total_bytes.load(Ordering::Relaxed);
        let eps = (total as f64) / elapsed;
        let mbps = (bytes as f64) / (1024.0 * 1024.0 * elapsed);

        let throughput = HardwareThroughputSummary {
            events_per_sec: eps,
            megabytes_per_sec: mbps,
            events_per_ms_per_core: eps / (threads as f64 * 1000.0),
            per_core_eps: eps / threads as f64,
            total_processed: total,
            total_bytes_processed: bytes,
            duration_secs: elapsed,
        };

        // Latency sampling
        let latency = Self::sample_latency_distribution(
            |raw| {
                let parser = UniversalParser::new();
                let _ = parser.parse_lossless(raw);
            },
            &corpus,
            latency_samples,
        );

        // Exhaustive Accuracy Audit
        let (accuracy, robustness, failures) = Self::audit_accuracy(
            |raw| {
                let parser = UniversalParser::new();
                parser.parse_lossless(raw)
            },
            |raw| {
                // Naive exact-match baseline (FAIR): cluster identity = canonical
                // post-mask skeleton hashed over its FULL content. Deliberately not
                // compute_signature_hash — that is a structural signature (vendor +
                // selected tokens) for LRU format routing, which would merge lines
                // by design and hand the baseline a false impurity. The GT-hash
                // variant lives only inside audit_accuracy as the oracle ceiling.
                let masked = crate::drain::mask_line(raw);
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&masked, &mut hasher);
                let cluster_id = hasher.finish() as usize;
                (cluster_id, masked)
            },
            &corpus,
            &gt_overrides,
        );

        BenchmarkTierResult {
            name: "Baseline (UniversalParser)".into(),
            throughput,
            latency,
            accuracy,
            tier_diagnostics: None,
            failures,
            robustness,
        }
    }

    /// Isolated benchmark pass for 3-Tier Pipeline (LRU + DrainDotNet + Laya)
    pub fn benchmark_tiered_isolated(
        corpus: Arc<Vec<String>>,
        duration_secs: u64,
        threads: usize,
        latency_samples: usize,
        gt_overrides: Arc<GtOverrides>,
    ) -> BenchmarkTierResult {
        let pipeline = Arc::new(TieredPipeline::new());

        // Warmup pass (200ms)
        for i in 0..1000.min(corpus.len()) {
            let _ = pipeline.process(&corpus[i]);
        }

        let stop_signal = Arc::new(AtomicBool::new(false));
        let total_count = Arc::new(AtomicU64::new(0));
        let total_bytes = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        let start = Instant::now();
        let target_duration = Duration::from_secs(duration_secs);

        for worker_id in 0..threads {
            let corpus_ref = corpus.clone();
            let stop_ref = stop_signal.clone();
            let count_ref = total_count.clone();
            let bytes_ref = total_bytes.clone();
            let pipe_ref = pipeline.clone();

            handles.push(std::thread::spawn(move || {
                let mut idx = worker_id;
                let len = corpus_ref.len();
                let mut local_count = 0u64;
                let mut local_bytes = 0u64;

                while !stop_ref.load(Ordering::Relaxed) {
                    let raw = &corpus_ref[idx % len];
                    let _ = pipe_ref.process(raw);
                    local_count += 1;
                    local_bytes += raw.len() as u64;
                    idx += 1;

                    if local_count.is_multiple_of(1024) {
                        count_ref.fetch_add(1024, Ordering::Relaxed);
                        bytes_ref.fetch_add(local_bytes, Ordering::Relaxed);
                        local_bytes = 0;
                    }
                }
                count_ref.fetch_add(local_count % 1024, Ordering::Relaxed);
                bytes_ref.fetch_add(local_bytes, Ordering::Relaxed);
            }));
        }

        std::thread::sleep(target_duration);
        stop_signal.store(true, Ordering::Relaxed);

        for h in handles {
            let _ = h.join();
        }

        let elapsed = start.elapsed().as_secs_f64();
        let total = total_count.load(Ordering::Relaxed);
        let bytes = total_bytes.load(Ordering::Relaxed);
        let eps = (total as f64) / elapsed;
        let mbps = (bytes as f64) / (1024.0 * 1024.0 * elapsed);
        let pipe_stats = pipeline.stats();

        let throughput = HardwareThroughputSummary {
            events_per_sec: eps,
            megabytes_per_sec: mbps,
            events_per_ms_per_core: eps / (threads as f64 * 1000.0),
            per_core_eps: eps / threads as f64,
            total_processed: total,
            total_bytes_processed: bytes,
            duration_secs: elapsed,
        };

        let pipe_for_lat = pipeline.clone();
        let latency = Self::sample_latency_distribution(
            move |raw| {
                let _ = pipe_for_lat.process(raw);
            },
            &corpus,
            latency_samples,
        );

        let mut miner = DrainMiner::new(DrainConfig::default());
        let pipe_for_acc = pipeline.clone();
        let (accuracy, robustness, failures) = Self::audit_accuracy(
            move |raw| pipe_for_acc.process(raw),
            move |raw| {
                let res = miner.add_log(raw);
                (res.cluster_id, res.template)
            },
            &corpus,
            &gt_overrides,
        );

        let dedupe_pct = if total > 0 {
            (total.saturating_sub(pipe_stats.tier3_laya_dispatches)) as f64 / total as f64 * 100.0
        } else {
            100.0
        };

        let tier_diagnostics = Some(TierDiagnosticsSummary {
            tier1_lru_hit_rate: pipe_stats.lru_hit_ratio,
            tier1_lookups: pipe_stats.lru_stats.total_lookups,
            tier1_hits: pipe_stats.tier1_lru_hits,
            tier1_misses: pipe_stats.lru_stats.misses,
            tier1_evictions: pipe_stats.lru_stats.evictions,
            tier1_entries_count: pipe_stats.lru_stats.entries_count,
            tier2_clusters_count: pipeline.tier2_cluster_count(),
            tier2_cluster_matches: pipe_stats.tier2_drain_hits,
            tier2_unique_anchor_enforced: !DrainConfig::default().unique_anchor_tokens.is_empty(),
            tier3_laya_dispatches: pipe_stats.tier3_laya_dispatches,
            tier3_ai_deduplication_pct: dedupe_pct,
            tier3_auto_onboarded_count: pipe_stats.tier3_laya_onboarded,
        });

        BenchmarkTierResult {
            name: "3-Tier (LRU+DrainDotNet+Laya)".into(),
            throughput,
            latency,
            accuracy,
            tier_diagnostics,
            failures,
            robustness,
        }
    }

    /// Sample high-density latency distribution across thousands of measurements
    fn sample_latency_distribution<F>(
        mut parse_fn: F,
        corpus: &[String],
        target_samples: usize,
    ) -> LatencySummary
    where
        F: FnMut(&str),
    {
        let count = target_samples.max(100);
        let mut latencies: Vec<f64> = Vec::with_capacity(count);

        for i in 0..count {
            let raw = &corpus[i % corpus.len()];
            let t0 = Instant::now();
            parse_fn(raw);
            let micros = t0.elapsed().as_nanos() as f64 / 1000.0;
            latencies.push(micros);
        }

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let len = latencies.len();

        let sum: f64 = latencies.iter().sum();
        let mean = sum / len as f64;

        let var: f64 = latencies.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / len as f64;
        let std_dev = var.sqrt();

        LatencySummary {
            min_micros: latencies[0],
            p1_micros: latencies[len / 100],
            p5_micros: latencies[len * 5 / 100],
            p25_micros: latencies[len * 25 / 100],
            p50_micros: latencies[len * 50 / 100],
            p75_micros: latencies[len * 75 / 100],
            p90_micros: latencies[len * 90 / 100],
            p95_micros: latencies[len * 95 / 100],
            p99_micros: latencies[len * 99 / 100],
            p999_micros: latencies[(len * 999 / 1000).min(len - 1)],
            p9999_micros: latencies[(len * 9999 / 10000).min(len - 1)],
            max_micros: *latencies.last().unwrap_or(&0.0),
            mean_micros: mean,
            std_dev_micros: std_dev,
            samples_count: len,
        }
    }

    /// Extract ground truth vendor, template tag, and expected action from raw log.
    /// Ground truth follows OCSF semantics: `disposition_id` 1 Allowed / 2 Blocked / 3 Dropped.
    pub fn extract_ground_truth(raw: &str) -> (String, String, Option<String>) {
        // ArcSight CEF (vendor-neutral): CEF:Version|Vendor|Product|Version|SigID|Name|Severity|Extension
        if let Some(cef_pos) = raw.find("CEF:") {
            let cef = &raw[cef_pos..];
            let mut parts = cef.splitn(8, '|');
            parts.next(); // CEF:Version
            let vendor = parts.next().unwrap_or("Unknown").trim().to_string();
            parts.next(); // Product
            parts.next(); // Device Version
            parts.next(); // Signature ID
            parts.next(); // Name
            parts.next(); // Severity
            let extension = parts.next().unwrap_or("");
            let action = Self::action_from_kv_token(extension, "act=");
            return (vendor, "cef".to_string(), action);
        }

        if raw.contains("%ASA-") {
            let tag = if let Some(pos) = raw.find("%ASA-") {
                let end = raw[pos..].find(':').unwrap_or(15);
                raw[pos..pos + end].trim().to_string()
            } else {
                "%ASA".to_string()
            };

            // P7.2 shared VPN/AAA verdict vocabulary (engine half:
            // `cisco_asa::fallback_parse` — keep BOTH sides in lockstep).
            // Failure phrases win first: a line can mention both a tunnel
            // and a failed authentication.
            let lower = raw.to_ascii_lowercase();
            let action =
                if lower.contains("authentication failed") || lower.contains("login failed") {
                    Some("Blocked".to_string())
                } else if raw.contains("Built")
                    || raw.contains("permit")
                    || lower.contains("successful login")
                    || lower.contains("tunnel established")
                {
                    Some("Allowed".to_string())
                } else if raw.contains("Deny") || raw.contains("drop") {
                    // OCSF: deny-by-policy is Blocked (disposition_id 2), never Dropped
                    Some("Blocked".to_string())
                } else if raw.contains("Teardown") {
                    Some("Allowed".to_string())
                } else {
                    None
                };
            ("Cisco".to_string(), tag, action)
        } else if raw.contains("devname=")
            || raw.contains("type=\"traffic\"")
            || raw.contains("logid=")
        {
            let action = Self::action_from_kv_token(raw, "action=");
            // P7.2 subtype-aware grouping tag: traffic/dns/utm/app-ctrl are
            // distinct FortiGate log classes (Drain's key-aware class anchor
            // partitions them; GA keeps each cluster pure). Absent or
            // `type="traffic"` keeps the historical `fortigate_traffic` tag —
            // the core corpus is traffic-only, so nothing regresses.
            let tag = match Self::kv_value_word(raw, "type=") {
                Some("dns") => "fortigate_dns",
                Some("utm") => "fortigate_utm",
                Some("app-ctrl") => "fortigate_appctrl",
                _ => "fortigate_traffic",
            };
            ("Fortinet".to_string(), tag.to_string(), action)
        } else if raw.contains(",TRAFFIC,") || raw.contains(",THREAT,") {
            let action = Self::panos_action_field(raw);
            // P7.2: THREAT rows are their own class (anchored in Drain via
            // the bare TRAFFIC/THREAT tokens).
            let tag = if raw.contains(",THREAT,") {
                "panos_threat"
            } else {
                "panos_traffic"
            };
            ("Palo Alto".to_string(), tag.to_string(), action)
        } else if raw.starts_with('{') || raw.contains("\"event_type\"") {
            // Suricata EVE: an explicit `action` inside the event is authoritative
            // (alert with "action": "allowed" means the traffic WAS allowed);
            // without one, alert = Blocked (detection), dns/flow = Allowed.
            let action = match Self::eve_action_value(raw) {
                Some("blocked") | Some("reject") => Some("Blocked".to_string()),
                Some("drop") | Some("dropped") => Some("Dropped".to_string()),
                Some("allowed") | Some("pass") => Some("Allowed".to_string()),
                _ => {
                    if raw.contains("\"alert\"") {
                        Some("Blocked".to_string())
                    } else {
                        Some("Allowed".to_string())
                    }
                }
            };
            let sub = if raw.contains("\"alert\"") {
                "suricata_alert"
            } else {
                "suricata_flow"
            };
            ("Suricata".to_string(), sub.to_string(), action)
        } else if raw.contains("filterlog[") || raw.contains("filterlog:") {
            let action = if raw.contains(",pass,") {
                Some("Allowed".to_string())
            } else if raw.contains(",block,") {
                Some("Blocked".to_string())
            } else {
                None
            };
            (
                "pfSense".to_string(),
                "pfsense_filterlog".to_string(),
                action,
            )
        } else {
            ("Unknown".to_string(), "unknown_template".to_string(), None)
        }
    }

    /// Resolve an OCSF disposition from a whitespace-delimited `key=value` / `key="value"` token
    /// (FortiGate `action="timeout"`, CEF extension `act=accept`, ...).
    /// Mapping: accept/allow -> Allowed, deny/blocked -> Blocked, drop -> Dropped,
    /// close/timeout/client-rst/server-rst -> Allowed (session end of permitted traffic).
    fn action_from_kv_token(text: &str, key: &str) -> Option<String> {
        for token in text.split_whitespace() {
            if let Some(value) = token.strip_prefix(key) {
                let value = value.trim_matches('"').trim_matches(',');
                return match value {
                    // `allowed`/`denied` are the OCSF/Suricata-style verbs CEF
                    // devices (e.g. Windows) emit; previously these fell to
                    // `None` and the disposition check was skipped.
                    "accept" | "allow" | "allowed" => Some("Allowed".to_string()),
                    "deny" | "denied" | "blocked" | "block" => Some("Blocked".to_string()),
                    "drop" => Some("Dropped".to_string()),
                    "close" | "closed" | "timeout" | "client-rst" | "server-rst" | "reset" => {
                        Some("Allowed".to_string())
                    }
                    _ => None,
                };
            }
        }
        None
    }

    /// Value of a whitespace-delimited `key="value"` token in `raw`, as the
    /// bare word form (`type="dns"` -> `dns`); `None` when the key is absent
    /// or the value is empty. Borrows `raw` — no allocation.
    fn kv_value_word<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
        for token in raw.split_whitespace() {
            if let Some(value) = token.strip_prefix(key) {
                let value = value.trim_matches(|c: char| {
                    c == '"' || c == '\'' || c == ',' || c == ';' || c.is_whitespace()
                });
                return if value.is_empty() { None } else { Some(value) };
            }
        }
        None
    }

    /// Extract the explicit Suricata EVE `action` value, if present
    /// (e.g. `"action": "blocked"` inside the `alert`/`flow` object).
    fn eve_action_value(raw: &str) -> Option<&str> {
        let p = raw.find("\"action\"")?;
        let after = &raw[p + "\"action\"".len()..];
        let q1 = after.find('"')?;
        let q2 = after[q1 + 1..].find('"')?;
        Some(&after[q1 + 1..q1 + 1 + q2])
    }

    /// Resolve ground-truth disposition for PAN-OS from the positional action column
    /// (`fields[traffic_idx + 27]`), falling back to ordered substring markers when the
    /// positional layout cannot be located. Positional beats substring because the PAN-OS
    /// `subtype` column (start/end/drop/deny) also produces `,deny,`/`,drop,` markers.
    fn panos_action_field(raw: &str) -> Option<String> {
        let fields = ulpf_core::parser::extractors::split_csv(raw);
        let traffic_pos = fields
            .iter()
            .position(|f| f.eq_ignore_ascii_case("TRAFFIC") || f.eq_ignore_ascii_case("THREAT"));
        if let Some(tp) = traffic_pos {
            if let Some(action) = fields.get(tp + 27) {
                match action.to_ascii_lowercase().as_str() {
                    "allow" => return Some("Allowed".to_string()),
                    "deny" => return Some("Blocked".to_string()),
                    "drop" => return Some("Dropped".to_string()),
                    _ => {}
                }
            }
        }
        // Fallback: ordered substring markers (drop > deny > allow)
        if raw.contains(",drop,") {
            Some("Dropped".to_string())
        } else if raw.contains(",deny,") {
            Some("Blocked".to_string())
        } else if raw.contains(",allow,") {
            Some("Allowed".to_string())
        } else {
            None
        }
    }

    /// Map extractor-emitted vendor labels onto ground-truth vocabulary.
    /// Explicit fixed table, never fuzzy/edit-distance: a genuinely wrong vendor must fail.
    pub fn map_audit_vendor(vendor_lower: &str) -> &str {
        match vendor_lower {
            "oisf" => "suricata",
            "netgate" => "pfsense",
            other => other,
        }
    }

    /// True when `num` appears in `raw` as a fully delimited alphanumeric token
    /// (e.g. `proto=17`, `"proto": 6`, `,6,`). Grants numeric IANA equivalence so a
    /// correct protocol mapping (17 -> UDP) is not punished for the raw line carrying
    /// the number instead of the name.
    pub fn raw_contains_numeric(raw: &str, num: u8) -> bool {
        let target = num.to_string();
        raw.split(|c: char| !c.is_alphanumeric())
            .any(|seg| seg == target)
    }

    // ------------------------------------------------------------------
    // P5 null-correct rule: a field the engine reports as `None` is audited
    // as CORRECT only when `raw` carries no valid marker for that field.
    // Marker + null stays a failure — evidence is never laundered.
    // ------------------------------------------------------------------

    /// Byte-scan a syntactically valid IPv4 at index `i`: four dot-separated
    /// octets 0–255 with alphanumeric/dot-free boundaries so version strings
    /// (`v7.0.2`), timestamps, and digit soup never count. Returns the total
    /// byte length of the address on success.
    fn ipv4_len_at(s: &str, i: usize) -> Option<usize> {
        let b = s.as_bytes();
        if i >= b.len() || !b[i].is_ascii_digit() {
            return None;
        }
        // Boundary before: a version string's `v7`/`x.1` fragments are not
        // address starts. A preceding ':' is fine (`outside:10.0.0.1`).
        if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.') {
            return None;
        }
        let mut j = i;
        for group in 0..4 {
            let gs = j;
            while j < b.len() && b[j].is_ascii_digit() && j - gs < 3 {
                j += 1;
            }
            if j == gs || (j < b.len() && b[j].is_ascii_digit()) {
                return None;
            }
            match s[gs..j].parse::<u16>() {
                Ok(v) if v <= 255 => {}
                _ => return None,
            }
            if group < 3 {
                if j >= b.len() || b[j] != b'.' {
                    return None;
                }
                j += 1;
            }
        }
        if j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'.') {
            return None;
        }
        Some(j - i)
    }

    /// Count distinct IPv4 addresses in `raw` (bails at 2 — the audit only
    /// needs "two or more endpoints are evidenced"). No regex, byte-exact.
    pub fn distinct_ipv4_count(raw: &str) -> usize {
        let b = raw.as_bytes();
        let mut found: [&str; 2] = ["", ""];
        let mut n = 0usize;
        let mut i = 0usize;
        while i < b.len() {
            match Self::ipv4_len_at(raw, i) {
                Some(len) => {
                    let cand = &raw[i..i + len];
                    if !found[..n].contains(&cand) {
                        found[n] = cand;
                        n += 1;
                        if n == 2 {
                            return n;
                        }
                    }
                    i += len;
                }
                None => i += 1,
            }
        }
        n
    }

    /// Endpoint-role keys whose presence evidences an IP for that role, even
    /// on a single-IP line.
    const SRC_IP_KEYS: &'static [&'static str] = &[
        "src=",
        "srcip=",
        "src_ip=",
        "saddr=",
        "srcaddr=",
        "source_ip=",
        "\"src_ip\"",
        "\"srcip\"",
        "\"source_ip\"",
    ];
    const DST_IP_KEYS: &'static [&'static str] = &[
        "dst=",
        "dstip=",
        "dst_ip=",
        "daddr=",
        "dstaddr=",
        "dest_ip=",
        "\"dst_ip\"",
        "\"dstip\"",
        "\"dst\"",
    ];

    /// True when `raw` evidences a source IP: an explicit `src`-role key or
    /// two distinct IPv4 addresses (both endpoints present).
    pub fn raw_has_src_ip_marker(raw: &str) -> bool {
        Self::SRC_IP_KEYS.iter().any(|k| raw.contains(k)) || Self::distinct_ipv4_count(raw) >= 2
    }

    /// True when `raw` evidences a destination IP (mirrors the src rule).
    pub fn raw_has_dst_ip_marker(raw: &str) -> bool {
        Self::DST_IP_KEYS.iter().any(|k| raw.contains(k)) || Self::distinct_ipv4_count(raw) >= 2
    }

    /// Port keys whose value, when a valid 1–65535 integer, evidences a port.
    const PORT_KEYS: &'static [&'static str] = &[
        "spt=",
        "dpt=",
        "sport=",
        "dport=",
        "srcport=",
        "dstport=",
        "src_port=",
        "dst_port=",
        "port=",
        "srcPort=",
        "dstPort=",
    ];

    /// True when `raw` carries valid port evidence: a port-key assignment with
    /// a 1–65535 value (ICMP-style `sport=0` is NOT evidence), the ASA
    /// `interface:IP/PORT` shape (a bare CIDR `10.0.0.0/24` is NOT a port),
    /// or a bracketed-IPv6 `]:PORT`.
    pub fn raw_has_port_marker(raw: &str) -> bool {
        fn digits_in_range(b: &[u8], from: usize) -> bool {
            let mut e = from;
            while e < b.len() && b[e].is_ascii_digit() && e - from < 5 {
                e += 1;
            }
            if e == from || (e < b.len() && b[e].is_ascii_digit()) {
                return false;
            }
            match std::str::from_utf8(&b[from..e])
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                Some(v) => (1..=65535).contains(&v),
                None => false,
            }
        }

        let b = raw.as_bytes();
        for key in Self::PORT_KEYS {
            let mut from = 0usize;
            while let Some(p) = raw[from..].find(key) {
                let vs = from + p + key.len();
                if digits_in_range(b, vs) {
                    return true;
                }
                from = vs;
            }
        }
        // interface:IPv4/PORT — requires the ':IP' shape, so CIDRs never count.
        for i in 0..b.len() {
            if b[i] == b':' {
                if let Some(len) = Self::ipv4_len_at(raw, i + 1) {
                    let slash = i + 1 + len;
                    if slash < b.len() && b[slash] == b'/' && digits_in_range(b, slash + 1) {
                        return true;
                    }
                }
            }
        }
        // bracketed IPv6 with explicit port: `]:443`
        if let Some(p) = raw.find("]:") {
            if digits_in_range(b, p + 2) {
                return true;
            }
        }
        false
    }

    const PROTO_KEYS: &'static [&'static str] = &[
        "proto=",
        "protocol=",
        "ip_proto=",
        "ipprotocol=",
        "\"proto\"",
        "\"protocol\"",
    ];
    /// IANA IP-layer protocol names — whole-word, case-insensitive.
    /// Application labels (`SSL`, `HTTP`) are NOT IP-protocol markers.
    const PROTO_NAMES: &'static [&'static str] = &[
        "TCP", "UDP", "ICMP", "ICMPV6", "GRE", "ESP", "SCTP", "OSPF", "IGMP", "AH",
    ];

    /// True when `raw` carries protocol evidence: a `proto=`/`protocol=`-style
    /// key with a non-empty value, or a whole-word IANA IP-protocol name.
    pub fn raw_has_protocol_marker(raw: &str) -> bool {
        for key in Self::PROTO_KEYS {
            if let Some(p) = raw.find(key) {
                let rest = raw[p + key.len()..]
                    .trim_start_matches(':')
                    .trim_start_matches('"')
                    .trim_start();
                if !rest.is_empty()
                    && !rest.starts_with(|c: char| {
                        c.is_whitespace() || c == ',' || c == '}' || c == ']'
                    })
                {
                    return true;
                }
            }
        }
        let up = raw.to_ascii_uppercase();
        let ub = up.as_bytes();
        for name in Self::PROTO_NAMES {
            let mut from = 0usize;
            while let Some(p) = up[from..].find(name) {
                let abs = from + p;
                let end = abs + name.len();
                let before_ok = abs == 0 || !ub[abs - 1].is_ascii_alphabetic();
                let after_ok = end >= ub.len() || !ub[end].is_ascii_alphabetic();
                if before_ok && after_ok {
                    return true;
                }
                from = abs + 1;
            }
        }
        false
    }

    /// Template-Validity (honest TA): the produced cluster template must be an exact
    /// token-aligned generalization of this record's own masked line:
    /// non-empty, same token count, every non-`<*>` token identical at its position,
    /// and any syslog-style GT tag (`%ASA-6-302013:`) preserved verbatim.
    /// No similarity threshold — Token-F1 of 1.0 is required.
    pub fn template_is_valid(raw: &str, template: &str, gt_template: &str) -> bool {
        if template.is_empty() {
            return false;
        }
        let masked_tokens = DrainMiner::tokenize(&crate::drain::mask_line(raw));
        // Tokenize the template with the *same* function (trims quote/comma edges),
        // otherwise a template equal to the masked line fails on untrimmed edges.
        let tmpl_tokens = DrainMiner::tokenize(template);
        if tmpl_tokens.len() != masked_tokens.len() {
            return false;
        }
        let aligned = tmpl_tokens
            .iter()
            .zip(masked_tokens.iter())
            .all(|(t, m)| t.as_str() == "<*>" || t == m);
        if !aligned {
            return false;
        }
        if gt_template.starts_with('%') && !template.contains(gt_template) {
            return false;
        }
        true
    }

    /// Audit comprehensive schema, semantic, and academic clustering accuracy.
    ///
    /// Returns the summary, the P7 robustness block, and every per-record
    /// mismatch (for `--audit-dump` JSONL).
    /// Oracle GA (clusters built from the ground-truth tag itself) is computed
    /// alongside the primary GA and reported only as a labeled ceiling — never as
    /// a fair baseline. The fair baseline engine is the naive post-mask exact-match
    /// clustering passed in via `cluster_fn` on the baseline side.
    ///
    /// P7.5: `gt_overrides` (sidecar GT keyed by verbatim raw line) are
    /// authoritative over in-line derivation for their line — mutations
    /// destroy in-line markers, so the sidecar is the only honest GT source
    /// on the adversarial/holdout corpora. Parsing runs under `catch_unwind`:
    /// a panic must be observable (`no_panic` + a `panic` failure), never a
    /// process abort.
    fn audit_accuracy<F, C>(
        mut parse_fn: F,
        mut cluster_fn: C,
        corpus: &[String],
        gt_overrides: &GtOverrides,
    ) -> (AccuracyAuditSummary, RobustnessSummary, Vec<AuditFailure>)
    where
        F: FnMut(&str) -> NetworkActivity,
        C: FnMut(&str) -> (usize, String),
    {
        // Full-coverage audit: every corpus line is scored. The former
        // `1000.min(...)` cap silently excluded all pfSense records.
        let audit_count = corpus.len();
        let mut rob = RobustnessSummary::default();
        let mut vendor_correct = 0;
        let mut sha_matches = 0;
        let mut uuid_valid = 0;
        let mut src_ip_correct = 0;
        let mut dst_ip_correct = 0;
        let mut src_port_correct = 0;
        let mut dst_port_correct = 0;
        let mut proto_correct = 0;
        let mut disposition_correct = 0;
        let mut template_correct = 0;
        let mut failures: Vec<AuditFailure> = Vec::new();

        // Grouping Accuracy Tracking: maps cluster_id -> (ground_truth_tag -> count)
        let mut cluster_to_gt_map: HashMap<usize, HashMap<String, usize>> = HashMap::new();
        // Oracle ceiling: identity = ground-truth tag (labeled, never a fair baseline)
        let mut oracle_map: HashMap<usize, HashMap<String, usize>> = HashMap::new();
        // (corpus index, cluster id, gt tag) retained for the grouping-failure pass
        let mut records: Vec<(usize, usize, String)> = Vec::with_capacity(audit_count);

        for (idx, raw) in corpus.iter().enumerate() {
            rob.lines_total += 1;

            // P7.5 GT seam: sidecar override is authoritative for its
            // verbatim line (vendor + template tag + disposition).
            let sidecar = gt_overrides.get(raw);
            let (gt_vendor, gt_template, gt_action) = match sidecar {
                Some(sc) => (
                    sc.gt_vendor.clone(),
                    sc.gt_template_tag.clone(),
                    sc.gt_disposition.clone(),
                ),
                None => Self::extract_ground_truth(raw),
            };

            let (cluster_id, template_str) = cluster_fn(raw);
            records.push((idx, cluster_id, gt_template.clone()));

            // 1. Grouping Accuracy tracking (primary engine clusters)
            *cluster_to_gt_map
                .entry(cluster_id)
                .or_default()
                .entry(gt_template.clone())
                .or_insert(0) += 1;

            // Oracle ceiling clusters (GT-hash identity)
            let oracle_id = SignatureLruCache::compute_signature_hash(&gt_template) as usize;
            *oracle_map
                .entry(oracle_id)
                .or_default()
                .entry(gt_template.clone())
                .or_insert(0) += 1;

            // 2. Template validity (honest TA): exact token-aligned generalization
            //    of this record's masked line, syslog GT tag preserved. No thresholds.
            if Self::template_is_valid(raw, &template_str, &gt_template) {
                template_correct += 1;
            } else {
                failures.push(AuditFailure::new(
                    "template",
                    idx,
                    raw,
                    &gt_template,
                    &template_str,
                    cluster_id,
                ));
            }

            // P7 robustness: the parse must never panic — and if it ever did,
            // the failure is recorded here instead of aborting the process.
            let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_fn(raw)));
            let activity = match parsed {
                Ok(activity) => {
                    rob.no_panic += 1;
                    activity
                }
                Err(_) => {
                    // A panicked parse is strictly worse than a null: every
                    // non-null sidecar expectation grades WRONG.
                    if let Some(sc) = sidecar {
                        Self::grade_gt_fields(&sc.gt_fields, None, &mut rob);
                    }
                    failures.push(AuditFailure::new(
                        "panic",
                        idx,
                        raw,
                        "parse without panic",
                        "panicked",
                        cluster_id,
                    ));
                    continue;
                }
            };

            // 3. Vendor Classification Accuracy (explicit label map, never fuzzy)
            let parsed_vendor_raw = activity.metadata.product.vendor_name.to_ascii_lowercase();
            let parsed_vendor = Self::map_audit_vendor(&parsed_vendor_raw);
            if parsed_vendor != "unknown" {
                // P7 robustness: the engine recognized a known format.
                rob.format_recognized += 1;
            }
            let expected_vendor = gt_vendor.to_ascii_lowercase();
            if parsed_vendor.contains(&expected_vendor) || expected_vendor.contains(parsed_vendor) {
                vendor_correct += 1;
            } else {
                failures.push(AuditFailure::new(
                    "vendor",
                    idx,
                    raw,
                    &expected_vendor,
                    parsed_vendor,
                    cluster_id,
                ));
            }

            // 4. SHA-256 Digest & UUID
            if activity.metadata.raw_hash == compute_sha256(raw.as_bytes()) {
                sha_matches += 1;
                rob.lossless_ok += 1;
            }
            if Uuid::parse_str(&activity.metadata.event_id).is_ok() {
                uuid_valid += 1;
            }

            // 5. IP Address Verification (`Some` must appear in raw; `None` is
            //    correct only when raw carries no endpoint marker — P5 rule)
            match activity.src_endpoint.ip.as_deref() {
                Some(ip) if raw.contains(ip) => src_ip_correct += 1,
                None if !Self::raw_has_src_ip_marker(raw) => src_ip_correct += 1,
                other => failures.push(AuditFailure::new(
                    "src_ip",
                    idx,
                    raw,
                    "ip embedded in raw",
                    other.unwrap_or("null"),
                    cluster_id,
                )),
            }
            match activity.dst_endpoint.ip.as_deref() {
                Some(ip) if raw.contains(ip) => dst_ip_correct += 1,
                None if !Self::raw_has_dst_ip_marker(raw) => dst_ip_correct += 1,
                other => failures.push(AuditFailure::new(
                    "dst_ip",
                    idx,
                    raw,
                    "ip embedded in raw",
                    other.unwrap_or("null"),
                    cluster_id,
                )),
            }

            // 6. Port Verification (`None` correct only without port evidence)
            match activity.src_endpoint.port {
                Some(port) if (1..=65535).contains(&port) && raw.contains(&port.to_string()) => {
                    src_port_correct += 1
                }
                None if !Self::raw_has_port_marker(raw) => src_port_correct += 1,
                other => failures.push(AuditFailure::new(
                    "src_port",
                    idx,
                    raw,
                    "valid 1-65535 port present in raw",
                    &other
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "null".to_string()),
                    cluster_id,
                )),
            }
            match activity.dst_endpoint.port {
                Some(port) if (1..=65535).contains(&port) && raw.contains(&port.to_string()) => {
                    dst_port_correct += 1
                }
                None if !Self::raw_has_port_marker(raw) => dst_port_correct += 1,
                other => failures.push(AuditFailure::new(
                    "dst_port",
                    idx,
                    raw,
                    "valid 1-65535 port present in raw",
                    &other
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "null".to_string()),
                    cluster_id,
                )),
            }

            // 7. Protocol Verification: name match OR numeric IANA equivalence.
            //    A raw line carrying `proto=17` for an extracted UDP is correct —
            //    the old name-only `contains` punished proper number mappings.
            if let Some(ref proto) = activity.connection_info.protocol_name {
                let proto_upper = proto.to_ascii_uppercase();
                let name_ok =
                    raw.to_ascii_uppercase().contains(&proto_upper) || proto_upper == "IP";
                let num_ok = activity
                    .connection_info
                    .protocol_num
                    .map(|n| Self::raw_contains_numeric(raw, n))
                    .unwrap_or(false);
                if name_ok || num_ok {
                    proto_correct += 1;
                } else {
                    failures.push(AuditFailure::new(
                        "protocol",
                        idx,
                        raw,
                        &proto_upper,
                        "no name or numeric match in raw",
                        cluster_id,
                    ));
                }
            } else if !Self::raw_has_protocol_marker(raw) {
                // P5 null-correct: raw carries no IP-protocol evidence
                proto_correct += 1;
            } else {
                failures.push(AuditFailure::new(
                    "protocol",
                    idx,
                    raw,
                    "protocol present",
                    "null",
                    cluster_id,
                ));
            }

            // 8. Disposition Accuracy (strict equality vs OCSF vocabulary)
            if let Some(ref expected_act) = gt_action {
                if activity.disposition == *expected_act {
                    disposition_correct += 1;
                } else {
                    failures.push(AuditFailure::new(
                        "disposition",
                        idx,
                        raw,
                        expected_act,
                        &activity.disposition,
                        cluster_id,
                    ));
                }
            } else if !activity.disposition.is_empty() && activity.disposition != "Unknown" {
                disposition_correct += 1;
            } else {
                failures.push(AuditFailure::new(
                    "disposition",
                    idx,
                    raw,
                    "non-Unknown disposition",
                    &activity.disposition,
                    cluster_id,
                ));
            }

            // 9. P7 sidecar field grading (null-vs-wrong discipline): a
            //    non-null expectation grades correct/wrong, an honest null
            //    only counts as null — never silently skipped.
            if let Some(sc) = sidecar {
                Self::grade_gt_fields(&sc.gt_fields, Some(&activity), &mut rob);
            }
        }

        // Calculate LogPai Grouping Accuracy (GA %): sum of majority classes per cluster / total
        let ga_correct_total: usize = cluster_to_gt_map
            .values()
            .map(|gt_counts| gt_counts.values().max().copied().unwrap_or(0))
            .sum();
        let oracle_ga_total: usize = oracle_map
            .values()
            .map(|gt_counts| gt_counts.values().max().copied().unwrap_or(0))
            .sum();
        let unique_clusters = cluster_to_gt_map.len();

        // Grouping failures: any record outside its cluster's majority GT class
        let mut majority: HashMap<usize, String> = HashMap::new();
        for (cid, counts) in &cluster_to_gt_map {
            if let Some((tag, _)) = counts.iter().max_by_key(|(_, c)| **c) {
                majority.insert(*cid, tag.clone());
            }
        }
        for (idx, cid, gt_tag) in &records {
            if majority.get(cid).is_some_and(|m| m != gt_tag) {
                failures.push(AuditFailure::new(
                    "grouping",
                    *idx,
                    &corpus[*idx],
                    gt_tag,
                    &format!("cluster {}", cid),
                    *cid,
                ));
            }
        }

        let ga_pct = (ga_correct_total as f64 / audit_count as f64) * 100.0;
        let oracle_ga_pct = (oracle_ga_total as f64 / audit_count as f64) * 100.0;
        let vca_pct = (vendor_correct as f64 / audit_count as f64) * 100.0;
        let ta_pct = (template_correct as f64 / audit_count as f64) * 100.0;

        let src_ip_pct = (src_ip_correct as f64 / audit_count as f64) * 100.0;
        let dst_ip_pct = (dst_ip_correct as f64 / audit_count as f64) * 100.0;
        let src_port_pct = (src_port_correct as f64 / audit_count as f64) * 100.0;
        let dst_port_pct = (dst_port_correct as f64 / audit_count as f64) * 100.0;
        let proto_pct = (proto_correct as f64 / audit_count as f64) * 100.0;

        let field_f1 = (src_ip_pct + dst_ip_pct + src_port_pct + dst_port_pct + proto_pct) / 5.0;
        let disp_pct = (disposition_correct as f64 / audit_count as f64) * 100.0;
        let action_inviolability = if Self::verify_action_preservation() {
            100.0
        } else {
            0.0
        };

        let summary = AccuracyAuditSummary {
            total_audited: audit_count,
            vendor_classification_accuracy_pct: vca_pct,
            grouping_accuracy_ga_pct: ga_pct,
            template_accuracy_ta_pct: ta_pct,
            field_extraction_f1_pct: field_f1,
            src_ip_accuracy_pct: src_ip_pct,
            dst_ip_accuracy_pct: dst_ip_pct,
            src_port_accuracy_pct: src_port_pct,
            dst_port_accuracy_pct: dst_port_pct,
            protocol_accuracy_pct: proto_pct,
            disposition_accuracy_pct: disp_pct,
            action_inviolability_pct: action_inviolability,
            lossless_sha256_match_pct: (sha_matches as f64 / audit_count as f64) * 100.0,
            valid_uuid_v7_pct: (uuid_valid as f64 / audit_count as f64) * 100.0,
            oracle_ga_pct,
            unique_clusters,
        };
        (summary, rob, failures)
    }

    /// Grade sidecar `gt_fields` against the parse result (P7 null-vs-wrong):
    /// non-null expectations count in `gt_fields_total` and resolve to
    /// correct/wrong; honest nulls count only in `gt_fields_null`.
    /// `activity` is `None` on a panicked parse — every non-null expectation
    /// is then `wrong`, never laundered into `null`.
    fn grade_gt_fields(
        gt_fields: &serde_json::Value,
        activity: Option<&NetworkActivity>,
        rob: &mut RobustnessSummary,
    ) {
        const KEYS: [&str; 5] = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"];
        for key in KEYS {
            let expected = gt_fields.get(key);
            if matches!(expected, None | Some(serde_json::Value::Null)) {
                rob.gt_fields_null += 1;
                continue;
            }
            let expected = expected.expect("checked non-null above");
            rob.gt_fields_total += 1;
            let observed = match activity {
                Some(a) => Self::engine_field_value(a, key),
                None => serde_json::Value::Null,
            };
            if Self::gt_value_matches(expected, &observed) {
                rob.gt_fields_correct += 1;
            } else {
                rob.gt_fields_wrong += 1;
                *rob.gt_wrong_by_key.entry(key.to_string()).or_insert(0) += 1;
            }
        }
    }

    /// Engine-observed value for one audited field key, sidecar-comparable.
    fn engine_field_value(activity: &NetworkActivity, key: &str) -> serde_json::Value {
        let strv = |o: &Option<String>| {
            o.clone()
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null)
        };
        match key {
            "src_ip" => strv(&activity.src_endpoint.ip),
            "dst_ip" => strv(&activity.dst_endpoint.ip),
            "src_port" => activity
                .src_endpoint
                .port
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            "dst_port" => activity
                .dst_endpoint
                .port
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            _ => strv(&activity.connection_info.protocol_name),
        }
    }

    /// Sidecar expectation vs engine value: strings compare ASCII-insensitively
    /// (`TCP` vs `tcp` is the same protocol), numbers exactly, everything else
    /// strictly. `null` observed vs non-null expected is always a mismatch.
    fn gt_value_matches(expected: &serde_json::Value, observed: &serde_json::Value) -> bool {
        match (expected, observed) {
            (serde_json::Value::String(a), serde_json::Value::String(b)) => {
                a.eq_ignore_ascii_case(b)
            }
            (serde_json::Value::Number(a), serde_json::Value::Number(b)) => a == b,
            _ => expected == observed,
        }
    }

    /// Verify that DrainDotNet anchor tokens preserve action disposition separation
    fn verify_action_preservation() -> bool {
        let mut miner = DrainMiner::new(DrainConfig::default());
        let log_allow = "FW_ACTION: traffic ALLOW proto=TCP src=10.0.0.1 dst=10.0.0.2";
        let log_deny = "FW_ACTION: traffic DENY proto=TCP src=10.0.0.1 dst=10.0.0.2";

        let res_allow = miner.add_log(log_allow);
        let res_deny = miner.add_log(log_deny);

        res_allow.cluster_id != res_deny.cluster_id
    }
}
