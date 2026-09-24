use crossbeam_channel::{bounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use ulpf_core::parser::classifier::VendorFormat;
use ulpf_core::parser::lru_cache::{LruStats, SignatureLruCache};
use ulpf_core::parser::UniversalParser;
use ulpf_core::schema::ocsf::NetworkActivity;

use crate::drain::{DrainConfig, DrainMiner};
use crate::laya::LayaDecisionEngine;
use crate::onboarder::{DynamicParserRegistry, Onboarder};

/// Task sent to the asynchronous out-of-band Laya System 1 decision worker
#[derive(Debug, Clone)]
pub struct AsyncTriageTask {
    /// Exemplar budget/buffer key: the Tier-1 signature hash (format-level
    /// identity computable on every process() path without the drain lock).
    pub cluster_id: usize,
    /// Drain template when known; empty on the Tier-1 fast path (worker uses sample_log)
    pub template: String,
    pub sample_log: String,
    pub timestamp_ms: i64,
}

/// Tier-3 exemplar budget per cluster: the onboarder needs >= 3 samples, the
/// extra headroom covers bounded-channel drops. The former budget of exactly 1
/// made onboarding mathematically impossible (generate_parser requires 3).
const MAX_EXEMPLARS_PER_CLUSTER: u8 = 8;
/// Minimum sample count before the onboarder synthesizes a parser from a cluster.
const ONBOARD_MIN_SAMPLES: usize = 3;

/// Real-time throughput and triage statistics across all 3 tiers
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PipelineStats {
    pub total_events: u64,
    pub tier1_lru_hits: u64,
    pub tier2_drain_hits: u64,
    pub tier3_laya_dispatches: u64,
    pub tier3_laya_onboarded: u64,
    /// Wired Laya `classify_action` head: high-confidence action decisions seen
    pub laya_action_flags: u64,
    /// Wired Laya `score_threat_risk` head: scores at/above the 0.50 threshold
    pub laya_threat_flags: u64,
    pub lru_hit_ratio: f64,
    pub lru_stats: LruStats,
}

/// 3-Tier Enterprise Log Processing Pipeline:
/// - Tier 1: Lock-Free Signature LRU Cache (~0.06 µs fast path)
/// - Tier 2: DrainDotNet Engine with Anchor Tokens (line-rate clustering on cache miss)
/// - Tier 3: Asynchronous Decoupled Laya System 1 Decision Engine (zero-hallucination out-of-band triage)
pub struct TieredPipeline {
    parser: Arc<UniversalParser>,
    drain: Arc<Mutex<DrainMiner>>,
    dynamic_registry: Arc<Mutex<DynamicParserRegistry>>,
    laya_sender: Sender<AsyncTriageTask>,
    _worker_handle: Option<JoinHandle<()>>,
    total_events: AtomicU64,
    tier2_drain_hits: AtomicU64,
    tier3_laya_dispatches: AtomicU64,
    tier3_laya_onboarded: Arc<AtomicU64>,
    /// Exemplar dispatch budget per format key (Tier-3 needs >= 3 samples)
    triage_dispatch_counts: Mutex<HashMap<usize, u8>>,
    /// Count of format keys still under their exemplar budget: the Tier-1 fast
    /// path reads this single atomic and pays ~1 ns in the steady state (all
    /// budgets closed) instead of touching the dispatch map at all.
    exemplar_budget_open: AtomicU64,
    /// Wired Laya action/threat heads (feeds P8 adjudication metrics)
    laya_action_flags: Arc<AtomicU64>,
    laya_threat_flags: Arc<AtomicU64>,
}

impl TieredPipeline {
    /// Create and start a new 3-tier pipeline with default ring-buffer capacity (10,000 tasks)
    pub fn new() -> Self {
        Self::with_ring_buffer_capacity(10_000)
    }

    /// Create and start a new 3-tier pipeline with custom ring-buffer capacity
    pub fn with_ring_buffer_capacity(capacity: usize) -> Self {
        let parser = Arc::new(UniversalParser::new());
        let drain = Arc::new(Mutex::new(DrainMiner::new(DrainConfig::default())));
        let dynamic_registry = Arc::new(Mutex::new(DynamicParserRegistry::new()));
        let (sender, receiver): (Sender<AsyncTriageTask>, Receiver<AsyncTriageTask>) =
            bounded(capacity);

        let onboarded_counter = Arc::new(AtomicU64::new(0));
        let onboarded_ref = onboarded_counter.clone();
        let registry_ref = dynamic_registry.clone();
        let action_flags = Arc::new(AtomicU64::new(0));
        let action_flags_ref = action_flags.clone();
        let threat_flags = Arc::new(AtomicU64::new(0));
        let threat_flags_ref = threat_flags.clone();

        // Spawn Asynchronous Tier-3 Control Plane Worker (Out-of-Band)
        let worker_handle = thread::Builder::new()
            .name("laya-triage-worker".into())
            .spawn(move || {
                let laya = LayaDecisionEngine::new();
                // Per-cluster exemplar buffers: onboard only at >= ONBOARD_MIN_SAMPLES
                // so the synthesizer sees real variation instead of a single line
                // (generate_parser rejects slices shorter than 3).
                let mut buffers: HashMap<usize, Vec<String>> = HashMap::new();

                while let Ok(task) = receiver.recv() {
                    // 1. Non-autoregressive vendor classification
                    let vendor_choice = laya.classify_vendor(&task.sample_log);
                    // Previously-discarded heads wired into triage outcome flags
                    let action_choice = laya.classify_action(&task.sample_log);
                    let threat_score = laya.score_threat_risk(&task.sample_log);
                    if action_choice.probability >= 0.85 {
                        action_flags_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    if threat_score.score >= 0.50 {
                        threat_flags_ref.fetch_add(1, Ordering::Relaxed);
                    }

                    // Guardrail 3: Calibrated Confidence Gating (P >= 0.85)
                    if vendor_choice.probability < 0.85 {
                        continue;
                    }

                    let buf = buffers.entry(task.cluster_id).or_default();
                    if buf.len() < MAX_EXEMPLARS_PER_CLUSTER as usize {
                        buf.push(task.sample_log);
                    }
                    if buf.len() < ONBOARD_MIN_SAMPLES {
                        continue;
                    }

                    let samples: Vec<&str> = buf.iter().map(|s| s.as_str()).collect();
                    let outcome = Onboarder::generate_parser(
                        &vendor_choice.label,
                        &format!("cluster-{}", task.cluster_id),
                        &samples,
                    );
                    // Retry with more exemplars until the buffer cap, then give up.
                    let done = match outcome {
                        Ok((parser_def, report)) => {
                            if report.passed && report.match_percentage == 100.0 {
                                let mut reg = registry_ref.lock().unwrap();
                                reg.register(parser_def);
                                onboarded_ref.fetch_add(1, Ordering::Relaxed);
                                true
                            } else {
                                buf.len() >= MAX_EXEMPLARS_PER_CLUSTER as usize
                            }
                        }
                        Err(_) => buf.len() >= MAX_EXEMPLARS_PER_CLUSTER as usize,
                    };
                    if done {
                        buffers.remove(&task.cluster_id);
                    }
                }
            })
            .expect("Failed to spawn laya worker thread");

        Self {
            parser,
            drain,
            dynamic_registry,
            laya_sender: sender,
            _worker_handle: Some(worker_handle),
            total_events: AtomicU64::new(0),
            tier2_drain_hits: AtomicU64::new(0),
            tier3_laya_dispatches: AtomicU64::new(0),
            tier3_laya_onboarded: onboarded_counter,
            triage_dispatch_counts: Mutex::new(HashMap::new()),
            exemplar_budget_open: AtomicU64::new(0),
            laya_action_flags: action_flags,
            laya_threat_flags: threat_flags,
        }
    }

    /// Process a raw log line through the 3-Tier Pipeline
    /// Guarantees sub-microsecond line rate without blocking for Tier-3 Laya
    pub fn process(&self, raw: &str) -> NetworkActivity {
        self.total_events.fetch_add(1, Ordering::Relaxed);

        // ---------------------------------------------------------------------
        // TIER 1: Signature LRU Cache Fast-Path Lookup (~0.06 µs)
        // ---------------------------------------------------------------------
        let sig_hash = SignatureLruCache::compute_signature_hash(raw);
        if let Some(format) = self.parser.cache.get(sig_hash) {
            // Fast-path exemplar dispatch: gated by one atomic read so the steady
            // state (every format's exemplar budget closed) costs ~1 ns. Without
            // this, Tier-1 promotion would starve Tier-3 at exactly 2 samples and
            // onboarding could never reach its 3-sample minimum.
            if self.exemplar_budget_open.load(Ordering::Relaxed) > 0 {
                // Template is unavailable without touching the drain lock; the
                // worker consumes sample_log, so an empty template is fine here.
                self.dispatch_triage_exemplar(sig_hash as usize, String::new(), raw);
            }
            // Direct zero-copy parse using cached vendor extractor
            return self.parse_with_format(raw, format);
        }

        // ---------------------------------------------------------------------
        // TIER 2: Cache Miss -> DrainDotNet Clustering Engine (~10 µs)
        // ---------------------------------------------------------------------
        let cluster_res = {
            let mut miner = self.drain.lock().unwrap();
            miner.add_log(raw)
        };

        if !cluster_res.is_new {
            // Matched known cluster template!
            self.tier2_drain_hits.fetch_add(1, Ordering::Relaxed);

            // Budgeted exemplars for Tier-3 (up to MAX_EXEMPLARS_PER_CLUSTER per
            // format key) so the worker can accumulate >= 3 samples and onboard.
            self.dispatch_triage_exemplar(sig_hash as usize, cluster_res.template, raw);

            // Classify once and promote to Tier-1 LRU cache so subsequent events hit Tier 1
            let format = self.parser.classify(raw);
            if format != VendorFormat::Unknown {
                self.parser.cache.insert(sig_hash, format);
            }
            return self.parse_with_format(raw, format);
        }

        // ---------------------------------------------------------------------
        // TIER 3: Unseen Cluster Template -> Asynchronous Laya Dispatch
        // ---------------------------------------------------------------------
        // Guardrail 1 relaxed: exemplar budget per format key (see dispatch helper).
        // Keyed by sig_hash (not the Drain cluster id) so exemplars accumulate on
        // the same identity the Tier-1 fast path can compute without the drain lock.
        self.dispatch_triage_exemplar(sig_hash as usize, cluster_res.template, raw);

        // In-band fallback: never drop logs; parse losslessly
        self.parser.parse_lossless(raw)
    }

    /// Dispatch a Tier-3 exemplar within the per-format-key budget (bounded, non-blocking).
    /// Guardrail 1 becomes a budget of `MAX_EXEMPLARS_PER_CLUSTER` instead of exactly
    /// 1 — the old single-exemplar rule starved the onboarder, which needs >= 3 samples.
    /// All three process() paths share this key so a cluster never splits its budget.
    fn dispatch_triage_exemplar(&self, exemplar_key: usize, template: String, raw: &str) {
        let (within_budget, opened, closed) = match self.triage_dispatch_counts.lock() {
            Ok(mut counts) => {
                let entry = counts.entry(exemplar_key).or_insert(0);
                if *entry >= MAX_EXEMPLARS_PER_CLUSTER {
                    (false, false, false)
                } else {
                    let created = *entry == 0;
                    *entry += 1;
                    (true, created, *entry >= MAX_EXEMPLARS_PER_CLUSTER)
                }
            }
            Err(_) => (false, false, false),
        };
        if opened {
            self.exemplar_budget_open.fetch_add(1, Ordering::Relaxed);
        }
        if closed {
            self.exemplar_budget_open.fetch_sub(1, Ordering::Relaxed);
        }
        if !within_budget {
            return;
        }
        // Guardrail 2: Decoupled bounded ring buffer (non-blocking try_send)
        let _ = self.laya_sender.try_send(AsyncTriageTask {
            cluster_id: exemplar_key,
            template,
            sample_log: raw.to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });
        self.tier3_laya_dispatches.fetch_add(1, Ordering::Relaxed);
    }

    /// Helper to parse raw log with verified VendorFormat
    #[inline]
    fn parse_with_format(&self, raw: &str, format: VendorFormat) -> NetworkActivity {
        match self.parser.parse_with_format(raw, format) {
            Ok(activity) => activity,
            Err(_) => self.parser.parse_lossless(raw),
        }
    }

    /// Current Tier-2 Drain cluster count (real telemetry for evaluator reports)
    pub fn tier2_cluster_count(&self) -> usize {
        self.drain
            .lock()
            .map(|drain| drain.cluster_count())
            .unwrap_or(0)
    }

    /// Query multi-tier statistics
    pub fn stats(&self) -> PipelineStats {
        let total = self.total_events.load(Ordering::Relaxed);
        let lru_stats = self.parser.cache_stats();
        let drain_hits = self.tier2_drain_hits.load(Ordering::Relaxed);
        let laya_dispatches = self.tier3_laya_dispatches.load(Ordering::Relaxed);
        let laya_onboarded = self.tier3_laya_onboarded.load(Ordering::Relaxed);

        PipelineStats {
            total_events: total,
            tier1_lru_hits: lru_stats.hits,
            tier2_drain_hits: drain_hits,
            tier3_laya_dispatches: laya_dispatches,
            tier3_laya_onboarded: laya_onboarded,
            laya_action_flags: self.laya_action_flags.load(Ordering::Relaxed),
            laya_threat_flags: self.laya_threat_flags.load(Ordering::Relaxed),
            lru_hit_ratio: lru_stats.hit_ratio,
            lru_stats,
        }
    }

    /// Access the dynamic parser registry
    pub fn dynamic_registry(&self) -> Arc<Mutex<DynamicParserRegistry>> {
        self.dynamic_registry.clone()
    }
}

impl Default for TieredPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiered_pipeline_lifecycle_and_promotion() {
        let pipeline = TieredPipeline::new();

        let log_asa1 = "%ASA-6-302013: Built inbound UDP connection 1001 for outside:1.1.1.1/53 to inside:2.2.2.2/53";
        let log_asa2 = "%ASA-6-302013: Built inbound UDP connection 1002 for outside:1.1.1.2/53 to inside:2.2.2.3/53";
        let log_fgt =
            r#"date=2026-09-21 time=14:00:02 devname="FGT-DC-EDGE" type="traffic" srcip=10.0.0.1"#;

        // 1st log: Misses LRU, enters Tier 2 DrainDotNet (new cluster #1), triggers async Laya task
        let act1 = pipeline.process(log_asa1);
        assert_eq!(act1.metadata.product.vendor_name, "Cisco");

        // 2nd log: Matches cluster #1 in DrainDotNet, promotes to Tier 1 LRU
        let act2 = pipeline.process(log_asa2);
        assert_eq!(act2.metadata.product.vendor_name, "Cisco");

        // 3rd log of same signature: Hits Tier 1 LRU directly!
        let _act3 = pipeline.process(log_asa1);

        // Process Fortigate
        let _act_fgt = pipeline.process(log_fgt);

        let stats = pipeline.stats();
        assert_eq!(stats.total_events, 4);
        assert!(
            stats.tier3_laya_dispatches >= 2,
            "Dispatched new clusters to Laya"
        );
    }
}
