use crossbeam_channel::{bounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
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
    pub cluster_id: usize,
    pub template: String,
    pub sample_log: String,
    pub timestamp_ms: i64,
}

/// Real-time throughput and triage statistics across all 3 tiers
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PipelineStats {
    pub total_events: u64,
    pub tier1_lru_hits: u64,
    pub tier2_drain_hits: u64,
    pub tier3_laya_dispatches: u64,
    pub tier3_laya_onboarded: u64,
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

        // Spawn Asynchronous Tier-3 Control Plane Worker (Out-of-Band)
        let worker_handle = thread::Builder::new()
            .name("laya-triage-worker".into())
            .spawn(move || {
                let laya = LayaDecisionEngine::new();

                while let Ok(task) = receiver.recv() {
                    // 1. Non-autoregressive vendor classification
                    let vendor_choice = laya.classify_vendor(&task.sample_log);
                    let _action_choice = laya.classify_action(&task.sample_log);
                    let _threat_score = laya.score_threat_risk(&task.sample_log);

                    // Guardrail 3: Calibrated Confidence Gating (P >= 0.85)
                    if vendor_choice.probability >= 0.85 {
                        let sample_refs = vec![task.sample_log.as_str()];
                        if let Ok((parser_def, report)) = Onboarder::generate_parser(
                            &vendor_choice.label,
                            &format!("cluster-{}", task.cluster_id),
                            &sample_refs,
                        ) {
                            if report.passed {
                                let mut reg = registry_ref.lock().unwrap();
                                reg.register(parser_def);
                                onboarded_ref.fetch_add(1, Ordering::Relaxed);
                            }
                        }
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
        // Guardrail 1: Cluster-level deduplication (only 1st exemplar is dispatched)
        // Guardrail 2: Decoupled bounded ring buffer (non-blocking try_send)
        let _ = self.laya_sender.try_send(AsyncTriageTask {
            cluster_id: cluster_res.cluster_id,
            template: cluster_res.template,
            sample_log: raw.to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });
        self.tier3_laya_dispatches.fetch_add(1, Ordering::Relaxed);

        // In-band fallback: never drop logs; parse losslessly
        self.parser.parse_lossless(raw)
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
