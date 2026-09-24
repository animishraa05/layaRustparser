use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Drain3 Configuration Options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainConfig {
    /// Depth of the prefix search tree (default: 4)
    pub depth: usize,
    /// Minimum similarity score [0.0, 1.0] for matching existing cluster (default: 0.5)
    pub similarity_threshold: f64,
    /// Maximum children at any prefix node before branching to wildcard '*' (default: 100)
    pub max_children: usize,
    /// Maximum number of clusters retained in the tree (default: 10,000)
    pub max_clusters: usize,
    /// Lifetime occurrence threshold to classify a cluster as "rare" (default: 5)
    pub rare_count_threshold: usize,
    /// Traffic surge multiplier above baseline to trigger RareClusterSurge alert (default: 3.0)
    pub surge_multiplier: f64,
    /// Rolling window sample size for anomaly rate calculation (default: 100)
    pub window_size: usize,
    /// Unique event anchor tokens that must NEVER be merged into a wildcard `<*>`
    /// If an anchor token differs between two logs, a distinct cluster is forced (DrainDotNet innovation)
    pub unique_anchor_tokens: Vec<String>,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            depth: 4,
            similarity_threshold: 0.5,
            max_children: 100,
            max_clusters: 10000,
            rare_count_threshold: 5,
            surge_multiplier: 3.0,
            window_size: 100,
            unique_anchor_tokens: vec![
                // Security verdicts (invariant #3 — Action Inviolability).
                "ALLOW".into(),
                "DENY".into(),
                "DROP".into(),
                "BLOCK".into(),
                "PERMIT".into(),
                "REJECT".into(),
                "PASS".into(),
                // P6.1 vocabulary completion: observed verdict/lifecycle tokens
                // (raw corpus + `--audit-dump`) that were missing — `accept`
                // is THE FortiGate/Suricata allow-verb (`act="accept"` vs
                // `act="deny"` previously merged at sim ≈ 0.95 unguarded).
                "ACCEPT".into(),
                "ALLOWED".into(),
                "DENIED".into(),
                "BLOCKED".into(),
                "BUILT".into(),
                "TEARDOWN".into(),
                "CLOSE".into(),
                "CLOSED".into(),
                "RESET".into(),
                "RST".into(),
                // P7.2 anti-merge insurance: PAN-OS CSV rows carry their type
                // token BARE at index 3 — TRAFFIC and THREAT are distinct
                // classes and must never share a cluster (split-only).
                "TRAFFIC".into(),
                "THREAT".into(),
            ],
        }
    }
}

/// P7.2 key-aware class anchors: kv tokens whose KEY is listed here are
/// class discriminators — the same key with a different value can never
/// share a cluster (`type="traffic"` vs `type="dns"`), regardless of how
/// similar the rest of the line is (sim ≈ 0.97 on same-length siblings).
const CLASS_KEYS: &[&str] = &["type"];

/// Alert severity for anomaly events
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Structural anomaly category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    /// First appearance of an unseen log template (Parser Drift / Unknown Device Format)
    NewTemplate,
    /// Previously rare cluster (count <= rare_count_threshold) exhibits an abrupt traffic surge
    RareClusterSurge,
    /// Evasion anomaly: sudden influx of rare / malformed log structural templates
    EvasionAnomaly,
}

/// Anomaly notification generated during Drain3 online template mining
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyAlert {
    pub anomaly_type: AnomalyType,
    pub cluster_id: usize,
    pub template: String,
    pub message: String,
    pub timestamp: i64,
    pub count: usize,
    pub severity: AlertSeverity,
}

/// Mined Log Template Cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogCluster {
    pub cluster_id: usize,
    pub template_tokens: Vec<String>,
    pub template: String,
    pub count: usize,
    pub size: usize,
    pub created_at: i64,
    pub last_seen: i64,
    #[serde(skip)]
    recent_timestamps: VecDeque<i64>,
    /// Dynamic message-code anchor (P6.1): the raw `%FAC-SEV-CODE:` tag of the
    /// line that CREATED this cluster. `find_best_match` enforces strict
    /// equality → every syslog cluster is tag-homogeneous: tags never
    /// generalize to `<*>`, GA can't mix message codes, and TA's
    /// verbatim-GT-tag clause holds by construction. `None` for untagged
    /// formats → no filter (CEF/kv/CSV/JSON unaffected).
    #[serde(default)]
    pub syslog_tag: Option<String>,
}

impl LogCluster {
    pub fn new(
        cluster_id: usize,
        tokens: Vec<String>,
        now_ms: i64,
        syslog_tag: Option<String>,
    ) -> Self {
        let template = tokens.join(" ");
        let size = tokens.len();
        let mut recent_timestamps = VecDeque::with_capacity(64);
        recent_timestamps.push_back(now_ms);
        Self {
            cluster_id,
            template_tokens: tokens,
            template,
            count: 1,
            size,
            created_at: now_ms,
            last_seen: now_ms,
            recent_timestamps,
            syslog_tag,
        }
    }

    pub fn update(&mut self, incoming_tokens: &[String], now_ms: i64) {
        self.count += 1;
        self.last_seen = now_ms;
        if self.recent_timestamps.len() >= 64 {
            self.recent_timestamps.pop_front();
        }
        self.recent_timestamps.push_back(now_ms);

        let mut changed = false;
        for (tmpl_token, in_token) in self.template_tokens.iter_mut().zip(incoming_tokens.iter()) {
            if tmpl_token != in_token && tmpl_token != "<*>" {
                *tmpl_token = "<*>".to_string();
                changed = true;
            }
        }
        if changed {
            self.template = self.template_tokens.join(" ");
        }
    }

    /// Calculate frequency (hits per second) in the recent observation window
    pub fn recent_rate_per_sec(&self) -> f64 {
        if self.recent_timestamps.len() < 2 {
            return 0.0;
        }
        let oldest = *self.recent_timestamps.front().unwrap();
        let newest = *self.recent_timestamps.back().unwrap();
        let elapsed_ms = newest - oldest;
        if elapsed_ms <= 0 {
            return self.recent_timestamps.len() as f64;
        }
        (self.recent_timestamps.len() as f64) / (elapsed_ms as f64 / 1000.0)
    }
}

/// Result returned from processing an event through Drain3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterResult {
    pub cluster_id: usize,
    pub template: String,
    pub is_new: bool,
    pub similarity: f64,
    pub anomaly: Option<AnomalyAlert>,
    pub mining_latency_micros: u64,
}

/// Internal Drain3 Fixed-Depth Prefix Search Tree Node
#[derive(Debug, Clone)]
struct Node {
    _key: String,
    children: HashMap<String, Node>,
    cluster_ids: Vec<usize>,
}

impl Node {
    fn new(key: String) -> Self {
        Self {
            _key: key,
            children: HashMap::new(),
            cluster_ids: Vec::new(),
        }
    }
}

/// High-Performance Native Rust Implementation of Drain3 Log Template Miner
/// Canonical line masker — the exact masking `DrainMiner::add_log` applies before
/// clustering. Exposed so the evaluator's Template-Validity audit can verify
/// template/line token alignment with identical semantics. The compiled regex set
/// is cached process-wide; the audit loop calls this once per corpus line.
pub fn mask_line(raw: &str) -> String {
    use std::sync::OnceLock;
    static SHARED: OnceLock<LogMasker> = OnceLock::new();
    SHARED.get_or_init(LogMasker::new).mask(raw)
}

/// Syslog message-code protection pattern — **single source of truth** shared
/// by the masker (`LogMasker::re_syslog_tag`, which protects tags verbatim in
/// masked output) and the cluster tag anchor (`syslog_tag_of`, P6.1).
pub(crate) const SYSLOG_TAG_PATTERN: &str = r"%[A-Za-z0-9_-]+-\d+-\d+:|%[A-Za-z0-9_-]+:";

/// Syslog message code (`%ASA-6-302013:`) extracted from a raw line, or `None`
/// for untagged formats (CEF / FortiGate kv / Suricata JSON / PAN CSV).
///
/// Dynamic anchor per plan `P6.1` — Action Inviolability for intra-vendor
/// severity codes: `302013` (built) vs `302015` (built/udp) vs `106001`
/// (denied) must never share a cluster even when their token streams sit at
/// similarity ≥ 0.5 (one tag token in fourteen). Mirrors the masker's tag
/// protection exactly, so cluster tag-homogeneity implies
/// `template_is_valid`'s verbatim-GT-tag clause for every syslog cluster.
pub fn syslog_tag_of(raw: &str) -> Option<String> {
    static TAG_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    TAG_RE
        .get_or_init(|| Regex::new(SYSLOG_TAG_PATTERN).expect("valid syslog tag pattern"))
        .find(raw)
        .map(|m| m.as_str().to_owned())
}

pub struct DrainMiner {
    config: DrainConfig,
    root: Node,
    clusters: HashMap<usize, LogCluster>,
    next_cluster_id: AtomicUsize,
    masker: LogMasker,
    total_logs_processed: usize,
}

impl DrainMiner {
    pub fn new(config: DrainConfig) -> Self {
        Self {
            config,
            root: Node::new("root".to_string()),
            clusters: HashMap::new(),
            next_cluster_id: AtomicUsize::new(1),
            masker: LogMasker::new(),
            total_logs_processed: 0,
        }
    }

    /// Process a raw log line, identify or update its structural template cluster,
    /// and evaluate whether an anomaly (Drift / Surge / Evasion) occurred.
    /// Runs in microseconds on standard CPU with zero deep learning overhead.
    pub fn add_log(&mut self, raw: &str) -> ClusterResult {
        let start = Instant::now();
        let now_ms = Utc::now().timestamp_millis();
        self.total_logs_processed += 1;

        // 1. Dynamic Parameter Masking (IPs, numbers, timestamps, hashes, URLs -> <*>)
        let masked = self.masker.mask(raw);

        // 2. Tokenize masked string into tokens
        let tokens = Self::tokenize(&masked);
        if tokens.is_empty() {
            let elapsed = start.elapsed().as_micros() as u64;
            return ClusterResult {
                cluster_id: 0,
                template: String::new(),
                is_new: false,
                similarity: 1.0,
                anomaly: None,
                mining_latency_micros: elapsed,
            };
        }

        let token_count = tokens.len();

        // 3. Search Prefix Tree down to candidate leaf node — tag-anchored (P6.1):
        //    candidate clusters must carry the SAME syslog message code (or none).
        let syslog_tag = syslog_tag_of(raw);
        let (matched_cluster_id, max_sim) = self.find_best_match(&tokens, &syslog_tag);

        let mut anomaly = None;
        let cluster_id: usize;
        let template: String;
        let is_new: bool;

        if let Some(c_id) = matched_cluster_id {
            // Found matching cluster above similarity threshold
            let cluster = self.clusters.get_mut(&c_id).unwrap();
            let prev_count = cluster.count;

            cluster.update(&tokens, now_ms);
            cluster_id = c_id;
            template = cluster.template.clone();
            is_new = false;

            // Anomaly Check: Rare Cluster Surge (Evasion / Spike)
            // Triggered when a rare cluster surges after baseline is established
            if self.total_logs_processed > self.config.rare_count_threshold * 3
                && prev_count <= self.config.rare_count_threshold
                && cluster.count > self.config.rare_count_threshold
            {
                let rate = cluster.recent_rate_per_sec();
                if rate >= self.config.surge_multiplier
                    || cluster.count >= self.config.rare_count_threshold + 2
                {
                    anomaly = Some(AnomalyAlert {
                        anomaly_type: AnomalyType::RareClusterSurge,
                        cluster_id,
                        template: template.clone(),
                        message: format!(
                            "Rare cluster #{} suddenly surged to {} events (rate: {:.2} eps)",
                            cluster_id, cluster.count, rate
                        ),
                        timestamp: now_ms,
                        count: cluster.count,
                        severity: AlertSeverity::High,
                    });
                }
            }
        } else {
            // No match found: Create a new cluster
            cluster_id = self.next_cluster_id.fetch_add(1, Ordering::SeqCst);
            let new_cluster = LogCluster::new(cluster_id, tokens.clone(), now_ms, syslog_tag);
            template = new_cluster.template.clone();
            is_new = true;

            self.insert_to_tree(cluster_id, &tokens, token_count);
            self.clusters.insert(cluster_id, new_cluster);

            // Anomaly: New Template (Parser Drift / Unseen Device Format)
            anomaly = Some(AnomalyAlert {
                anomaly_type: AnomalyType::NewTemplate,
                cluster_id,
                template: template.clone(),
                message: format!(
                    "Unseen log structural template #{} detected: '{}'",
                    cluster_id, template
                ),
                timestamp: now_ms,
                count: 1,
                severity: AlertSeverity::Medium,
            });
        }

        let elapsed = start.elapsed().as_micros() as u64;

        ClusterResult {
            cluster_id,
            template,
            is_new,
            similarity: max_sim,
            anomaly,
            mining_latency_micros: elapsed,
        }
    }

    /// Fast tokenization: splits by whitespace, respecting commas in CSV-like logs
    pub fn tokenize(input: &str) -> Vec<String> {
        // If the string contains spaces, split primarily by whitespace
        if input.contains(' ') {
            input
                .split_whitespace()
                .map(|s| {
                    s.trim_matches(|c| c == ',' || c == ';' || c == '"' || c == '\'')
                        .to_string()
                })
                .filter(|s| !s.is_empty())
                .collect()
        } else if input.contains(',') {
            // Pure CSV log without spaces
            input
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![input.to_string()]
        }
    }

    /// Search candidate clusters in prefix tree and select cluster with maximum similarity.
    ///
    /// P6.1 dynamic anchor: candidates whose `syslog_tag` differs from the
    /// incoming line's tag are skipped **before** similarity — strict
    /// `Option` equality (tagged lines only match their own code; untagged
    /// `None` lines match freely). Split-only: can never lower GA/TA.
    fn find_best_match(
        &self,
        tokens: &[String],
        syslog_tag: &Option<String>,
    ) -> (Option<usize>, f64) {
        let token_count = tokens.len();
        let len_key = token_count.to_string();

        let len_node = match self.root.children.get(&len_key) {
            Some(node) => node,
            None => return (None, 0.0),
        };

        let mut current = len_node;
        let max_prefix_depth = self.config.depth - 2; // depth = 4 -> 2 prefix tokens

        for i in 0..max_prefix_depth {
            if i >= tokens.len() {
                break;
            }
            let token = &tokens[i];
            let key = if Self::has_digit_or_param(token) {
                "*"
            } else {
                token.as_str()
            };

            if let Some(child) = current.children.get(key) {
                current = child;
            } else if let Some(wildcard_child) = current.children.get("*") {
                current = wildcard_child;
            } else {
                return (None, 0.0);
            }
        }

        // Compare incoming tokens against all candidates in leaf node
        let mut best_cluster_id = None;
        let mut max_sim = 0.0;

        for &c_id in &current.cluster_ids {
            if let Some(cluster) = self.clusters.get(&c_id) {
                if cluster.size != token_count {
                    continue;
                }
                // P6.1: message-code anchor — strict tag homogeneity.
                if &cluster.syslog_tag != syslog_tag {
                    continue;
                }
                let sim = Self::compute_similarity(
                    &cluster.template_tokens,
                    tokens,
                    &self.config.unique_anchor_tokens,
                );
                if sim > max_sim {
                    max_sim = sim;
                    if sim >= self.config.similarity_threshold {
                        best_cluster_id = Some(c_id);
                    }
                }
            }
        }

        (best_cluster_id, max_sim)
    }

    /// Insert new cluster into the prefix tree
    fn insert_to_tree(&mut self, cluster_id: usize, tokens: &[String], token_count: usize) {
        let len_key = token_count.to_string();
        let len_node = self
            .root
            .children
            .entry(len_key.clone())
            .or_insert_with(|| Node::new(len_key));

        let mut current = len_node;
        let max_prefix_depth = self.config.depth - 2;

        for i in 0..max_prefix_depth {
            if i >= tokens.len() {
                break;
            }
            let token = &tokens[i];
            let has_digit = Self::has_digit_or_param(token);

            let key = if has_digit || current.children.len() >= self.config.max_children {
                "*".to_string()
            } else {
                token.clone()
            };

            current = current
                .children
                .entry(key.clone())
                .or_insert_with(|| Node::new(key));
        }

        current.cluster_ids.push(cluster_id);
    }

    /// Compute Drain similarity between cluster template and incoming tokens:
    /// sim = count(matching or wildcard tokens) / total_tokens
    /// Enforces DrainDotNet UniqueEventPatterns: anchor tokens (e.g. ALLOW vs
    /// DENY, act="accept" vs act="deny", BUILT vs TEARDOWN) cannot be merged.
    ///
    /// P6.1: anchors are compared on `anchor_value` forms — the VALUE of
    /// `key="value"` / `"key":"value"` tokens — so kv-log verdicts
    /// (FortiGate `action="deny"`, Suricata `"action":"allowed"`) participate
    /// in Action Inviolability with the same force as bare ASA verbs.
    /// Allocation-free (`eq_ignore_ascii_case` over slices) — stays off the
    /// `to_string` budget of the hot path.
    #[inline]
    fn compute_similarity(
        tmpl_tokens: &[String],
        in_tokens: &[String],
        anchor_tokens: &[String],
    ) -> f64 {
        if tmpl_tokens.len() != in_tokens.len() || tmpl_tokens.is_empty() {
            return 0.0;
        }

        if !anchor_tokens.is_empty() {
            for (t1, t2) in tmpl_tokens.iter().zip(in_tokens.iter()) {
                let v1 = Self::anchor_value(t1);
                let v2 = Self::anchor_value(t2);
                let is_anchor = anchor_tokens
                    .iter()
                    .any(|a| v1.eq_ignore_ascii_case(a) || v2.eq_ignore_ascii_case(a));
                if is_anchor && !v1.eq_ignore_ascii_case(v2) {
                    return 0.0; // Force distinct template cluster
                }
                // P7.2 key-aware class partition: same CLASS_KEYS key with a
                // different value forces a distinct cluster even when the key
                // itself is not in the vocabulary list (kv `type=` classes).
                if let (Some(k1), Some(k2)) = (Self::kv_key(t1), Self::kv_key(t2)) {
                    if k1.eq_ignore_ascii_case(k2)
                        && CLASS_KEYS.iter().any(|c| k1.eq_ignore_ascii_case(c))
                        && !v1.eq_ignore_ascii_case(v2)
                    {
                        return 0.0;
                    }
                }
            }
        }

        let mut matches = 0;
        for (t1, t2) in tmpl_tokens.iter().zip(in_tokens.iter()) {
            if t1 == "<*>" || t1 == t2 {
                matches += 1;
            }
        }
        (matches as f64) / (tmpl_tokens.len() as f64)
    }

    /// Value-form of a token for anchor comparison: for `key=value` /
    /// `"key":"value"` shapes the VALUE part (separator + quotes/commas
    /// trimmed), otherwise the whole token. Pure slices — no allocation.
    #[inline]
    fn anchor_value(token: &str) -> &str {
        let value = if let Some(p) = token.find('=') {
            token.get(p + 1..).unwrap_or(token)
        } else if let Some(p) = token.find("\":") {
            token.get(p + 2..).unwrap_or(token)
        } else {
            token
        };
        value.trim_matches(|c: char| {
            c == '"' || c == '\'' || c == ',' || c == ';' || c.is_whitespace()
        })
    }

    /// Key-form of a `key=value` / `"key":"value"` token (P7.2 class-anchor
    /// pairing); `None` for tokens without a separator. Pure slices.
    #[inline]
    fn kv_key(token: &str) -> Option<&str> {
        let key = if let Some(p) = token.find('=') {
            &token[..p]
        } else if let Some(p) = token.find("\":") {
            &token[..p]
        } else {
            return None;
        };
        Some(key.trim_matches(|c: char| {
            c == '"' || c == '\'' || c == ',' || c == ';' || c.is_whitespace()
        }))
    }

    /// Check if token contains digits or dynamic parameters
    #[inline]
    fn has_digit_or_param(token: &str) -> bool {
        token == "<*>" || token.chars().any(|c| c.is_ascii_digit())
    }

    /// Get cluster by ID
    pub fn get_cluster(&self, id: usize) -> Option<&LogCluster> {
        self.clusters.get(&id)
    }

    /// Total number of unique structural clusters mined
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Returns a list of all mined clusters sorted by frequency descending
    pub fn all_clusters_by_frequency(&self) -> Vec<&LogCluster> {
        let mut list: Vec<&LogCluster> = self.clusters.values().collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.count));
        list
    }

    /// Total count of logs processed
    pub fn total_logs(&self) -> usize {
        self.total_logs_processed
    }
}

/// Dynamic Parameter Masker replacing dynamic fields with `<*>`
struct LogMasker {
    re_syslog_tag: Regex,
    re_ip_port: Regex,
    re_ip: Regex,
    re_timestamp_iso: Regex,
    re_timestamp_syslog: Regex,
    re_hex: Regex,
    re_uuid: Regex,
    re_url: Regex,
    re_kv_num: Regex,
    re_pure_num: Regex,
}

impl LogMasker {
    fn new() -> Self {
        Self {
            re_syslog_tag: Regex::new(SYSLOG_TAG_PATTERN).unwrap(),
            // IP:port or IP/port (e.g. outside:192.168.1.1/443 or 10.0.0.1:8080)
            re_ip_port: Regex::new(r"((?:\d{1,3}\.){3}\d{1,3})[:/](\d{1,5})").unwrap(),
            // Standalone IP
            re_ip: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            // ISO 8601 timestamps
            re_timestamp_iso: Regex::new(r"\b\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b").unwrap(),
            // Syslog month/day/time
            re_timestamp_syslog: Regex::new(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b").unwrap(),
            // Hex addresses / hashes
            re_hex: Regex::new(r"\b0x[0-9a-fA-F]+\b|\b[a-fA-F0-9]{32,64}\b").unwrap(),
            // UUIDs
            re_uuid: Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap(),
            // URLs
            re_url: Regex::new(r#"https?://[^\s,"'>]+"#).unwrap(),
            // Dynamic numeric KV pairs (e.g. sessionid=12345, sentbyte=4096)
            re_kv_num: Regex::new(r#"(\b(?:sessionid|session_id|logid|sentbyte|rcvdbyte|sentpkt|rcvdpkt|duration|bytes|cn1|cn2|cn3|eventtime|tracker)=\s*["']?)\d+(["']?)"#).unwrap(),
            // Standalone integers >= 3 digits
            re_pure_num: Regex::new(r"\b\d{3,}\b").unwrap(),
        }
    }

    fn mask(&self, raw: &str) -> String {
        let has_percent = raw.contains('%');
        let has_dot = raw.contains('.');
        let has_colon = raw.contains(':');
        let has_digit = raw.chars().any(|c| c.is_ascii_digit());

        if !has_digit && !has_percent {
            return raw.to_string();
        }

        let mut s = raw.to_string();

        // 1. Protect vendor syslog message tags (e.g. %ASA-6-302013:)
        let mut saved_tags = Vec::new();
        if has_percent {
            let mut placeholder_idx = 0;
            s = self
                .re_syslog_tag
                .replace_all(&s, |caps: &regex::Captures| {
                    let tag = caps.get(0).unwrap().as_str().to_string();
                    let placeholder = format!("__SYSLOG_TAG_{}__", placeholder_idx);
                    placeholder_idx += 1;
                    saved_tags.push((placeholder.clone(), tag));
                    placeholder
                })
                .into_owned();
        }

        // 2. Mask URLs
        if raw.contains("http") {
            s = self.re_url.replace_all(&s, "<*>").into_owned();
        }

        // 3. Mask UUIDs
        if raw.contains('-') && raw.len() > 36 {
            s = self.re_uuid.replace_all(&s, "<*>").into_owned();
        }

        // 4. Mask Hex / Hashes
        if raw.contains("0x") {
            s = self.re_hex.replace_all(&s, "<*>").into_owned();
        }

        // 5. Mask Timestamps
        if has_colon {
            if raw.contains('-') || raw.contains('/') {
                s = self.re_timestamp_iso.replace_all(&s, "<*>").into_owned();
            }
            s = self.re_timestamp_syslog.replace_all(&s, "<*>").into_owned();
        }

        // 6. Mask IP:port / IP/port
        if has_dot && (has_colon || raw.contains('/')) {
            s = self.re_ip_port.replace_all(&s, "<*>").into_owned();
        }

        // 7. Mask standalone IPs
        if has_dot {
            s = self.re_ip.replace_all(&s, "<*>").into_owned();
        }

        // 8. Mask dynamic KV numbers
        if raw.contains('=') {
            s = self.re_kv_num.replace_all(&s, "${1}<*>${2}").into_owned();
        }

        // 9. Mask long numbers (e.g. connection IDs)
        if has_digit {
            s = self.re_pure_num.replace_all(&s, "<*>").into_owned();
        }

        // 10. Restore protected syslog tags
        if !saved_tags.is_empty() {
            for (placeholder, tag) in saved_tags {
                s = s.replace(&placeholder, &tag);
            }
        }

        s
    }
}
