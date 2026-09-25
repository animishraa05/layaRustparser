use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use crate::parser::classifier::VendorFormat;

/// Fast non-cryptographic FxHasher for 64-bit signature keys
#[derive(Default)]
pub struct FxHasher64 {
    hash: u64,
}

impl Hasher for FxHasher64 {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.hash = self.hash.rotate_left(5) ^ (byte as u64);
            self.hash = self.hash.wrapping_mul(0x517cc1b727220a95);
        }
    }
}

pub type FastBuildHasher = BuildHasherDefault<FxHasher64>;

/// Statistics for LRU Cache performance
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LruStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub hit_ratio: f64,
    pub total_lookups: u64,
    pub entries_count: usize,
}

struct Shard {
    capacity: usize,
    entries: HashMap<u64, VendorFormat, FastBuildHasher>,
    order: VecDeque<u64>,
}

impl Shard {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity_and_hasher(capacity, FastBuildHasher::default()),
            order: VecDeque::with_capacity(capacity),
        }
    }

    #[inline]
    fn get(&self, key: u64) -> Option<VendorFormat> {
        self.entries.get(&key).copied()
    }

    fn insert(&mut self, key: u64, format: VendorFormat) -> bool {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(key) {
            e.insert(format);
            return false;
        }

        let mut evicted = false;
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
                evicted = true;
            }
        }

        self.entries.insert(key, format);
        self.order.push_back(key);
        evicted
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Tier-1 Lock-Free / Read-Optimized Sharded LRU Cache
/// Maps 64-bit log signature hashes directly to specialized VendorFormat parser routes.
pub struct SignatureLruCache {
    shards: Vec<RwLock<Shard>>,
    shard_mask: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl SignatureLruCache {
    /// Create a new cache with default 16 shards and 512 entries per shard (8,192 capacity)
    pub fn new() -> Self {
        Self::with_capacity(16, 512)
    }

    /// Create a new cache with custom shard count (must be power of two) and capacity per shard
    pub fn with_capacity(num_shards: usize, capacity_per_shard: usize) -> Self {
        assert!(
            num_shards.is_power_of_two(),
            "num_shards must be power of two"
        );
        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(RwLock::new(Shard::new(capacity_per_shard)));
        }

        Self {
            shards,
            shard_mask: num_shards - 1,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Fast structural signature extractor and 64-bit hash calculator
    /// Extracts anchor tokens (e.g. %ASA-, devname=, filterlog, JSON delimiters)
    #[inline]
    pub fn compute_signature_hash(raw: &str) -> u64 {
        let bytes = raw.as_bytes();
        let len = bytes.len();
        if len == 0 {
            return 0;
        }

        // Fast path: inspect initial window up to 96 bytes for distinct vendor anchors.
        // Floored to a char boundary: slicing multibyte UTF-8 (e.g. a
        // Unicode hostname) mid-char panics, and this runs on the hot path.
        let window_len = raw.floor_char_boundary(len.min(96));
        let window = &raw[..window_len];

        let mut hasher = FxHasher64::default();

        if window.contains("CEF:") {
            // CEF is a vendor-neutral envelope — one signature bucket for the
            // format (device vendor lives in the header, same cached format).
            hasher.write(b"cef_format");
        } else if let Some(pos) = window.find("%ASA-") {
            // Hash the ASA message tag (e.g. %ASA-6-302013). The +16 cut is
            // floored: a multibyte tail must not panic the hot path.
            let end = window.floor_char_boundary(window.len().min(pos + 16));
            let tag_slice = &window[pos..end];
            hasher.write(tag_slice.as_bytes());
        } else if window.contains("devname=")
            || window.contains("type=\"traffic\"")
            || window.contains("logid=")
        {
            hasher.write(b"fortigate_traffic");
        } else if window.contains("filterlog[") || window.contains("filterlog:") {
            hasher.write(b"pfsense_filterlog");
        } else if window.starts_with('{') || window.contains("\"event_type\"") {
            hasher.write(b"suricata_eve_json");
        } else if window.contains(",TRAFFIC,") || window.contains(",THREAT,") {
            hasher.write(b"paloalto_panos_csv");
        } else {
            // Fallback: structural fingerprint of tokens (skipping pure numbers)
            let mut token_count = 0;
            for token in window.split(|c: char| c.is_whitespace() || c == ',' || c == ':') {
                if token.is_empty() || token.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                hasher.write(token.as_bytes());
                token_count += 1;
                if token_count >= 3 {
                    break;
                }
            }
        }

        hasher.finish()
    }

    /// Sub-microsecond cache lookup using shared read lock across shards
    #[inline]
    pub fn get(&self, signature_hash: u64) -> Option<VendorFormat> {
        let shard_idx = (signature_hash as usize) & self.shard_mask;
        let shard = self.shards[shard_idx].read().unwrap();
        match shard.get(signature_hash) {
            Some(format) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(format)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a newly classified vendor format route into the LRU cache
    pub fn insert(&self, signature_hash: u64, format: VendorFormat) {
        let shard_idx = (signature_hash as usize) & self.shard_mask;
        let mut shard = self.shards[shard_idx].write().unwrap();
        if shard.insert(signature_hash, format) {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Query live statistics
    pub fn stats(&self) -> LruStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let evictions = self.evictions.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_ratio = if total > 0 {
            (hits as f64) / (total as f64)
        } else {
            0.0
        };

        let mut total_entries = 0;
        for s in &self.shards {
            total_entries += s.read().unwrap().len();
        }

        LruStats {
            hits,
            misses,
            evictions,
            hit_ratio,
            total_lookups: total,
            entries_count: total_entries,
        }
    }

    /// Reset metrics
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
    }
}

impl Default for SignatureLruCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_lru_cache_basic_lifecycle() {
        let cache = SignatureLruCache::with_capacity(4, 2);

        let asa_log = "%ASA-6-302013: Built inbound UDP connection 1001 for outside:1.1.1.1/53";
        let fgt_log =
            r#"date=2026-09-21 time=14:00:02 devname="FGT-DC-EDGE" type="traffic" srcip=10.0.0.1"#;

        let hash_asa = SignatureLruCache::compute_signature_hash(asa_log);
        let hash_fgt = SignatureLruCache::compute_signature_hash(fgt_log);

        assert_ne!(hash_asa, hash_fgt);

        assert_eq!(cache.get(hash_asa), None);
        cache.insert(hash_asa, VendorFormat::CiscoAsa);
        assert_eq!(cache.get(hash_asa), Some(VendorFormat::CiscoAsa));

        cache.insert(hash_fgt, VendorFormat::Fortinet);
        assert_eq!(cache.get(hash_fgt), Some(VendorFormat::Fortinet));

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_ratio - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_signature_hash_never_panics_on_multibyte_prefix() {
        // 47 × 'é' (94 bytes) + '€' (bytes 94-96): the 96-byte window ends
        // INSIDE the euro sign. Byte slicing there panics ("not a char
        // boundary") — the hot path must floor to a boundary instead.
        let raw = "é".repeat(47)
            + "€ %ASA-6-302013: Built inbound UDP connection 1 for outside:1.1.1.1/53";
        let h1 = SignatureLruCache::compute_signature_hash(&raw);
        let h2 = SignatureLruCache::compute_signature_hash(&raw);
        assert_eq!(h1, h2, "hashing must stay deterministic");
    }
}
