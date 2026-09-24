pub mod classifier;
pub mod extractors;
pub mod lru_cache;

pub use classifier::{Classifier, VendorFormat};
pub use extractors::{
    CefExtractor, CiscoAsaExtractor, FortigateExtractor, PaloAltoExtractor, PfSenseExtractor,
    SuricataExtractor,
};
pub use lru_cache::{LruStats, SignatureLruCache};

use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product,
};

/// Common trait for format-specific log parsers
pub trait LogParser: Send + Sync {
    fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity>;
    fn vendor_format(&self) -> VendorFormat;
}

/// Universal Parser orchestrating two-tier classification, extraction,
/// cryptographic SHA-256 hashing, and UUIDv7 event ID generation.
pub struct UniversalParser {
    classifier: Classifier,
    cisco_asa: CiscoAsaExtractor,
    fortigate: FortigateExtractor,
    paloalto: PaloAltoExtractor,
    suricata: SuricataExtractor,
    pfsense: PfSenseExtractor,
    cef: CefExtractor,
    pub cache: SignatureLruCache,
}

impl UniversalParser {
    pub fn new() -> Self {
        Self {
            classifier: Classifier::new(),
            cisco_asa: CiscoAsaExtractor::new(),
            fortigate: FortigateExtractor::new(),
            paloalto: PaloAltoExtractor::new(),
            suricata: SuricataExtractor::new(),
            pfsense: PfSenseExtractor::new(),
            cef: CefExtractor::new(),
            cache: SignatureLruCache::new(),
        }
    }

    /// Classify the vendor format of a raw log line
    pub fn classify(&self, raw: &str) -> VendorFormat {
        self.classifier.classify(raw)
    }

    /// Parse raw log line into normalized OCSF 1.3 NetworkActivity (UID 4001).
    /// Guarantees 100% raw log preservation, SHA-256 cryptographic digest,
    /// time-ordered UUIDv7 event identifier, and ingestion timestamp.
    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let raw_hash = compute_sha256(raw.as_bytes());
        let event_id = Uuid::now_v7().to_string();
        let ingest_time = Utc::now().timestamp_millis();

        let format = self.classifier.classify(raw);
        let mut activity = match format {
            VendorFormat::CiscoAsa => self.cisco_asa.parse(raw)?,
            VendorFormat::Fortinet => self.fortigate.parse(raw)?,
            VendorFormat::PaloAlto => self.paloalto.parse(raw)?,
            VendorFormat::Suricata => self.suricata.parse(raw)?,
            VendorFormat::PfSense => self.pfsense.parse(raw)?,
            VendorFormat::Cef => self.cef.parse(raw)?,
            VendorFormat::Unknown => {
                return Err(anyhow::anyhow!(
                    "Unrecognized log format for raw line: {}",
                    raw
                ));
            }
        };

        // Guarantee 100% complete preserved raw log line and cryptographic traceability
        activity.metadata.raw_data = raw.to_string();
        activity.metadata.raw_hash = raw_hash;
        activity.metadata.event_id = event_id;
        activity.metadata.ingest_time = ingest_time;

        Ok(activity)
    }

    /// Lossless parsing that never drops a log: if format is unknown or parsing fails,
    /// a normalized OCSF event is still produced preserving raw_data, SHA-256 hash, and UUIDv7.
    pub fn parse_lossless(&self, raw: &str) -> NetworkActivity {
        match self.parse(raw) {
            Ok(activity) => activity,
            Err(err) => {
                let raw_hash = compute_sha256(raw.as_bytes());
                let event_id = Uuid::now_v7().to_string();
                let now_ms = Utc::now().timestamp_millis();

                let mut unmapped = std::collections::HashMap::new();
                unmapped.insert("parse_error".to_string(), err.to_string());

                let product = Product::new("Unknown", "Generic / Unparsed", None);
                let metadata = Metadata::new(product, raw, raw_hash, event_id, now_ms);

                NetworkActivity::new(
                    activity_id::OTHER,
                    now_ms,
                    disposition::UNKNOWN,
                    Endpoint::default(),
                    Endpoint::default(),
                    ConnectionInfo::default(),
                    None,
                    metadata,
                )
                .with_unmapped(unmapped)
            }
        }
    }

    /// Parse directly with a known pre-classified VendorFormat, skipping classification completely
    #[inline]
    pub fn parse_with_format(
        &self,
        raw: &str,
        format: VendorFormat,
    ) -> anyhow::Result<NetworkActivity> {
        let raw_hash = compute_sha256(raw.as_bytes());
        let event_id = Uuid::now_v7().to_string();
        let ingest_time = Utc::now().timestamp_millis();

        let mut activity = match format {
            VendorFormat::CiscoAsa => self.cisco_asa.parse(raw)?,
            VendorFormat::Fortinet => self.fortigate.parse(raw)?,
            VendorFormat::PaloAlto => self.paloalto.parse(raw)?,
            VendorFormat::Suricata => self.suricata.parse(raw)?,
            VendorFormat::PfSense => self.pfsense.parse(raw)?,
            VendorFormat::Cef => self.cef.parse(raw)?,
            VendorFormat::Unknown => {
                return Err(anyhow::anyhow!(
                    "Unrecognized log format for raw line: {}",
                    raw
                ));
            }
        };

        activity.metadata.raw_data = raw.to_string();
        activity.metadata.raw_hash = raw_hash;
        activity.metadata.event_id = event_id;
        activity.metadata.ingest_time = ingest_time;

        Ok(activity)
    }

    /// Parse raw log line using Tier-1 Signature LRU Cache fast path
    pub fn parse_cached(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let sig_hash = SignatureLruCache::compute_signature_hash(raw);
        let format = match self.cache.get(sig_hash) {
            Some(fmt) => fmt,
            None => {
                let fmt = self.classifier.classify(raw);
                if fmt != VendorFormat::Unknown {
                    self.cache.insert(sig_hash, fmt);
                }
                fmt
            }
        };

        self.parse_with_format(raw, format)
    }

    /// Lossless parsing using Tier-1 Signature LRU Cache
    pub fn parse_cached_lossless(&self, raw: &str) -> NetworkActivity {
        match self.parse_cached(raw) {
            Ok(activity) => activity,
            Err(err) => {
                let raw_hash = compute_sha256(raw.as_bytes());
                let event_id = Uuid::now_v7().to_string();
                let now_ms = Utc::now().timestamp_millis();

                let mut unmapped = std::collections::HashMap::new();
                unmapped.insert("parse_error".to_string(), err.to_string());

                let product = Product::new("Unknown", "Generic / Unparsed", None);
                let metadata = Metadata::new(product, raw, raw_hash, event_id, now_ms);

                NetworkActivity::new(
                    activity_id::OTHER,
                    now_ms,
                    disposition::UNKNOWN,
                    Endpoint::default(),
                    Endpoint::default(),
                    ConnectionInfo::default(),
                    None,
                    metadata,
                )
                .with_unmapped(unmapped)
            }
        }
    }

    /// Query LRU cache statistics
    pub fn cache_stats(&self) -> LruStats {
        self.cache.stats()
    }
}

impl Default for UniversalParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes hex-encoded SHA-256 digest of input bytes
pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_universal_parser_sha256_and_uuid() {
        let parser = UniversalParser::new();
        let raw = "%ASA-6-302013: Built inbound UDP connection 12345 for outside:1.1.1.1/53 to inside:2.2.2.2/53";
        let event = parser.parse(raw).unwrap();

        assert_eq!(event.metadata.raw_data, raw);
        assert_eq!(event.metadata.raw_hash, compute_sha256(raw.as_bytes()));

        // Check valid UUIDv7
        let parsed_uuid = Uuid::parse_str(&event.metadata.event_id).expect("Invalid UUID");
        assert_eq!(parsed_uuid.get_version_num(), 7);
    }
}
