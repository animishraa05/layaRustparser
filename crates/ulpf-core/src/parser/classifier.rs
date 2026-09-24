use aho_corasick::{AhoCorasick, PatternID};
use serde::{Deserialize, Serialize};

/// Supported Vendor / Device Log Formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VendorFormat {
    CiscoAsa,
    Fortinet,
    PaloAlto,
    Suricata,
    PfSense,
    Cef,
    Unknown,
}

impl VendorFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CiscoAsa => "Cisco ASA",
            Self::Fortinet => "Fortinet FortiGate",
            Self::PaloAlto => "Palo Alto PAN-OS",
            Self::Suricata => "Suricata EVE-JSON",
            Self::PfSense => "pfSense Filterlog",
            Self::Cef => "ArcSight CEF",
            Self::Unknown => "Unknown",
        }
    }
}

/// High-speed Aho-Corasick multi-pattern automaton classifier.
/// Identifies vendor and log format in sub-microsecond time.
pub struct Classifier {
    ac: AhoCorasick,
    pattern_to_format: Vec<VendorFormat>,
}

impl Classifier {
    pub fn new() -> Self {
        // Pattern table: (pattern, corresponding vendor format)
        // Order matters for priority if multiple patterns match.
        let patterns_with_formats: Vec<(&str, VendorFormat)> = vec![
            // Cisco ASA signatures
            ("%ASA-", VendorFormat::CiscoAsa),
            // ArcSight CEF (vendor-neutral envelope: device vendor is header field 2)
            ("CEF:", VendorFormat::Cef),
            // Fortinet signatures
            ("devname=\"", VendorFormat::Fortinet),
            ("type=\"traffic\"", VendorFormat::Fortinet),
            ("logid=\"", VendorFormat::Fortinet),
            ("type=traffic", VendorFormat::Fortinet),
            ("devname=", VendorFormat::Fortinet),
            // pfSense signatures
            ("filterlog[", VendorFormat::PfSense),
            ("filterlog:", VendorFormat::PfSense),
            // Suricata signatures
            ("{\"timestamp\":", VendorFormat::Suricata),
            ("\"event_type\":", VendorFormat::Suricata),
            ("\"flow\":", VendorFormat::Suricata),
            ("\"alert\":", VendorFormat::Suricata),
            // Palo Alto PAN-OS signatures
            (",TRAFFIC,", VendorFormat::PaloAlto),
            (",THREAT,", VendorFormat::PaloAlto),
            (",SYSTEM,", VendorFormat::PaloAlto),
            ("TRAFFIC,drop", VendorFormat::PaloAlto),
            ("TRAFFIC,allow", VendorFormat::PaloAlto),
            ("TRAFFIC,start", VendorFormat::PaloAlto),
            ("TRAFFIC,end", VendorFormat::PaloAlto),
            ("PAN-OS", VendorFormat::PaloAlto),
        ];

        let mut patterns = Vec::with_capacity(patterns_with_formats.len());
        let mut pattern_to_format = Vec::with_capacity(patterns_with_formats.len());

        for (pat, format) in patterns_with_formats {
            patterns.push(pat);
            pattern_to_format.push(format);
        }

        let ac = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            .build(&patterns)
            .expect("Failed to build Aho-Corasick automaton");

        Self {
            ac,
            pattern_to_format,
        }
    }

    /// Classify a raw log line into its vendor format in single-pass O(m) time.
    pub fn classify(&self, raw: &str) -> VendorFormat {
        if let Some(mat) = self.ac.find(raw) {
            let pat_id: PatternID = mat.pattern();
            let idx = pat_id.as_usize();
            if idx < self.pattern_to_format.len() {
                return self.pattern_to_format[idx];
            }
        }

        // Secondary fast structural fallback
        self.fallback_classify(raw)
    }

    fn fallback_classify(&self, raw: &str) -> VendorFormat {
        let trimmed = raw.trim();
        if trimmed.contains("%ASA-") {
            return VendorFormat::CiscoAsa;
        }
        if trimmed.contains("CEF:") {
            return VendorFormat::Cef;
        }
        if trimmed.contains("filterlog") {
            return VendorFormat::PfSense;
        }
        if (trimmed.starts_with('{') || trimmed.contains("{\""))
            && (trimmed.contains("\"timestamp\"") || trimmed.contains("\"event_type\""))
        {
            return VendorFormat::Suricata;
        }
        if (trimmed.contains("srcip=") || trimmed.contains("dstip=")) && trimmed.contains("proto=")
        {
            return VendorFormat::Fortinet;
        }
        // Palo Alto PAN-OS CSV heuristic: typically has 20+ comma-separated tokens
        let comma_count = trimmed.bytes().filter(|&b| b == b',').count();
        if comma_count >= 15
            && (trimmed.contains("TRAFFIC")
                || trimmed.contains("THREAT")
                || trimmed.contains("allow")
                || trimmed.contains("deny")
                || trimmed.contains("drop"))
        {
            return VendorFormat::PaloAlto;
        }

        VendorFormat::Unknown
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_all_vendors() {
        let classifier = Classifier::new();

        assert_eq!(
            classifier.classify("<166>Sep 21 14:00:00 %ASA-6-302013: Built inbound UDP connection"),
            VendorFormat::CiscoAsa
        );
        assert_eq!(
            classifier.classify(
                "date=2023-10-15 time=10:20:30 devname=\"FGT60D\" type=\"traffic\" srcip=1.1.1.1"
            ),
            VendorFormat::Fortinet
        );
        assert_eq!(
            classifier.classify("1,2023/10/15 10:20:30,001801000000,TRAFFIC,drop,0,2023/10/15 10:20:30,10.0.0.1,10.0.0.2"),
            VendorFormat::PaloAlto
        );
        assert_eq!(
            classifier.classify("{\"timestamp\":\"2023-10-15T10:20:30.123456+0000\",\"event_type\":\"alert\",\"src_ip\":\"1.1.1.1\"}"),
            VendorFormat::Suricata
        );
        assert_eq!(
            classifier.classify(
                "Oct 15 10:20:30 pfSense filterlog[12345]: 5,,,1000000103,em0,match,pass,in,4"
            ),
            VendorFormat::PfSense
        );
        assert_eq!(
            classifier.classify(
                "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|src=10.0.0.1 spt=1 dpt=2 proto=6 act=accept"
            ),
            VendorFormat::Cef
        );
        assert_eq!(
            classifier.classify("Random unformatted log line here"),
            VendorFormat::Unknown
        );
    }
}
