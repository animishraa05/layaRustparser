use chrono::Utc;
use std::borrow::Cow;
use std::collections::HashMap;

use super::fortigate::KvTokenizer;
use super::{protocol_name_from_num, protocol_num_from_name};
use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product, Traffic,
};

/// Zero-copy ArcSight CEF (Common Event Format) extractor.
///
/// Layout: `CEF:<version>|<device vendor>|<device product>|<device version>|`
/// `<signature id>|<name>|<severity>|<extension key=value ...>`
///
/// - `vendor_name` comes from the Device Vendor header field (field 2), which is
///   what ground truth reads — never a hardcoded brand.
/// - The extension is iterated with the same `KvTokenizer` the other kv vendors
///   use (unquoted values end at whitespace per the CEF escaping rules).
/// - Disposition mirrors the evaluator's GT CEF branch exactly:
///   `accept|allow|allowed → Allowed`, `deny|denied|blocked|block → Blocked`,
///   `drop → Dropped`, `close|closed|timeout|client-rst|server-rst|reset →
///   Allowed (CLOSE)`.
///
// Private helpers below (header splitter + unescaper); the struct follows.
/// Split a CEF header into its 7 `|`-separated fields + extension.
///
/// Per the CEF spec `\|` is a literal pipe inside a field, not a
/// separator. Clean fields borrow from `input`; only fields containing
/// `\` allocate.
fn split_cef_header(input: &str) -> Vec<Cow<'_, str>> {
    let mut parts = Vec::with_capacity(8);
    let bytes = input.as_bytes();
    let mut start = 0;
    let mut i = 0;
    let mut splits = 0;
    while i < bytes.len() && splits < 7 {
        if bytes[i] == b'\\' {
            // Escaped char (e.g. `\|`): never a separator, skip both.
            i += 2;
            continue;
        }
        if bytes[i] == b'|' {
            parts.push(unescape_cef(&input[start..i]));
            start = i + 1;
            splits += 1;
        }
        i += 1;
    }
    // Extension: the raw remainder (KvTokenizer handles its own escapes).
    parts.push(Cow::Borrowed(&input[start..]));
    parts
}

/// Unescape CEF `\| \= \\ \r \n`; unknown `\x` stays literal (no data
/// loss). Clean slices borrow — the hot path allocates nothing.
fn unescape_cef(s: &str) -> Cow<'_, str> {
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some(x) => out.push(x),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

pub struct CefExtractor;

impl CefExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        // The syslog-prefixed form (`<164>... CEF:0|...`) must parse too:
        // the header starts at the first `CEF:`.
        let cef_pos = raw
            .find("CEF:")
            .ok_or_else(|| anyhow::anyhow!("Not a CEF record (no 'CEF:' header): {}", raw))?;
        let header_and_ext = &raw[cef_pos..];
        let header = split_cef_header(header_and_ext);
        let get = |i: usize| -> &str { header.get(i).map(|c| c.as_ref()).unwrap_or("") };
        let _cef_version = get(0); // CEF:<version>
        let vendor = get(1).trim();
        let product_name = get(2).trim();
        let device_version = get(3).trim();
        let signature_id = get(4).trim();
        let cef_name = get(5).trim();
        let severity = get(6).trim();
        let extension = get(7);

        let mut src_ip = None;
        let mut dst_ip = None;
        let mut src_port = None;
        let mut dst_port = None;
        let mut proto_num = None;
        let mut proto_name = None;
        let mut action = None;
        let mut rcvd_bytes = None;
        let mut sent_bytes = None;
        let mut unmapped: HashMap<String, String> = HashMap::new();

        for (key, val) in KvTokenizer::new(extension) {
            let val = unescape_cef(val.trim_matches('"'));
            match key {
                "src" => src_ip = Some(val.to_string()),
                "dst" => dst_ip = Some(val.to_string()),
                "spt" | "sport" => src_port = val.parse::<u16>().ok(),
                "dpt" | "dport" => dst_port = val.parse::<u16>().ok(),
                "proto" => {
                    if let Ok(num) = val.parse::<u8>() {
                        proto_num = Some(num);
                        proto_name = Some(protocol_name_from_num(num).to_string());
                    } else {
                        let name = val.to_ascii_uppercase();
                        proto_num = protocol_num_from_name(&name);
                        proto_name = Some(name);
                    }
                }
                "act" | "action" => action = Some(val.to_string()),
                "in" => rcvd_bytes = val.parse::<u64>().ok(),
                "out" => sent_bytes = val.parse::<u64>().ok(),
                _ => {
                    unmapped.insert(key.to_string(), val.to_string());
                }
            }
        }

        // ICMP carries no transport ports: never emit Some(0) (matches the
        // FortiGate/PAN-OS extractors' P2 normalization).
        if proto_num == Some(1) {
            src_port = None;
            dst_port = None;
        } else {
            if src_port == Some(0) {
                src_port = None;
            }
            if dst_port == Some(0) {
                dst_port = None;
            }
        }

        // Header fields that are not the vendor/product/version go to unmapped
        // (never dropped — raw is preserved separately, but structured access
        // to the signature/name/severity keeps the extension tidy).
        if !signature_id.is_empty() {
            unmapped.insert("cef_signature_id".to_string(), signature_id.to_string());
        }
        if !cef_name.is_empty() {
            unmapped.insert("cef_name".to_string(), cef_name.to_string());
        }
        if !severity.is_empty() {
            unmapped.insert("cef_severity".to_string(), severity.to_string());
        }

        // Disposition: mirrors the evaluator's ground-truth CEF branch (`act=`).
        let (disp, act_id) = match action.as_deref().map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("accept") | Some("allow") | Some("allowed") => {
                (disposition::ALLOWED, activity_id::TRAFFIC_FLOW)
            }
            Some("deny") | Some("denied") | Some("blocked") | Some("block") => {
                (disposition::BLOCKED, activity_id::OTHER)
            }
            Some("drop") => (disposition::DROPPED, activity_id::OTHER),
            Some("close") | Some("closed") | Some("timeout") | Some("client-rst")
            | Some("server-rst") | Some("reset") => (disposition::ALLOWED, activity_id::CLOSE),
            _ => (disposition::UNKNOWN, activity_id::TRAFFIC_FLOW),
        };

        let now_ms = Utc::now().timestamp_millis();

        let src_endpoint = Endpoint::new(src_ip, src_port, None, None);
        let dst_endpoint = Endpoint::new(dst_ip, dst_port, None, None);
        let connection_info = ConnectionInfo::new(proto_num, proto_name, None);

        let traffic = if rcvd_bytes.is_some() || sent_bytes.is_some() {
            Some(Traffic::new(rcvd_bytes, sent_bytes, None, None))
        } else {
            None
        };

        let product = Product::new(
            vendor,
            if product_name.is_empty() {
                "CEF"
            } else {
                product_name
            },
            if device_version.is_empty() {
                None
            } else {
                Some(device_version.to_string())
            },
        );
        let metadata = Metadata::new(product, raw, "", "", now_ms);

        Ok(NetworkActivity::new(
            act_id,
            now_ms,
            disp,
            src_endpoint,
            dst_endpoint,
            connection_info,
            traffic,
            metadata,
        )
        .with_unmapped(unmapped))
    }
}

impl Default for CefExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cef_accept_extracts_endpoints_and_disposition() {
        let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|deviceExternalId=FGT200F581900120 src=192.168.1.146 spt=25297 dst=203.0.113.207 dpt=80 proto=6 act=accept cat=traffic:forward app=HTTP in=485401 out=1176097 dvchost=FGT-DC-EDGE";
        let ev = CefExtractor::new().parse(raw).expect("parse cef");
        assert_eq!(ev.metadata.product.vendor_name, "Fortinet");
        assert_eq!(ev.metadata.product.name, "FortiGate");
        assert_eq!(ev.metadata.product.version.as_deref(), Some("v7.0.2"));
        assert_eq!(ev.src_endpoint.ip.as_deref(), Some("192.168.1.146"));
        assert_eq!(ev.src_endpoint.port, Some(25297));
        assert_eq!(ev.dst_endpoint.ip.as_deref(), Some("203.0.113.207"));
        assert_eq!(ev.dst_endpoint.port, Some(80));
        assert_eq!(ev.connection_info.protocol_num, Some(6));
        assert_eq!(ev.connection_info.protocol_name.as_deref(), Some("TCP"));
        assert_eq!(ev.disposition, disposition::ALLOWED);
        assert_eq!(ev.metadata.raw_data, raw);
        let unmapped = ev.unmapped.as_ref().expect("unmapped present");
        assert_eq!(
            unmapped.get("cef_name").map(String::as_str),
            Some("traffic:forward accept")
        );
        assert_eq!(
            unmapped.get("dvchost").map(String::as_str),
            Some("FGT-DC-EDGE")
        );
    }

    #[test]
    fn test_cef_session_end_states_close() {
        let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000014|traffic:forward server-rst|3|src=192.168.3.14 spt=46909 dst=198.51.100.3 dpt=993 proto=6 act=server-rst";
        let ev = CefExtractor::new().parse(raw).expect("parse cef");
        assert_eq!(ev.disposition, disposition::ALLOWED);
        assert_eq!(ev.activity_id, activity_id::CLOSE);
    }

    #[test]
    fn test_cef_deny_is_blocked() {
        let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000012|traffic:forward deny|3|src=192.168.6.68 spt=46825 dst=198.51.100.142 dpt=123 proto=17 act=deny";
        let ev = CefExtractor::new().parse(raw).expect("parse cef");
        assert_eq!(ev.disposition, disposition::BLOCKED);
        assert_ne!(
            ev.disposition,
            disposition::ALLOWED,
            "action inviolability: deny must never be Allowed"
        );
    }

    #[test]
    fn test_cef_syslog_prefix_and_foreign_vendor_header() {
        // Vendor comes from the header — never hardcoded to one brand.
        let raw = "<134>Oct 15 10:20:30 gw CEF:0|Microsoft|Windows|10.0.19044|9001|Logon|5|src=10.20.30.40 spt=50122 dst=10.20.30.10 dpt=445 proto=6 act=allowed";
        let ev = CefExtractor::new()
            .parse(raw)
            .expect("parse cef with syslog prefix");
        assert_eq!(ev.metadata.product.vendor_name, "Microsoft");
        assert_eq!(ev.metadata.product.name, "Windows");
        assert_eq!(ev.disposition, disposition::ALLOWED);
        assert_eq!(ev.src_endpoint.ip.as_deref(), Some("10.20.30.40"));
    }

    #[test]
    fn test_cef_icmp_ports_stay_null() {
        let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000009|traffic:forward accept|3|src=10.1.1.1 spt=0 dst=10.2.2.2 dpt=0 proto=1 act=accept";
        let ev = CefExtractor::new().parse(raw).expect("parse cef icmp");
        assert_eq!(ev.connection_info.protocol_num, Some(1));
        assert_eq!(ev.src_endpoint.port, None, "ICMP must never emit Some(0)");
        assert_eq!(ev.dst_endpoint.port, None);
    }
}
