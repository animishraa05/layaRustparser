use chrono::Utc;
use std::collections::HashMap;

use super::{parse_date_time_or_fallback, protocol_name_from_num, protocol_num_from_name};
use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product, Traffic,
};

/// Fast zero-copy iterator over key-value pairs in a Fortinet / Syslog log line.
pub struct KvTokenizer<'a> {
    s: &'a str,
}

impl<'a> KvTokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { s: input.trim() }
    }
}

impl<'a> Iterator for KvTokenizer<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        self.s = self.s.trim_start();
        if self.s.is_empty() {
            return None;
        }

        let eq_pos = self.s.find('=')?;
        let raw_key = &self.s[..eq_pos];
        // Extract the word immediately preceding the '='
        let key = if let Some(space_pos) = raw_key.rfind(|c: char| c.is_whitespace()) {
            &raw_key[space_pos + 1..]
        } else {
            raw_key
        };
        let key = key.trim_start_matches(|c: char| !c.is_alphanumeric() && c != '_');

        let after_eq = &self.s[eq_pos + 1..];
        if let Some(inner) = after_eq.strip_prefix('"') {
            // Quoted value
            let mut end_pos = None;
            let mut escaped = false;
            for (idx, b) in inner.bytes().enumerate() {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    end_pos = Some(idx);
                    break;
                }
            }

            if let Some(close_idx) = end_pos {
                let val = &inner[..close_idx];
                self.s = &inner[close_idx + 1..];
                Some((key, val))
            } else {
                let val = inner;
                self.s = "";
                Some((key, val))
            }
        } else {
            // Unquoted value: ends at whitespace
            let ws_pos = after_eq.find(|c: char| c.is_whitespace());
            let (val, rest) = match ws_pos {
                Some(idx) => (&after_eq[..idx], &after_eq[idx..]),
                None => (after_eq, ""),
            };
            self.s = rest;
            Some((key, val))
        }
    }
}

pub struct FortigateExtractor;

impl FortigateExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let mut src_ip = None;
        let mut dst_ip = None;
        let mut src_port = None;
        let mut dst_port = None;
        let mut src_intf = None;
        let mut dst_intf = None;
        let mut src_zone = None;
        let mut dst_zone = None;

        let mut proto_num = None;
        let mut proto_name = None;
        let mut action = None;

        let mut sent_bytes = None;
        let mut rcvd_bytes = None;
        let mut sent_pkts = None;
        let mut rcvd_pkts = None;

        let mut date_str = None;
        let mut time_str = None;
        let mut devname = None;

        let mut unmapped = HashMap::new();

        for (key, val) in KvTokenizer::new(raw) {
            match key {
                "srcip" => src_ip = Some(val.to_string()),
                "dstip" => dst_ip = Some(val.to_string()),
                "srcport" => src_port = val.parse::<u16>().ok(),
                "dstport" => dst_port = val.parse::<u16>().ok(),
                "srcintf" => src_intf = Some(val.to_string()),
                "dstintf" => dst_intf = Some(val.to_string()),
                "srcintfrole" | "srczone" => src_zone = Some(val.to_string()),
                "dstintfrole" | "dstzone" => dst_zone = Some(val.to_string()),
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
                "action" => action = Some(val.to_string()),
                "sentbyte" => sent_bytes = val.parse::<u64>().ok(),
                "rcvdbyte" => rcvd_bytes = val.parse::<u64>().ok(),
                "sentpkt" => sent_pkts = val.parse::<u64>().ok(),
                "rcvdpkt" => rcvd_pkts = val.parse::<u64>().ok(),
                "date" => date_str = Some(val),
                "time" => time_str = Some(val),
                "devname" => devname = Some(val.to_string()),
                _ => {
                    unmapped.insert(key.to_string(), val.to_string());
                }
            }
        }

        // ICMP carries no transport ports: proto=1 (or port fields written as 0)
        // must emit None, never Some(0) — OCSF endpoints have no port for ICMP.
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

        let now_ms = Utc::now().timestamp_millis();
        let event_time = match (date_str, time_str) {
            (Some(d), Some(t)) => parse_date_time_or_fallback(d, t, now_ms),
            _ => now_ms,
        };

        // Determine disposition and activity. Vocabulary kept in lockstep with
        // the evaluator's GT `action_from_kv_token` (P7 parity): every verb
        // the GT resolves must resolve identically here or the disposition
        // audit fails (e.g. `action="blocked"` previously fell to UNKNOWN).
        let (disp, act_id) = match action.as_deref().map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("accept") | Some("allow") | Some("allowed") => {
                (disposition::ALLOWED, activity_id::TRAFFIC_FLOW)
            }
            Some("deny") | Some("denied") | Some("block") | Some("blocked") => {
                (disposition::BLOCKED, activity_id::OTHER)
            }
            Some("drop") => (disposition::DROPPED, activity_id::OTHER),
            // Session-end states of permitted traffic (OCSF: Allowed + CLOSE);
            // `timeout` was previously left to fall through to UNKNOWN, which
            // failed the evaluator's disposition check for idle-expired sessions.
            Some("close") | Some("closed") | Some("client-rst") | Some("server-rst")
            | Some("timeout") | Some("reset") => (disposition::ALLOWED, activity_id::CLOSE),
            Some("open") | Some("start") => (disposition::ALLOWED, activity_id::OPEN),
            _ => (disposition::UNKNOWN, activity_id::TRAFFIC_FLOW),
        };

        let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, src_zone);
        let dst_endpoint = Endpoint::new(dst_ip, dst_port, dst_intf, dst_zone);
        let connection_info = ConnectionInfo::new(proto_num, proto_name, None);

        let traffic = if sent_bytes.is_some()
            || rcvd_bytes.is_some()
            || sent_pkts.is_some()
            || rcvd_pkts.is_some()
        {
            Some(Traffic::new(rcvd_bytes, sent_bytes, rcvd_pkts, sent_pkts))
        } else {
            None
        };

        let product_name = devname.unwrap_or_else(|| "FortiGate".to_string());
        let product = Product::new("Fortinet", product_name, None);
        let metadata = Metadata::new(product, raw, "", "", now_ms);

        Ok(NetworkActivity::new(
            act_id,
            event_time,
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

impl Default for FortigateExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fortigate_kv_tokenizer() {
        let raw = r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=192.168.1.100 srcport=54321 dstip=203.0.113.5 dstport=443 proto=6 action="accept" sentbyte=2048 rcvdbyte=4096"#;
        let pairs: Vec<(&str, &str)> = KvTokenizer::new(raw).collect();
        assert_eq!(pairs.len(), 12);
        assert_eq!(pairs[0], ("date", "2023-10-15"));
        assert_eq!(pairs[2], ("devname", "FGT60D"));
        assert_eq!(pairs[10], ("sentbyte", "2048"));
        assert_eq!(pairs[11], ("rcvdbyte", "4096"));
    }

    #[test]
    fn test_fortigate_extractor_traffic() {
        let extractor = FortigateExtractor::new();
        let raw = r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=192.168.1.100 srcport=54321 srcintf="port1" dstip=203.0.113.5 dstport=443 dstintf="port2" proto=6 action="accept" sentbyte=2048 rcvdbyte=4096 sentpkt=10 rcvdpkt=15 app="HTTPS""#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::TRAFFIC_FLOW);
        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(event.src_endpoint.port, Some(54321));
        assert_eq!(event.src_endpoint.interface.as_deref(), Some("port1"));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(event.dst_endpoint.port, Some(443));
        assert_eq!(event.dst_endpoint.interface.as_deref(), Some("port2"));
        assert_eq!(event.connection_info.protocol_num, Some(6));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));

        let traffic = event.traffic.unwrap();
        assert_eq!(traffic.bytes_out, Some(2048));
        assert_eq!(traffic.bytes_in, Some(4096));
        assert_eq!(traffic.packets_out, Some(10));
        assert_eq!(traffic.packets_in, Some(15));
    }

    #[test]
    fn test_fortigate_extractor_deny() {
        let extractor = FortigateExtractor::new();
        let raw = r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=10.0.0.1 srcport=12345 dstip=10.0.0.2 dstport=80 proto=6 action="deny""#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OTHER);
        assert_eq!(event.disposition, disposition::BLOCKED);
    }

    #[test]
    fn test_fortigate_icmp_ports_none() {
        let extractor = FortigateExtractor::new();
        let raw = r#"date=2026-09-21 time=14:00:02 devname="FGT" type="traffic" subtype="forward" srcip=10.0.0.1 srcport=0 dstip=203.0.113.1 dstport=0 proto=1 action="accept""#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.src_endpoint.port, None, "ICMP has no source port");
        assert_eq!(event.dst_endpoint.port, None, "ICMP has no dest port");
        assert_eq!(event.connection_info.protocol_num, Some(1));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("ICMP"));
        assert_eq!(event.disposition, disposition::ALLOWED);
    }

    #[test]
    fn test_fortigate_timeout_session_end() {
        let extractor = FortigateExtractor::new();
        let raw = r#"date=2026-09-21 time=14:00:02 devname="FGT" type="traffic" srcip=10.0.0.1 srcport=29853 dstip=203.0.113.46 dstport=53 proto=17 action="timeout""#;
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.activity_id, activity_id::CLOSE);
    }
}
