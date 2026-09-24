use chrono::Utc;
use std::collections::HashMap;

use super::{protocol_num_from_name, split_csv};
use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product,
};

pub struct PfSenseExtractor;

impl PfSenseExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let csv_part = if let Some(fl_pos) = raw.find("filterlog") {
            let sub = &raw[fl_pos..];
            if let Some(colon_pos) = sub.find(':') {
                sub[colon_pos + 1..].trim()
            } else {
                raw.trim()
            }
        } else {
            raw.trim()
        };

        let fields = split_csv(csv_part);
        if fields.len() < 9 {
            return Err(anyhow::anyhow!(
                "pfSense filterlog has insufficient fields (found {}): {}",
                fields.len(),
                raw
            ));
        }

        let rule_num = fields[0];
        let tracker = fields.get(3).unwrap_or(&"");
        let interface = fields.get(4).unwrap_or(&"");
        let reason = fields.get(5).unwrap_or(&"");
        let action = fields.get(6).unwrap_or(&"");
        let direction = fields.get(7).unwrap_or(&"");
        let ip_version = fields.get(8).unwrap_or(&"4");

        let mut src_ip = None;
        let mut dst_ip = None;
        let mut src_port = None;
        let mut dst_port = None;
        let mut proto_num = None;
        let mut proto_name = None;

        if *ip_version == "4" {
            // IPv4 layout
            if fields.len() > 15 {
                proto_num = fields[15].parse::<u8>().ok();
            }
            if fields.len() > 16 {
                let name = fields[16].to_ascii_uppercase();
                if proto_num.is_none() {
                    proto_num = protocol_num_from_name(&name);
                }
                proto_name = Some(name);
            }
            if fields.len() > 18 {
                src_ip = Some(fields[18].to_string());
            }
            if fields.len() > 19 {
                dst_ip = Some(fields[19].to_string());
            }
            // Ports exist only for transport protocols that have them: on ICMP
            // (and other non-transport protos) fields[20]/[21] are ICMP
            // type-name/code — parsing them yielded `Some(0)`, or even a
            // fabricated port from a numeric ICMP type. P2 normalization
            // ("never Some(0)") applies here too.
            if matches!(proto_num, Some(6) | Some(17)) {
                if fields.len() > 20 {
                    src_port = fields[20].parse::<u16>().ok().filter(|p| *p != 0);
                }
                if fields.len() > 21 {
                    dst_port = fields[21].parse::<u16>().ok().filter(|p| *p != 0);
                }
            }
        } else if *ip_version == "6" {
            // IPv6 layout
            if fields.len() > 12 {
                let name = fields[12].to_ascii_uppercase();
                proto_num = protocol_num_from_name(&name);
                proto_name = Some(name);
            }
            if fields.len() > 13 && proto_num.is_none() {
                proto_num = fields[13].parse::<u8>().ok();
            }
            if fields.len() > 15 {
                src_ip = Some(fields[15].to_string());
            }
            if fields.len() > 16 {
                dst_ip = Some(fields[16].to_string());
            }
            if matches!(proto_num, Some(6) | Some(17)) {
                if fields.len() > 17 {
                    src_port = fields[17].parse::<u16>().ok().filter(|p| *p != 0);
                }
                if fields.len() > 18 {
                    dst_port = fields[18].parse::<u16>().ok().filter(|p| *p != 0);
                }
            }
        }

        let disp = match action.to_ascii_lowercase().as_str() {
            "pass" => disposition::ALLOWED,
            "block" | "reject" => disposition::BLOCKED,
            "drop" => disposition::DROPPED,
            _ => disposition::UNKNOWN,
        };

        let act_id = if disp == disposition::ALLOWED {
            activity_id::TRAFFIC_FLOW
        } else {
            activity_id::OTHER
        };

        let dir = match direction.to_ascii_lowercase().as_str() {
            "in" => Some("Inbound".to_string()),
            "out" => Some("Outbound".to_string()),
            _ => None,
        };

        let intf_opt = if !interface.is_empty() {
            Some(interface.to_string())
        } else {
            None
        };

        let src_endpoint = Endpoint::new(src_ip, src_port, intf_opt.clone(), None);
        let dst_endpoint = Endpoint::new(dst_ip, dst_port, None, None);
        let connection_info = ConnectionInfo::new(proto_num, proto_name, dir);

        let mut unmapped = HashMap::new();
        if !rule_num.is_empty() {
            unmapped.insert("rule_number".to_string(), rule_num.to_string());
        }
        if !tracker.is_empty() {
            unmapped.insert("tracker".to_string(), tracker.to_string());
        }
        if !reason.is_empty() {
            unmapped.insert("reason".to_string(), reason.to_string());
        }
        unmapped.insert("ip_version".to_string(), ip_version.to_string());

        let now_ms = Utc::now().timestamp_millis();
        let product = Product::new("Netgate", "pfSense filterlog", None);
        let metadata = Metadata::new(product, raw, "", "", now_ms);

        Ok(NetworkActivity::new(
            act_id,
            now_ms,
            disp,
            src_endpoint,
            dst_endpoint,
            connection_info,
            None,
            metadata,
        )
        .with_unmapped(unmapped))
    }
}

impl Default for PfSenseExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfsense_ipv4_pass() {
        let extractor = PfSenseExtractor::new();
        let raw = "filterlog: 5,,,1000000103,em0,match,pass,in,4,0x0,,64,12345,0,none,6,tcp,60,192.168.1.50,203.0.113.10,54321,443,0,S,123456,,1024,,";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::TRAFFIC_FLOW);
        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.50"));
        assert_eq!(event.src_endpoint.port, Some(54321));
        assert_eq!(event.src_endpoint.interface.as_deref(), Some("em0"));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(event.dst_endpoint.port, Some(443));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
        assert_eq!(event.connection_info.protocol_num, Some(6));
        assert_eq!(event.connection_info.direction.as_deref(), Some("Inbound"));
    }

    #[test]
    fn test_pfsense_ipv4_block_with_syslog() {
        let extractor = PfSenseExtractor::new();
        let raw = "Oct 15 10:20:30 pfSense filterlog[12345]: 4,,,1000000101,igb0,match,block,in,4,0x0,,128,5432,0,none,17,udp,40,10.0.0.15,8.8.8.8,51234,53,20";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OTHER);
        assert_eq!(event.disposition, disposition::BLOCKED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("10.0.0.15"));
        assert_eq!(event.src_endpoint.port, Some(51234));
        assert_eq!(event.src_endpoint.interface.as_deref(), Some("igb0"));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(event.dst_endpoint.port, Some(53));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("UDP"));
        assert_eq!(event.connection_info.protocol_num, Some(17));
    }
}
