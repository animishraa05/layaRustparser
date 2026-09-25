use chrono::Utc;
use std::collections::HashMap;

use super::{parse_palo_alto_time_or_fallback, protocol_num_from_name, split_csv};
use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product, Traffic,
};

pub struct PaloAltoExtractor;

impl PaloAltoExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let csv_data = strip_syslog_prefix(raw);
        let fields = split_csv(csv_data);

        if fields.len() < 10 {
            return Err(anyhow::anyhow!(
                "Palo Alto log does not have enough CSV fields (found {}): {}",
                fields.len(),
                raw
            ));
        }

        // Locate the base offset using the TRAFFIC type token
        let traffic_idx = fields
            .iter()
            .position(|&f| f.eq_ignore_ascii_case("TRAFFIC"))
            .unwrap_or(3);
        let base = traffic_idx as isize - 3;

        let get = |idx: isize| -> Option<&str> {
            let actual = idx + base;
            if actual >= 0 && (actual as usize) < fields.len() {
                let s = fields[actual as usize].trim();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            } else {
                None
            }
        };

        let receive_time = get(1);
        let serial = get(2);
        let subtype = get(4).unwrap_or("");
        let src_ip = get(7).map(|s| s.to_string());
        let dst_ip = get(8).map(|s| s.to_string());
        let rule = get(11);
        let app = get(14);
        let src_zone = get(16).map(|s| s.to_string());
        let dst_zone = get(17).map(|s| s.to_string());
        let in_iface = get(18).map(|s| s.to_string());
        let out_iface = get(19).map(|s| s.to_string());
        let session_id = get(22);
        let proto_str = get(29).unwrap_or("");
        let action_str = get(30).unwrap_or("");
        // ICMP (or a port column written as 0) carries no transport port — emit
        // None, never Some(0); a TCP/UDP port of 0 is invalid and means "absent".
        let is_icmp = proto_str.eq_ignore_ascii_case("icmp")
            || proto_str.eq_ignore_ascii_case("icmp6")
            || proto_str == "1";
        let src_port = if is_icmp {
            None
        } else {
            get(24)
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|p| *p > 0)
        };
        let dst_port = if is_icmp {
            None
        } else {
            get(25)
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|p| *p > 0)
        };
        let _bytes_total = get(31).and_then(|s| s.parse::<u64>().ok());
        let bytes_sent = get(32).and_then(|s| s.parse::<u64>().ok());
        let bytes_rcvd = get(33).and_then(|s| s.parse::<u64>().ok());
        let packets = get(34).and_then(|s| s.parse::<u64>().ok());

        let now_ms = Utc::now().timestamp_millis();
        let event_time = receive_time
            .map(|rt| parse_palo_alto_time_or_fallback(rt, now_ms))
            .unwrap_or(now_ms);

        let proto_name = if !proto_str.is_empty() {
            Some(proto_str.to_ascii_uppercase())
        } else {
            None
        };
        let proto_num = proto_name.as_deref().and_then(protocol_num_from_name);

        let disp = match action_str.to_ascii_lowercase().as_str() {
            "allow" => disposition::ALLOWED,
            "deny" => disposition::BLOCKED,
            "drop" => disposition::DROPPED,
            "reset-client" | "reset-server" | "reset-both" => disposition::BLOCKED,
            _ => disposition::UNKNOWN,
        };

        let act_id = match subtype.to_ascii_lowercase().as_str() {
            "start" => activity_id::OPEN,
            "end" => activity_id::CLOSE,
            "drop" | "deny" => activity_id::OTHER,
            _ => {
                if disp == disposition::ALLOWED {
                    activity_id::TRAFFIC_FLOW
                } else {
                    activity_id::OTHER
                }
            }
        };

        let mut final_src_port = src_port;
        let mut final_dst_port = dst_port;
        if proto_name.as_deref() == Some("ICMP") || proto_num == Some(1) {
            final_src_port = None;
            final_dst_port = None;
        }

        let src_endpoint = Endpoint::new(src_ip, final_src_port, in_iface, src_zone);
        let dst_endpoint = Endpoint::new(dst_ip, final_dst_port, out_iface, dst_zone);
        let connection_info = ConnectionInfo::new(proto_num, proto_name, None);

        let traffic = if bytes_sent.is_some() || bytes_rcvd.is_some() || packets.is_some() {
            Some(Traffic::new(bytes_rcvd, bytes_sent, None, packets))
        } else {
            None
        };

        let mut unmapped = HashMap::new();
        if let Some(r) = rule {
            unmapped.insert("rule".to_string(), r.to_string());
        }
        if let Some(a) = app {
            unmapped.insert("application".to_string(), a.to_string());
        }
        if let Some(s) = serial {
            unmapped.insert("serial".to_string(), s.to_string());
        }
        if let Some(sid) = session_id {
            unmapped.insert("session_id".to_string(), sid.to_string());
        }
        if !subtype.is_empty() {
            unmapped.insert("subtype".to_string(), subtype.to_string());
        }

        let product = Product::new("Palo Alto Networks", "PAN-OS", None);
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

impl Default for PaloAltoExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_syslog_prefix(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.starts_with("1,20") {
        return trimmed;
    }
    if let Some(pos) = trimmed.find(" 1,20") {
        return &trimmed[pos + 1..];
    }
    if let Some(pos) = trimmed.find(": 1,20") {
        return &trimmed[pos + 2..];
    }
    if let Some(traffic_pos) = trimmed.find(",TRAFFIC,") {
        let before = &trimmed[..traffic_pos];
        if let Some(space_pos) = before.rfind(' ') {
            return &trimmed[space_pos + 1..];
        }
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_palo_alto_traffic_start() {
        let extractor = PaloAltoExtractor::new();
        let raw = "1,2023/10/15 10:20:30,001801000000,TRAFFIC,start,0,2023/10/15 10:20:30,192.168.1.50,203.0.113.25,192.168.1.50,203.0.113.25,allow-web,user1,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-forwarding,0,12345,1,54321,80,0,0,0x0,tcp,allow,1024,512,512,10,2023/10/15 10:20:30,15,any,0,1234567,0x0";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OPEN);
        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.50"));
        assert_eq!(event.src_endpoint.port, Some(54321));
        assert_eq!(event.src_endpoint.zone.as_deref(), Some("trust"));
        assert_eq!(event.src_endpoint.interface.as_deref(), Some("ethernet1/2"));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.25"));
        assert_eq!(event.dst_endpoint.port, Some(80));
        assert_eq!(event.dst_endpoint.zone.as_deref(), Some("untrust"));
        assert_eq!(event.dst_endpoint.interface.as_deref(), Some("ethernet1/1"));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
        assert_eq!(event.connection_info.protocol_num, Some(6));

        let traffic = event.traffic.unwrap();
        assert_eq!(traffic.bytes_out, Some(512));
        assert_eq!(traffic.bytes_in, Some(512));

        let unmapped = event.unmapped.unwrap();
        assert_eq!(unmapped.get("rule").map(|s| s.as_str()), Some("allow-web"));
    }

    #[test]
    fn test_palo_alto_traffic_drop_with_syslog() {
        let extractor = PaloAltoExtractor::new();
        let raw = "Oct 15 10:20:30 my-pan-fw 1,2023/10/15 10:20:30,001801000000,TRAFFIC,drop,0,2023/10/15 10:20:30,10.0.0.5,1.1.1.1,10.0.0.5,1.1.1.1,block-external,,,dns,vsys1,inside,outside,eth1,eth2,default,0,999,1,40000,53,0,0,0x0,udp,drop,0,0,0,1";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OTHER);
        assert_eq!(event.disposition, disposition::DROPPED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(event.src_endpoint.port, Some(40000));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("1.1.1.1"));
        assert_eq!(event.dst_endpoint.port, Some(53));
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("UDP"));
        assert_eq!(event.connection_info.protocol_num, Some(17));
    }

    #[test]
    fn test_palo_alto_icmp_ports_none() {
        // The proven drop fixture with ONLY values swapped: ports zeroed,
        // proto udp -> icmp. Field alignment identical to the passing test.
        let extractor = PaloAltoExtractor::new();
        let raw = "Oct 15 10:20:30 my-pan-fw 1,2023/10/15 10:20:30,001801000000,TRAFFIC,drop,0,2023/10/15 10:20:30,10.0.0.5,1.1.1.1,10.0.0.5,1.1.1.1,block-external,,,dns,vsys1,inside,outside,eth1,eth2,default,0,999,1,0,0,0,0,0x0,icmp,drop,0,0,0,1";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.src_endpoint.port, None, "ICMP has no source port");
        assert_eq!(event.dst_endpoint.port, None, "ICMP has no dest port");
        assert_eq!(event.connection_info.protocol_name.as_deref(), Some("ICMP"));
        assert_eq!(event.connection_info.protocol_num, Some(1));
        assert_eq!(event.disposition, disposition::DROPPED);
    }
}
