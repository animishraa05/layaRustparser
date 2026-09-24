pub mod cef;
pub mod cisco_asa;
pub mod fortigate;
pub mod paloalto;
pub mod pfsense;
pub mod suricata;

pub use cef::CefExtractor;
pub use cisco_asa::CiscoAsaExtractor;
pub use fortigate::FortigateExtractor;
pub use paloalto::PaloAltoExtractor;
pub use pfsense::PfSenseExtractor;
pub use suricata::SuricataExtractor;

use chrono::NaiveDateTime;

/// Helper to convert protocol name to IANA protocol number
pub fn protocol_num_from_name(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "ICMP" => Some(1),
        "IGMP" => Some(2),
        "TCP" => Some(6),
        "UDP" => Some(17),
        "GRE" => Some(47),
        "ESP" => Some(50),
        "AH" => Some(51),
        "ICMPV6" | "ICMP6" => Some(58),
        "OSPF" => Some(89),
        "SCTP" => Some(132),
        _ => None,
    }
}

/// Helper to convert IANA protocol number to protocol name
pub fn protocol_name_from_num(num: u8) -> &'static str {
    match num {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "UNKNOWN",
    }
}

/// Zero-copy CSV field tokenizer handling optional double quotes
pub fn split_csv(input: &str) -> Vec<&str> {
    let mut fields = Vec::with_capacity(48);
    let mut in_quotes = false;
    let mut start = 0;
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_quotes = !in_quotes;
        } else if bytes[i] == b',' && !in_quotes {
            let field = &input[start..i];
            fields.push(field.trim_matches('"').trim());
            start = i + 1;
        }
        i += 1;
    }
    if start <= input.len() {
        let field = &input[start..];
        fields.push(field.trim_matches('"').trim());
    }
    fields
}

/// Parse date string "YYYY-MM-DD" and time string "HH:MM:SS" into epoch millis
pub fn parse_date_time_or_fallback(date: &str, time: &str, fallback: i64) -> i64 {
    let combined = format!("{} {}", date.trim(), time.trim());
    if let Ok(dt) = NaiveDateTime::parse_from_str(&combined, "%Y-%m-%d %H:%M:%S") {
        dt.and_utc().timestamp_millis()
    } else {
        fallback
    }
}

/// Parse Palo Alto date-time string "YYYY/MM/DD HH:MM:SS" into epoch millis
pub fn parse_palo_alto_time_or_fallback(dt_str: &str, fallback: i64) -> i64 {
    if let Ok(dt) = NaiveDateTime::parse_from_str(dt_str.trim(), "%Y/%m/%d %H:%M:%S") {
        dt.and_utc().timestamp_millis()
    } else {
        fallback
    }
}

/// Parse RFC3339 / ISO8601 string into epoch millis
pub fn parse_rfc3339_or_fallback(ts_str: &str, fallback: i64) -> i64 {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str.trim()) {
        dt.timestamp_millis()
    } else {
        fallback
    }
}
