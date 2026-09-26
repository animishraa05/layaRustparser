pub mod cef;
pub mod cisco_asa;
pub mod fortigate;
pub mod paloalto;
pub mod pfsense;
pub mod suricata;

use std::borrow::Cow;

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

/// Zero-copy CSV field tokenizer handling optional double quotes.
/// Clean fields borrow from `input`; only fields containing quotes
/// allocate (RFC-4180 `""` collapses to one literal `"`).
pub fn split_csv(input: &str) -> Vec<Cow<'_, str>> {
    let mut fields = Vec::with_capacity(48);
    let mut in_quotes = false;
    let mut dirty = false;
    let mut start = 0;
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' if in_quotes && bytes.get(i + 1) == Some(&b'"') => {
                // RFC-4180 escaped quote: literal, does NOT toggle state.
                dirty = true;
                i += 2;
            }
            b'"' => {
                dirty = true;
                in_quotes = !in_quotes;
                i += 1;
            }
            b',' if !in_quotes => {
                fields.push(finish_csv_field(&input[start..i], dirty));
                start = i + 1;
                dirty = false;
                i += 1;
            }
            _ => i += 1,
        }
    }
    fields.push(finish_csv_field(&input[start..], dirty));
    fields
}

/// Clean slice borrows; quoted fields strip one wrapping pair, collapse
/// `""`, and trim — mirroring the old `trim_matches('"').trim()` for
/// well-formed input (including unterminated trailing quotes).
fn finish_csv_field(raw: &str, dirty: bool) -> Cow<'_, str> {
    if !dirty {
        return Cow::Borrowed(raw.trim());
    }
    let mut t = raw.trim();
    if let Some(s) = t.strip_prefix('"') {
        t = s;
    }
    if let Some(s) = t.strip_suffix('"') {
        t = s;
    }
    Cow::Owned(t.replace("\"\"", "\"").trim().to_string())
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
