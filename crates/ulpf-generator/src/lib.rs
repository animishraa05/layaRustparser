use anyhow::{Context, Result};
use chrono::Utc;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetKind {
    All,
    Cisco,
    Fortigate,
    PaloAlto,
    Suricata,
    PfSense,
    Kaggle,
}

impl FromStr for DatasetKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "all" => Ok(DatasetKind::All),
            "cisco" | "cisco_asa" | "cisco-asa" => Ok(DatasetKind::Cisco),
            "fortigate" | "fgt" => Ok(DatasetKind::Fortigate),
            "paloalto" | "palo_alto" | "palo-alto" | "panw" => Ok(DatasetKind::PaloAlto),
            "suricata" | "eve" => Ok(DatasetKind::Suricata),
            "pfsense" | "pf" => Ok(DatasetKind::PfSense),
            "kaggle" | "kaggle_firewall" => Ok(DatasetKind::Kaggle),
            _ => Err(anyhow::anyhow!("Unknown dataset kind '{}'. Supported: all, cisco, fortigate, paloalto, suricata, pfsense, kaggle", s)),
        }
    }
}

impl fmt::Display for DatasetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatasetKind::All => write!(f, "all"),
            DatasetKind::Cisco => write!(f, "cisco"),
            DatasetKind::Fortigate => write!(f, "fortigate"),
            DatasetKind::PaloAlto => write!(f, "paloalto"),
            DatasetKind::Suricata => write!(f, "suricata"),
            DatasetKind::PfSense => write!(f, "pfsense"),
            DatasetKind::Kaggle => write!(f, "kaggle"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            _ => Err(anyhow::anyhow!(
                "Invalid protocol '{}'. Must be 'udp' or 'tcp'",
                s
            )),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Tcp => write!(f, "TCP"),
        }
    }
}

/// Converts a Kaggle Firewall CSV row into a standard RFC3164 Syslog packet.
pub fn kaggle_row_to_syslog(row: &str, timestamp: Option<&str>) -> Option<String> {
    let parts: Vec<&str> = row.split(',').map(|s| s.trim()).collect();
    if parts.len() < 10 {
        return None;
    }
    // Skip header line if passed
    if parts[0].eq_ignore_ascii_case("source port") {
        return None;
    }

    let src_port = parts.first().unwrap_or(&"0");
    let dst_port = parts.get(1).unwrap_or(&"0");
    let nat_src_port = parts.get(2).unwrap_or(&"0");
    let nat_dst_port = parts.get(3).unwrap_or(&"0");
    let action = parts.get(4).unwrap_or(&"unknown");
    let bytes = parts.get(5).unwrap_or(&"0");
    let bytes_sent = parts.get(6).unwrap_or(&"0");
    let bytes_rcvd = parts.get(7).unwrap_or(&"0");
    let packets = parts.get(8).unwrap_or(&"0");
    let elapsed = parts.get(9).unwrap_or(&"0");
    let pkts_sent = parts.get(10).unwrap_or(&"0");
    let pkts_rcvd = parts.get(11).unwrap_or(&"0");

    let ts = match timestamp {
        Some(t) => t.to_string(),
        None => Utc::now().format("%b %d %H:%M:%S").to_string(),
    };

    Some(format!(
        "<134>{} firewall-kaggle-01 %KAGGLE-FW-1-TRAFFIC: action=\"{}\" src_port={} dst_port={} nat_src_port={} nat_dst_port={} bytes={} sent_bytes={} rcvd_bytes={} packets={} elapsed_sec={} pkts_sent={} pkts_rcvd={}",
        ts, action, src_port, dst_port, nat_src_port, nat_dst_port, bytes, bytes_sent, bytes_rcvd, packets, elapsed, pkts_sent, pkts_rcvd
    ))
}

/// Discovers the path to `data/raw` by checking standard locations.
pub fn locate_data_dir(custom_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = custom_path {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }

    // Repo-relative candidates only — a hardcoded foreign home directory
    // would silently resolve on one machine and fail everywhere else.
    let candidates = [
        PathBuf::from("data/raw"),
        PathBuf::from("../data/raw"),
        PathBuf::from("../../data/raw"),
    ];

    for candidate in &candidates {
        if candidate.exists() && candidate.is_dir() {
            return Ok(candidate.clone());
        }
    }

    Err(anyhow::anyhow!(
        "Could not find data/raw directory. Please specify --data-dir"
    ))
}

/// Reads lines from a file, ignoring empty lines.
fn read_lines(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path).with_context(|| format!("Failed to open file {:?}", path))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            lines.push(trimmed.to_string());
        }
    }
    Ok(lines)
}

/// Loads datasets from disk into memory.
pub fn load_dataset(kind: DatasetKind, data_dir: &Path) -> Result<Vec<String>> {
    let mut logs = Vec::new();

    let load_cisco = |logs: &mut Vec<String>| -> Result<()> {
        let p = data_dir.join("cisco_asa.log");
        let lines = read_lines(&p)?;
        println!(
            "  [+] Loaded {} Cisco ASA records from {:?}",
            lines.len(),
            p
        );
        logs.extend(lines);
        Ok(())
    };

    let load_fortigate = |logs: &mut Vec<String>| -> Result<()> {
        let p = data_dir.join("fortigate.log");
        let lines = read_lines(&p)?;
        println!(
            "  [+] Loaded {} FortiGate records from {:?}",
            lines.len(),
            p
        );
        logs.extend(lines);
        Ok(())
    };

    let load_paloalto = |logs: &mut Vec<String>| -> Result<()> {
        let p = data_dir.join("paloalto.log");
        let lines = read_lines(&p)?;
        println!(
            "  [+] Loaded {} Palo Alto records from {:?}",
            lines.len(),
            p
        );
        logs.extend(lines);
        Ok(())
    };

    let load_suricata = |logs: &mut Vec<String>| -> Result<()> {
        let p = data_dir.join("suricata.json");
        let lines = read_lines(&p)?;
        println!("  [+] Loaded {} Suricata records from {:?}", lines.len(), p);
        logs.extend(lines);
        Ok(())
    };

    let load_pfsense = |logs: &mut Vec<String>| -> Result<()> {
        let p = data_dir.join("pfsense.log");
        let lines = read_lines(&p)?;
        println!("  [+] Loaded {} pfSense records from {:?}", lines.len(), p);
        logs.extend(lines);
        Ok(())
    };

    let load_kaggle = |logs: &mut Vec<String>| -> Result<()> {
        let p = data_dir.join("kaggle_firewall.csv");
        let lines = read_lines(&p)?;
        let mut count = 0;
        for line in lines {
            if let Some(syslog) = kaggle_row_to_syslog(&line, None) {
                logs.push(syslog);
                count += 1;
            }
        }
        println!(
            "  [+] Loaded & converted {} Kaggle Firewall records into Syslog from {:?}",
            count, p
        );
        Ok(())
    };

    match kind {
        DatasetKind::Cisco => load_cisco(&mut logs)?,
        DatasetKind::Fortigate => load_fortigate(&mut logs)?,
        DatasetKind::PaloAlto => load_paloalto(&mut logs)?,
        DatasetKind::Suricata => load_suricata(&mut logs)?,
        DatasetKind::PfSense => load_pfsense(&mut logs)?,
        DatasetKind::Kaggle => load_kaggle(&mut logs)?,
        DatasetKind::All => {
            load_cisco(&mut logs)?;
            load_fortigate(&mut logs)?;
            load_paloalto(&mut logs)?;
            load_suricata(&mut logs)?;
            load_pfsense(&mut logs)?;
            load_kaggle(&mut logs)?;
        }
    }

    if logs.is_empty() {
        return Err(anyhow::anyhow!(
            "No logs loaded for dataset kind '{}'",
            kind
        ));
    }

    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kaggle_to_syslog() {
        let row = "57222,53,54587,53,allow,177,94,83,2,30,1,1";
        let syslog = kaggle_row_to_syslog(row, Some("Sep 21 14:00:00")).unwrap();
        assert!(syslog.contains("%KAGGLE-FW-1-TRAFFIC"));
        assert!(syslog.contains("src_port=57222"));
        assert!(syslog.contains("dst_port=53"));
        assert!(syslog.contains("action=\"allow\""));
        assert!(syslog.contains("bytes=177"));
    }

    #[test]
    fn test_kaggle_header_skipped() {
        let header = "Source Port,Destination Port,NAT Source Port,NAT Destination Port,Action,Bytes,Bytes Sent,Bytes Received,Packets,Elapsed Time (sec),pkts_sent,pkts_received";
        assert!(kaggle_row_to_syslog(header, None).is_none());
    }

    #[test]
    fn test_dataset_kind_parsing() {
        assert_eq!("all".parse::<DatasetKind>().unwrap(), DatasetKind::All);
        assert_eq!("cisco".parse::<DatasetKind>().unwrap(), DatasetKind::Cisco);
        assert_eq!(
            "fortigate".parse::<DatasetKind>().unwrap(),
            DatasetKind::Fortigate
        );
        assert_eq!(
            "paloalto".parse::<DatasetKind>().unwrap(),
            DatasetKind::PaloAlto
        );
        assert_eq!(
            "suricata".parse::<DatasetKind>().unwrap(),
            DatasetKind::Suricata
        );
        assert_eq!(
            "pfsense".parse::<DatasetKind>().unwrap(),
            DatasetKind::PfSense
        );
        assert_eq!(
            "kaggle".parse::<DatasetKind>().unwrap(),
            DatasetKind::Kaggle
        );
    }
}
