//! Forensic Tamper Detection Engine for the Universal Log Pre-processing Framework.
//!
//! Validates Parquet blocks against the anchored cryptographic ledger:
//! 1. Recomputes SHA-256 digests for every individual raw log.
//! 2. Rebuilds the RFC 6962 Standard Merkle Tree.
//! 3. Cross-examines the reconstructed root against the immutable ledger root.
//! 4. Pinpoints any altered byte, altered IP, deleted record, or swapped sequence.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::batcher::{BatchAccumulator, LedgerEntry};
use crate::merkle::MerkleTree;
use crate::storage::{read_parquet_file, StoredLogRecord};

/// Detailed explanation of why a record or block failed integrity verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TamperReason {
    /// The stored SHA-256 hash does not match the recomputed hash of `raw_log`.
    DigestMismatch {
        stored_hash: String,
        calculated_hash: String,
    },
    /// The record's leaf index does not match its sequential position in the block.
    IndexMismatch {
        expected_index: u32,
        found_index: u32,
    },
    /// Discrepancy between the expected record count from the ledger and actual count.
    CountDiscrepancy {
        expected_count: usize,
        actual_count: usize,
    },
    /// The reconstructed RFC 6962 Merkle Root does not match the anchored root in the ledger.
    MerkleRootMismatch {
        ledger_root: String,
        computed_root: String,
    },
}

impl fmt::Display for TamperReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TamperReason::DigestMismatch {
                stored_hash,
                calculated_hash,
            } => {
                write!(
                    f,
                    "SHA-256 Digest Mismatch (Stored: {} vs Computed: {})",
                    stored_hash, calculated_hash
                )
            }
            TamperReason::IndexMismatch {
                expected_index,
                found_index,
            } => {
                write!(
                    f,
                    "Leaf Index Mismatch (Expected: {}, Found: {})",
                    expected_index, found_index
                )
            }
            TamperReason::CountDiscrepancy {
                expected_count,
                actual_count,
            } => {
                write!(
                    f,
                    "Block Record Count Discrepancy (Ledger: {} vs Actual: {})",
                    expected_count, actual_count
                )
            }
            TamperReason::MerkleRootMismatch {
                ledger_root,
                computed_root,
            } => {
                write!(
                    f,
                    "Merkle Root Mismatch (Ledger: {} vs Computed: {})",
                    ledger_root, computed_root
                )
            }
        }
    }
}

/// Information identifying an individually corrupted or tampered record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TamperedRecord {
    pub leaf_index: u32,
    pub event_id: String,
    pub stored_raw_hash: String,
    pub calculated_raw_hash: String,
    pub raw_log_preview: String,
    pub reason: TamperReason,
}

/// Comprehensive forensic report generated after auditing a Parquet block.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TamperReport {
    pub is_valid: bool,
    pub block_id: u64,
    pub ledger_merkle_root: String,
    pub computed_merkle_root: String,
    pub expected_records: usize,
    pub actual_records: usize,
    pub tampered_records: Vec<TamperedRecord>,
    pub summary: String,
}

impl TamperReport {
    /// Returns true if any tampering or corruption was detected.
    pub fn is_tampered(&self) -> bool {
        !self.is_valid
    }

    /// Generates a high-visibility terminal report suitable for SOC alerts and CLI output.
    pub fn format_alert(&self) -> String {
        if self.is_valid {
            format!(
                "PASS: Merkle Root Matches (RFC 6962)\n\
                 Block ID:             {}\n\
                 Records Verified:     {}\n\
                 Anchored Merkle Root: {}\n\
                 Integrity Status:     100% UNTAMPERED",
                self.block_id, self.actual_records, self.ledger_merkle_root
            )
        } else {
            let mut out = format!(
                "ALARM: FORENSIC TAMPER DETECTED IN BLOCK #{:05}!\n\
                 --------------------------------------------------\n\
                 Ledger Root:   {}\n\
                 Computed Root: {}\n\
                 Expected Rows: {} | Actual Rows: {}\n\
                 Summary:       {}\n\
                 --------------------------------------------------\n",
                self.block_id,
                self.ledger_merkle_root,
                self.computed_merkle_root,
                self.expected_records,
                self.actual_records,
                self.summary
            );

            if !self.tampered_records.is_empty() {
                out.push_str("Tampered Records Breakdown:\n");
                for (i, rec) in self.tampered_records.iter().take(10).enumerate() {
                    out.push_str(&format!(
                        "  [{}] Leaf #{} (Event ID: {})\n\
                               Reason:     {}\n\
                               Stored:     {}\n\
                               Calculated: {}\n\
                               Log Snippet: \"{}\"\n",
                        i + 1,
                        rec.leaf_index,
                        rec.event_id,
                        rec.reason,
                        rec.stored_raw_hash,
                        rec.calculated_raw_hash,
                        rec.raw_log_preview
                    ));
                }
                if self.tampered_records.len() > 10 {
                    out.push_str(&format!(
                        "  ... and {} additional tampered records.\n",
                        self.tampered_records.len() - 10
                    ));
                }
            }

            out
        }
    }
}

/// Records below this count are hashed inline: spawning OS threads costs
/// ~20-50us each, which outweighs SHA-256 (~1us/record) on small blocks.
const PARALLEL_DIGEST_THRESHOLD: usize = 512;

/// Maximum worker threads for the digest pass. SHA-256 is memory-bound on
/// short log lines, so scaling flattens past a handful of cores.
const MAX_DIGEST_THREADS: usize = 8;

/// Hash every record's `raw_log` exactly once, returning digests in record
/// order. Large blocks fan out across contiguous chunks via scoped threads;
/// each worker writes back only its own chunk, so output order is
/// deterministic regardless of thread scheduling.
fn compute_digests(records: &[StoredLogRecord]) -> Vec<String> {
    let n = records.len();
    let mut digests: Vec<String> = vec![String::new(); n];
    if n == 0 {
        return digests;
    }

    if n < PARALLEL_DIGEST_THRESHOLD {
        for (slot, record) in digests.iter_mut().zip(records.iter()) {
            *slot = hex::encode(Sha256::digest(record.raw_log.as_bytes()));
        }
        return digests;
    }

    let requested = std::thread::available_parallelism().map_or(4, |p| p.get());
    let num_threads = requested.min(MAX_DIGEST_THREADS).min(n).max(1);
    if num_threads <= 1 {
        for (slot, record) in digests.iter_mut().zip(records.iter()) {
            *slot = hex::encode(Sha256::digest(record.raw_log.as_bytes()));
        }
        return digests;
    }
    let chunk_size = n.div_ceil(num_threads);

    // Borrow checker: chunks_mut yields disjoint &mut slices, so each scoped
    // worker owns its write range and no lock or atomic is needed.
    std::thread::scope(|s| {
        for (digest_chunk, record_chunk) in digests
            .chunks_mut(chunk_size)
            .zip(records.chunks(chunk_size))
        {
            s.spawn(move || {
                for (slot, record) in digest_chunk.iter_mut().zip(record_chunk.iter()) {
                    *slot = hex::encode(Sha256::digest(record.raw_log.as_bytes()));
                }
            });
        }
    });

    digests
}

/// Verifies a Parquet block file against an explicitly provided `LedgerEntry`.
pub fn verify_block_file(
    parquet_path: impl AsRef<Path>,
    ledger_entry: &LedgerEntry,
) -> Result<TamperReport> {
    let records = read_parquet_file(parquet_path)?;
    Ok(verify_records(&records, ledger_entry))
}

/// Verifies a Parquet block file by automatically finding its entry in `ledger.jsonl`.
pub fn verify_block_with_ledger(
    parquet_path: impl AsRef<Path>,
    ledger_path: impl AsRef<Path>,
) -> Result<TamperReport> {
    let records = read_parquet_file(parquet_path.as_ref())?;
    let ledger_entries = BatchAccumulator::load_ledger_entries(ledger_path.as_ref())?;

    // Determine target block ID: from records or filename
    let block_id = if let Some(first) = records.first() {
        first.block_id
    } else {
        // Parse block_id from filename like "block_00001.parquet"
        let fname = parquet_path
            .as_ref()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        fname
            .strip_prefix("block_")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    };

    let entry = ledger_entries
        .into_iter()
        .find(|e| e.block_id == block_id)
        .with_context(|| {
            format!(
                "No corresponding ledger entry found for block ID {} in {:?}",
                block_id,
                ledger_path.as_ref()
            )
        })?;

    Ok(verify_records(&records, &entry))
}

/// Performs in-memory forensic verification on a slice of `StoredLogRecord`.
pub fn verify_records(records: &[StoredLogRecord], ledger_entry: &LedgerEntry) -> TamperReport {
    let mut tampered_records = Vec::new();
    let actual_records = records.len();
    let expected_records = ledger_entry.leaf_count;

    // 1. Verify record count
    if actual_records != expected_records {
        tampered_records.push(TamperedRecord {
            leaf_index: actual_records as u32,
            event_id: String::new(),
            stored_raw_hash: String::new(),
            calculated_raw_hash: String::new(),
            raw_log_preview: String::new(),
            reason: TamperReason::CountDiscrepancy {
                expected_count: expected_records,
                actual_count: actual_records,
            },
        });
    }

    // 2. Validate individual records: sequence index and raw hash.
    // Each raw_log is hashed exactly once up front (in parallel for large
    // blocks); the digest below is reused for both the mismatch check and
    // the TamperReason payload, so stored-vs-calculated can never disagree.
    let digests = compute_digests(records);
    for ((i, record), computed_digest) in records.iter().enumerate().zip(digests.iter()) {
        let expected_idx = i as u32;

        if record.leaf_index != expected_idx {
            tampered_records.push(TamperedRecord {
                leaf_index: record.leaf_index,
                event_id: record.event_id.clone(),
                stored_raw_hash: record.raw_hash.clone(),
                calculated_raw_hash: String::new(),
                raw_log_preview: preview_log(&record.raw_log),
                reason: TamperReason::IndexMismatch {
                    expected_index: expected_idx,
                    found_index: record.leaf_index,
                },
            });
        }

        if computed_digest != &record.raw_hash {
            tampered_records.push(TamperedRecord {
                leaf_index: record.leaf_index,
                event_id: record.event_id.clone(),
                stored_raw_hash: record.raw_hash.clone(),
                calculated_raw_hash: computed_digest.clone(),
                raw_log_preview: preview_log(&record.raw_log),
                reason: TamperReason::DigestMismatch {
                    stored_hash: record.raw_hash.clone(),
                    calculated_hash: computed_digest.clone(),
                },
            });
        }
    }

    // 3. Rebuild RFC 6962 Merkle Tree from all raw logs
    let computed_tree = MerkleTree::from_raw_logs(records.iter().map(|r| r.raw_log.as_bytes()));
    let computed_root = computed_tree.root().to_hex();
    let ledger_root = ledger_entry.merkle_root.clone();

    let root_matches = computed_root == ledger_root;
    if !root_matches && tampered_records.is_empty() {
        // Hash matched per record, but tree root differs (e.g. attacker recomputed raw_hash)
        tampered_records.push(TamperedRecord {
            leaf_index: 0,
            event_id: String::new(),
            stored_raw_hash: ledger_root.clone(),
            calculated_raw_hash: computed_root.clone(),
            raw_log_preview: String::new(),
            reason: TamperReason::MerkleRootMismatch {
                ledger_root: ledger_root.clone(),
                computed_root: computed_root.clone(),
            },
        });
    }

    let is_valid = root_matches && tampered_records.is_empty();

    let summary = if is_valid {
        "Block integrity mathematically verified against anchored Merkle root.".to_string()
    } else {
        format!(
            "Tamper detected: {} anomaly/anomalies found. Recomputed root {} != Ledger root {}.",
            tampered_records.len(),
            computed_root,
            ledger_root
        )
    };

    TamperReport {
        is_valid,
        block_id: ledger_entry.block_id,
        ledger_merkle_root: ledger_root,
        computed_merkle_root: computed_root,
        expected_records,
        actual_records,
        tampered_records,
        summary,
    }
}

fn preview_log(log: &str) -> String {
    let max_len = 64;
    if log.chars().count() <= max_len {
        log.to_string()
    } else {
        let truncated: String = log.chars().take(max_len).collect();
        format!("{}...", truncated)
    }
}
