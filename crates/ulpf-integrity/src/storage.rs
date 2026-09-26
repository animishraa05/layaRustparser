//! Arrow and Parquet storage engine for the Universal Log Pre-processing Framework.
//!
//! Enforces high-assurance columnar persistence with Snappy and ZSTD compression.
//! Schema:
//! - `event_id`: Utf8 (UUIDv7)
//! - `block_id`: UInt64
//! - `leaf_index`: UInt32
//! - `timestamp`: Int64 (UTC unix millisecond timestamp)
//! - `vendor`: Dictionary(Int8, Utf8) — low-cardinality, dictionary-encoded
//! - `raw_log`: Utf8 (Complete, uncompressed raw log string)
//! - `raw_hash`: FixedSizeBinary(32) — raw SHA-256 digest bytes (hex only at the
//!   `StoredLogRecord` boundary; the record struct keeps the hex String)
//! - `ocsf_json`: Utf8 (Serialized OCSF 1.3 JSON representation)
//!
//! Backward compatibility: readers sniff each column's physical type, so blocks
//! written with the old all-Utf8 schema (e.g. tracked `data/parquet/*` fixtures)
//! still decode. Never regenerate those fixtures — block_00000 is intentionally
//! tampered and `verify` must keep failing on it.

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow::array::{
    Array, ArrayAccessor, ArrayRef, DictionaryArray, FixedSizeBinaryArray, Int64Array, RecordBatch,
    StringArray, UInt32Array, UInt64Array,
};
use arrow::datatypes::{DataType, Field, Int8Type, Schema, SchemaRef};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};

/// Canonical record stored in Arrow and Parquet blocks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredLogRecord {
    pub event_id: String,
    pub block_id: u64,
    pub leaf_index: u32,
    pub timestamp: i64,
    pub vendor: String,
    pub raw_log: String,
    pub raw_hash: String,
    pub ocsf_json: String,
}

/// Compression formats supported for Parquet log block files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ParquetCompression {
    #[default]
    Snappy,
    Zstd,
    Uncompressed,
}

impl From<ParquetCompression> for Compression {
    fn from(comp: ParquetCompression) -> Self {
        match comp {
            ParquetCompression::Snappy => Compression::SNAPPY,
            ParquetCompression::Zstd => Compression::ZSTD(ZstdLevel::default()),
            ParquetCompression::Uncompressed => Compression::UNCOMPRESSED,
        }
    }
}

/// Returns the official Arrow Schema for ULPF Parquet blocks.
pub fn log_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("block_id", DataType::UInt64, false),
        Field::new("leaf_index", DataType::UInt32, false),
        Field::new("timestamp", DataType::Int64, false),
        Field::new(
            "vendor",
            DataType::Dictionary(Box::new(DataType::Int8), Box::new(DataType::Utf8)),
            false,
        ),
        Field::new("raw_log", DataType::Utf8, false),
        Field::new("raw_hash", DataType::FixedSizeBinary(32), false),
        Field::new("ocsf_json", DataType::Utf8, false),
    ]))
}

/// Converts a slice of `StoredLogRecord` into an Arrow `RecordBatch`.
///
/// The dieted columns skip the `Vec<&str>` intermediate: vendors stream straight
/// into a `DictionaryArray<Int8Type>` and hex hashes are decoded once into a
/// `FixedSizeBinaryArray(32)`. `StoredLogRecord.raw_hash` stays a hex String —
/// the hex↔bytes translation lives only at this Arrow boundary.
///
/// Int8 dictionary keys address at most 128 distinct values per block. Vendor
/// cardinality in practice is a handful, but a pathological block must return an
/// explanatory error here — never panic inside the Arrow kernel.
pub fn records_to_batch(records: &[StoredLogRecord]) -> Result<RecordBatch> {
    let count = records.len();
    let mut event_ids = Vec::with_capacity(count);
    let mut block_ids = Vec::with_capacity(count);
    let mut leaf_indices = Vec::with_capacity(count);
    let mut timestamps = Vec::with_capacity(count);
    let mut raw_logs = Vec::with_capacity(count);
    let mut ocsf_jsons = Vec::with_capacity(count);

    for r in records {
        event_ids.push(r.event_id.as_str());
        block_ids.push(r.block_id);
        leaf_indices.push(r.leaf_index);
        timestamps.push(r.timestamp);
        raw_logs.push(r.raw_log.as_str());
        ocsf_jsons.push(r.ocsf_json.as_str());
    }

    // Dict guard: fail loudly before Arrow key overflow can panic.
    {
        let distinct: HashSet<&str> = records.iter().map(|r| r.vendor.as_str()).collect();
        // Int8 keys address 0..=127, i.e. 128 slots.
        if distinct.len() > 128 {
            anyhow::bail!(
                "Too many distinct vendor values for Dictionary(Int8) block: {} > 128 — split the block",
                distinct.len()
            );
        }
    }
    let vendors: DictionaryArray<Int8Type> =
        records.iter().map(|r| Some(r.vendor.as_str())).collect();

    let mut hash_bytes = Vec::with_capacity(count);
    for r in records.iter() {
        let bytes = hex::decode(&r.raw_hash)
            .with_context(|| format!("raw_hash for event {} is not valid hex", r.event_id))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "raw_hash for event {} decodes to {} bytes, expected 32 (SHA-256)",
                r.event_id,
                bytes.len()
            );
        }
        hash_bytes.push(bytes);
    }
    let raw_hashes = FixedSizeBinaryArray::try_from_iter(hash_bytes.iter())
        .context("Failed to build FixedSizeBinary(32) raw_hash column")?;

    let schema = log_schema();
    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from(event_ids)),
        Arc::new(UInt64Array::from(block_ids)),
        Arc::new(UInt32Array::from(leaf_indices)),
        Arc::new(Int64Array::from(timestamps)),
        Arc::new(vendors),
        Arc::new(StringArray::from(raw_logs)),
        Arc::new(raw_hashes),
        Arc::new(StringArray::from(ocsf_jsons)),
    ];

    RecordBatch::try_new(schema, columns).context("Failed to construct Arrow RecordBatch")
}

/// Converts an Arrow `RecordBatch` into a list of `StoredLogRecord`.
///
/// Each dieted column is sniffed by physical type from the reader schema: old
/// all-Utf8 blocks take the legacy path, new dieted blocks take the dictionary
/// / binary path. That keeps every tracked fixture readable with no migration.
pub fn batch_to_records(batch: &RecordBatch) -> Result<Vec<StoredLogRecord>> {
    let get_str = |col: usize, name: &str| -> Result<&StringArray> {
        batch
            .column(col)
            .as_any()
            .downcast_ref::<StringArray>()
            .with_context(|| format!("Column {} ({}) is not a Utf8 StringArray", col, name))
    };

    let event_ids = get_str(0, "event_id")?;
    let block_ids = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .context("Column 1 (block_id) is not a UInt64Array")?;
    let leaf_indices = batch
        .column(2)
        .as_any()
        .downcast_ref::<UInt32Array>()
        .context("Column 2 (leaf_index) is not a UInt32Array")?;
    let timestamps = batch
        .column(3)
        .as_any()
        .downcast_ref::<Int64Array>()
        .context("Column 3 (timestamp) is not an Int64Array")?;
    let raw_logs = get_str(5, "raw_log")?;
    let ocsf_jsons = get_str(7, "ocsf_json")?;

    // Vendor: legacy Utf8 blocks vs new Dictionary(_, Utf8) blocks.
    enum VendorCol<'a> {
        Plain(&'a StringArray),
        Dict(&'a DictionaryArray<Int8Type>),
    }
    let vendors = match batch.schema().field(4).data_type() {
        DataType::Utf8 => VendorCol::Plain(get_str(4, "vendor")?),
        DataType::Dictionary(_, _) => VendorCol::Dict(
            batch
                .column(4)
                .as_any()
                .downcast_ref::<DictionaryArray<Int8Type>>()
                .context("Column 4 (vendor) dictionary does not use Int8 keys")?,
        ),
        other => anyhow::bail!("Column 4 (vendor) has unexpected type {:?}", other),
    };
    // raw_hash: legacy hex-Utf8 blocks vs new FixedSizeBinary(32) blocks.
    enum HashCol<'a> {
        Plain(&'a StringArray),
        Binary(&'a FixedSizeBinaryArray),
    }
    let raw_hashes = match batch.schema().field(6).data_type() {
        DataType::Utf8 => HashCol::Plain(get_str(6, "raw_hash")?),
        DataType::FixedSizeBinary(32) => HashCol::Binary(
            batch
                .column(6)
                .as_any()
                .downcast_ref::<FixedSizeBinaryArray>()
                .context("Column 6 (raw_hash) is not a FixedSizeBinaryArray")?,
        ),
        other => anyhow::bail!("Column 6 (raw_hash) has unexpected type {:?}", other),
    };

    let vendor_at = |i: usize| -> Result<String> {
        match &vendors {
            VendorCol::Plain(arr) => Ok(arr.value(i).to_string()),
            VendorCol::Dict(dict) => {
                let values = dict
                    .downcast_dict::<StringArray>()
                    .context("Column 4 (vendor) dictionary values are not Utf8")?;
                let key = dict.keys().value(i) as usize;
                Ok(values.value(key).to_string())
            }
        }
    };
    // Binary hashes re-encode to lowercase hex — the struct's canonical form.
    let hash_at = |i: usize| -> String {
        match &raw_hashes {
            HashCol::Plain(arr) => arr.value(i).to_string(),
            HashCol::Binary(arr) => hex::encode(arr.value(i)),
        }
    };

    let num_rows = batch.num_rows();
    let mut records = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        records.push(StoredLogRecord {
            event_id: event_ids.value(i).to_string(),
            block_id: block_ids.value(i),
            leaf_index: leaf_indices.value(i),
            timestamp: timestamps.value(i),
            vendor: vendor_at(i)?,
            raw_log: raw_logs.value(i).to_string(),
            raw_hash: hash_at(i),
            ocsf_json: ocsf_jsons.value(i).to_string(),
        });
    }

    Ok(records)
}

/// Writes an Arrow `RecordBatch` to an Apache Parquet file using specified compression.
pub fn write_parquet_file(
    path: impl AsRef<Path>,
    batch: &RecordBatch,
    compression: ParquetCompression,
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
    }

    let file =
        File::create(path).with_context(|| format!("Failed to create file at {:?}", path))?;

    let props = WriterProperties::builder()
        .set_compression(compression.into())
        .build();

    let mut writer = ArrowWriter::try_new(file, batch.schema(), Some(props))
        .context("Failed to initialize ArrowWriter")?;

    writer
        .write(batch)
        .context("Failed to write batch to Parquet")?;
    writer.close().context("Failed to close Parquet writer")?;

    Ok(())
}

/// Writes a slice of `StoredLogRecord` directly into a compressed Parquet file.
pub fn write_records_to_parquet(
    path: impl AsRef<Path>,
    records: &[StoredLogRecord],
    compression: ParquetCompression,
) -> Result<()> {
    let batch = records_to_batch(records)?;
    write_parquet_file(path, &batch, compression)
}

/// Reads all records from a Parquet file.
pub fn read_parquet_file(path: impl AsRef<Path>) -> Result<Vec<StoredLogRecord>> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("Failed to open Parquet file at {:?}", path))?;

    let builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .context("Failed to create ParquetRecordBatchReaderBuilder")?;
    let reader = builder
        .build()
        .context("Failed to build ParquetRecordBatchReader")?;

    let mut all_records = Vec::new();
    for maybe_batch in reader {
        let batch = maybe_batch.context("Failed reading record batch from Parquet")?;
        let records = batch_to_records(&batch)?;
        all_records.extend(records);
    }

    Ok(all_records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sample_record(vendor: &str, raw_log: &str) -> StoredLogRecord {
        StoredLogRecord {
            event_id: "0193e0a0-0000-7000-8000-000000000001".to_string(),
            block_id: 7,
            leaf_index: 3,
            timestamp: 1_720_000_000_000,
            vendor: vendor.to_string(),
            raw_log: raw_log.to_string(),
            raw_hash: hex::encode(Sha256::digest(raw_log.as_bytes())),
            ocsf_json: r#"{"activity_id":1}"#.to_string(),
        }
    }

    #[test]
    fn schema_diets_vendor_and_hash_columns() {
        let schema = log_schema();
        assert_eq!(
            schema.field(4).data_type(),
            &DataType::Dictionary(Box::new(DataType::Int8), Box::new(DataType::Utf8))
        );
        assert_eq!(schema.field(6).data_type(), &DataType::FixedSizeBinary(32));
        // Everything else keeps its legacy type.
        assert_eq!(schema.field(0).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(5).data_type(), &DataType::Utf8);
    }

    #[test]
    fn new_block_round_trips_through_dieted_schema() {
        let records = vec![
            sample_record("paloalto", "<14>1 2024-01-01T00:00:00Z fw-01 PAN-OS 1"),
            sample_record("cisco", "<190>Jan  1 00:00:01 asa-01 %ASA-4-106023: deny"),
            sample_record("paloalto", "<14>1 2024-01-01T00:00:02Z fw-01 PAN-OS 2"),
        ];
        let batch = records_to_batch(&records).expect("dieted batch builds");
        assert_eq!(batch.num_rows(), 3);
        let decoded = batch_to_records(&batch).expect("dieted batch decodes");
        assert_eq!(decoded, records);
    }

    #[test]
    fn dieted_block_survives_parquet_file_round_trip() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("block_dieted.parquet");
        let records = vec![
            sample_record("fortigate", "date=2024-01-01 devname=fg-01 action=allow"),
            sample_record("suricata", r#"{"event_type":"alert","src_ip":"10.0.0.1"}"#),
        ];
        write_records_to_parquet(&path, &records, ParquetCompression::Snappy)
            .expect("dieted parquet writes");
        let decoded = read_parquet_file(&path).expect("dieted parquet reads");
        assert_eq!(decoded, records);
    }

    #[test]
    fn tracked_legacy_block_still_reads() {
        // Old all-Utf8 fixture — the new reader must not require a migration.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/parquet/block_00001.parquet");
        let records = read_parquet_file(&path).expect("legacy block reads");
        assert!(!records.is_empty(), "legacy fixture holds records");
        for r in &records {
            assert!(!r.vendor.is_empty());
            // Legacy hex hashes stay 64 lowercase hex chars after the read path.
            assert_eq!(r.raw_hash.len(), 64, "raw_hash stays hex at the boundary");
            assert!(r.raw_hash.bytes().all(|b| b.is_ascii_hexdigit()));
            // Provenance invariant: hash still matches the raw line bytes.
            assert_eq!(
                r.raw_hash,
                hex::encode(Sha256::digest(r.raw_log.as_bytes()))
            );
        }
    }

    #[test]
    fn pathological_vendor_cardinality_errors_instead_of_panicking() {
        // 200 distinct vendors overflows Int8 keys (128 slots) — must be an
        // explanatory error, never an Arrow kernel panic.
        let records: Vec<StoredLogRecord> = (0..200)
            .map(|i| sample_record(&format!("vendor-{i:03}"), "some raw line"))
            .collect();
        let err = records_to_batch(&records).expect_err("must refuse, not panic");
        assert!(err.to_string().contains("distinct vendor"), "got: {err}");
    }

    #[test]
    fn malformed_hash_errors_instead_of_panicking() {
        let mut bad = sample_record("paloalto", "some raw line");
        bad.raw_hash = "not-hex!!".to_string();
        assert!(records_to_batch(std::slice::from_ref(&bad)).is_err());

        let mut short = sample_record("paloalto", "some raw line");
        short.raw_hash = "abcd".to_string(); // valid hex, wrong length
        let err = records_to_batch(std::slice::from_ref(&short)).expect_err("short hash refused");
        assert!(err.to_string().contains("32"), "got: {err}");
    }
}
