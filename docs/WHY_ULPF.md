# Why ULPF — the problem, the field, one real line end to end

> Moved from README §2 during the README slim-down (nothing deleted; the
> README keeps a short summary and links here).

Modern perimeters mix Cisco ASA, Fortinet FortiGate, Palo Alto PAN-OS, pfSense and Suricata — each emitting a different syntax (RFC 3164 Syslog, EVE JSON, CSV, key-value, CEF). Traditional pipelines fail in three ways:

1. **The context-switching wall** — Python/Java log shippers bounce every line through 7–10 interpreter stages; throughput collapses under attack traffic exactly when you need it.
2. **The "hash vault" forensic illusion** — storing `SHA-256(event)` per row proves nothing about the *stream*: an attacker with root silently deletes rows and no cross-record link breaks, because none exists.
3. **Proprietary schema lock-in** — ad-hoc vendor schemas don't interoperate with SIEMs or data lakes.

How the common shippers handle those same three problems, from their own documentation. This is an architectural comparison, not a benchmark run (measured numbers are in the README's headline results):

| | Runtime footprint | Normalization | Stream-level provenance | Air-gapped install |
| :--- | :--- | :--- | :---: | :---: |
| **Logstash** (Elastic, JVM) | JVM heap — typically hundreds of MB to GB | hand-written `grok` patterns | none | no: plugin installs pull from the internet |
| **Fluentd** | Ruby + native C, ~100 MB class | hand-written filter plugins | none | no: `gem install` pulls from the internet |
| **Splunk Universal Forwarder** | proprietary agent | Splunk CIM, paid license | none | partial: offline package, licensed |
| **ULPF** (this repo) | single **18.6 MB** static Rust binary | OCSF 1.3, automatic (zero-copy extractors + Drain) | yes: RFC 6962 Merkle root → append-only ledger → Parquet WORM, exit-code audit | yes: zero network calls by design |

ULPF answers all three: **Rust zero-copy hot path** (slices `&[u8]`, no per-packet allocation), **RFC 6962 Merkle chaining** (deleting or editing *any* byte of *any* row breaks a verifiable root anchored in an append-only ledger), and **OCSF 1.3 normalization** as the single output schema.

## Format & vendor support matrix

Transcribed from the `VendorFormat` enum and prefix table in [`crates/ulpf-core/src/parser/classifier.rs`](../crates/ulpf-core/src/parser/classifier.rs) and the extractors in [`crates/ulpf-core/src/parser/extractors/`](../crates/ulpf-core/src/parser/extractors/):

| Wire format | Identified by (Aho-Corasick prefix) | Zero-copy extractor | Status |
| :--- | :--- | :--- | :---: |
| RFC 3164 syslog — **Cisco ASA** | `%ASA-` | `cisco_asa.rs` | supported |
| key-value syslog — **FortiGate** | `devname="` · `type="traffic"` · `logid="` | `fortigate.rs` | supported |
| CSV syslog — **Palo Alto PAN-OS** | `,TRAFFIC,` · `,THREAT,` · `,SYSTEM,` · `PAN-OS` | `paloalto.rs` | supported |
| EVE JSON — **Suricata** | `{"timestamp":` · `"event_type":` · `"flow":` · `"alert":` | `suricata.rs` | supported |
| filterlog — **pfSense** | `filterlog[` · `filterlog:` | `pfsense.rs` | supported |
| **CEF** envelope (vendor-neutral) | `CEF:` | `cef.rs` | supported |
| LEEF · generic `key=value` · flat JSON · XML · RFC 5424 (structured data) | — | — | planned, P10.1 (README roadmap) |
| anything else | — | generic fallback event — vendor `Unknown`, **never silently dropped** | by design |

About 10 more vendors (ISRO-relevant) are planned for P10.2 (README roadmap). You do not have to wait for that code: `ulpf onboard` synthesises and validates a parser from 3–5 sample lines, fully offline (README quick start, step 7).

## One real line, end to end

Every number in the README traces back to stored records. Here is one of them, copied verbatim from [`data/raw/cisco_asa.log`](../data/raw/cisco_asa.log) line 218:

**Input.** These exact bytes are what lands in the `raw_log` column, byte for byte:

```text
<166>Sep 21 14:07:15 asa-vpn-gw01 %ASA-6-302013: Built inbound TCP connection 1004583 for outside:203.0.113.57/80 (203.0.113.57/80) to inside:10.1.13.22/57911 (198.51.100.208/57911)
```

**Output.** The OCSF event stored in `data/parquet/block_00001.parquet` (it is written compact in the `ocsf_json` column; pretty-printed here):

```json
{
  "activity_id": 1,
  "activity_name": "Open",
  "category_uid": 4,
  "class_uid": 4001,
  "type_uid": 400101,
  "time": 1789984478068,
  "disposition": "Allowed",
  "src_endpoint": { "ip": "203.0.113.57", "port": 80, "interface": "outside" },
  "dst_endpoint": { "ip": "10.1.13.22", "port": 57911, "interface": "inside" },
  "connection_info": { "protocol_num": 6, "protocol_name": "TCP", "direction": "Inbound" },
  "metadata": {
    "product": { "vendor_name": "Cisco", "name": "ASA" },
    "raw_data": "<166>Sep 21 14:07:15 asa-vpn-gw01 %ASA-6-302013: Built inbound TCP connection 1004583 for outside:203.0.113.57/80 (203.0.113.57/80) to inside:10.1.13.22/57911 (198.51.100.208/57911)",
    "raw_hash": "167c1cec8f420d1e4700a7cbe588e0b335efabcfc4a16b59cf391497a13755fd",
    "event_id": "01a0c363-9374-7525-b61d-f7a11e05cca9",
    "ingest_time": 1789984478068
  },
  "unmapped": { "connection_id": "1004583", "cisco_severity": "6", "cisco_message_code": "302013" }
}
```

What to notice:

- `metadata.raw_data` is the input, byte for byte, and `metadata.raw_hash` is its SHA-256. Verify it yourself: `printf '%s' '<input above>' | sha256sum` prints `167c1cec…55fd`, which matches.
- The vendor line `%ASA-6-302013` ("Built") maps to OCSF vocabulary: `disposition: "Allowed"`, `activity_name: "Open"`, endpoints and direction in canonical fields. Vendor-specific leftovers (`connection_id`, `cisco_message_code`) are kept under `unmapped` instead of being thrown away.
- Reproduce on any stored record: `./target/release/ulpf inspect --file data/parquet/block_00001.parquet --count 1` (README quick start, step 6).
