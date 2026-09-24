# ULPF Full-Dataset End-to-End Results

**Date:** 2026-09-24 · **Track:** parser-lab (3-Tier Pipeline overhaul, plan P1–P8 complete)
**Scope:** generate a full dataset of proper (clean, unmutated) logs, run the *entire*
system against it — classification → parsing → clustering → evaluation → live
ingest → Merkle/Parquet integrity → tamper detection → air-gapped onboarding —
and report everything honestly, including what the run found wrong.

---

## 1. The dataset

Generated on demand (gitignored, regenerable byte-for-byte):

```bash
python3 scripts/gen_adversarial.py --full 1200   # seed 777, distinct from 1337/9090
```

- **10,799 lines / 9 files / 9.2 MB**, plus an 8-key `gt.jsonl` sidecar (10,799 records).
- Two consecutive runs → **md5-identical** (byte-deterministic).
- The RNG draw sequence is shared with the committed corpora, so adding `--full`
  does not change any committed fixture byte.

| File | Lines | Family / shape mix |
| :--- | ---: | :--- |
| `cisco_asa.log` | 1,200 | Built / Teardown / 106001 / 106007 deny (TCP+UDP) |
| `fortigate.log` | 1,200 | `type="traffic"` accept/deny, `proto=6/17` |
| `paloalto.log` | 1,200 | TRAFFIC start/end/drop CSV rows |
| `suricata.json` | 1,200 | alert / flow / dns EVE JSON |
| `pfsense.log` | 1,200 | filterlog v4 pass/block |
| `cisco_asa_vpn.log` | 1,199 | VPN/AAA verdict phrases (marker-safe) |
| `fortigate_utm.log` | 1,200 | dns / utm / app-ctrl (accept/blocked) |
| `paloalto_threat.log` | 1,200 | THREAT rows (deny/drop/start) |
| `pfsense_ipv6.log` | 1,200 | filterlog v6 (Netgate BNF layout) |

---

## 2. Evaluation on the full dataset

```bash
./target/release/ulpf evaluate --corpus core --data-dir data/raw/full \
  --engine all --duration 3 --threads 16 --samples 10000 \
  --out eval_full_report.md --audit-dump audit_full_dump.jsonl
```

`--corpus core` now loads `data/raw/full/gt.jsonl` when present, so all grading is
**sidecar-authoritative** (10,799 overrides). Full table in `eval_full_report.md`.

| Metric | Baseline | 3-Tier | Verdict |
| :--- | ---: | ---: | :--- |
| VCA | 100.00% | 100.00% | parity |
| GA (grouping) | 100.00% | 100.00% | ≥ baseline |
| TA (template) | 100.00% | 100.00% | ceiling both |
| Macro F1 (src/dst/port/proto) | 100.00% | 100.00% | exact |
| Disposition | 100.00% | 100.00% | exact |
| Action Inviolability | N/A | **100% preserved** | invariant held |
| Lossless SHA-256 | 10799/10799 | 10799/10799 | byte-exact |
| Recognized / no-panic | 10799/10799 | 10799/10799 | zero aborts |
| **Audit dump** | 0 | **0** | every line clean |
| Sidecar GT fields | 48000 correct / **0 wrong** / 5995 null | same | exact |
| p50 / p99 / p99.9 (µs) | 76.28 / 121.03 / 160.34 | **2.46 / 6.81 / 13.17** | −96.8% / −94.4% / −91.8% |
| Unique templates | 8056 | **32** | **252× compression**, strict < |

---

## 3. What the run found (and the fixes, dump-driven)

The first full run was **not** clean: dump = 1,440 records, F1 = 98.67,
sidecar wrong = 1,803. Both engines failed identically → shared-extractor or
ground-truth issues, exactly what the audit harness exists for.

### Finding 1 — ASA 106007 “dropped by access-list” lost all five fields (engine bug)

`%ASA-4-106007: dropped UDP from <ip>/<port> to <ip>/<port>, access-list … denied …`
does not match `REGEX_DENIED_CONN` (needs the literal `… connection denied from …`
phrasing) and fell through to `fallback_parse`, which emits **default endpoints** —
so a line embedding src/dst/ports/protocol graded `null`. This alone was
240 lines × 3 field-audit misses × 2 engines = **1,440 dump records**.

- **TDD:** `test_asa_106007_dropped_by_access_list_endpoints` RED
  (`None != Some("192.0.2.38")`) → new `REGEX_DROPPED_ACL` branch in the
  `106001|106006|106007` arm → GREEN; sibling 106001 shape pinned against regression.
- Direction stays `None` (no direction word in the raw — honest null, never fabricated).
- **Effect:** full dump 1,440 → **0**, F1 98.67 → **100.00**. Adversarial corpus
  benefits too: dump 544 → **382**, F1 95.01 → **97.15** (mutated 106007 lines recover).

### Finding 2 — the generator’s FortiGate sidecar contradicted its own raw (GT bug)

The new `gt_wrong_by_key` diagnostic row (added to the §1b scorecard) localized all
remaining 603 wrongs to one key: **`protocol`**, split `fgt-dns 245, fgt-utm 246,
fgt-app-ctrl 112` ≈ 50% each. Cause: `fgt_kv()` writes a *random* `proto=6|17`
into the line but hardcoded `proto_gt` ("udp" for dns, "tcp" otherwise), so the
sidecar contradicted its own line ~half the time. **The engine was reading the line
correctly; the sidecar was wrong.**

- **Fix:** `proto_gt = proto[1]` for every FortiGate type (raw is authoritative;
  RNG sequence untouched → no committed log byte changes).
- **Effect:** full sidecar wrong 603 → **0** (48000/48000 correct); adversarial
  wrongs 1643 → **1524** (the residual = mutation damage by design:
  `src_ip 679, dst_ip 556, protocol 203, src_port 43, dst_port 43` — encoding/
  truncation/field-damage classes, graded honestly as contradicted).
- New hermetic test `test_full_dataset_protocol_parity_when_generated` pins
  line-vs-sidecar protocol parity whenever `data/raw/full/` exists (skips otherwise).

**After both fixes: full dump 0, all metrics 100.00/100.00, 48000/48000 sidecar
fields correct, p50 2.46 µs.**

---

## 4. Live pipeline: ingest → OCSF → RFC 6962 → Parquet

```bash
ulpf ingest --udp 127.0.0.1:5141 --tcp 127.0.0.1:5142 \
  --parquet-dir data/full_out/parquet --ledger data/full_out/ledger.jsonl \
  --batch-size 1000 --batch-timeout 1000 &
# five per-family blasts (ulpf-generator --rate 1200 --duration 1 …)
```

| Stage | Result |
| :--- | :--- |
| Events received → normalized | **8,016 → 8,016 (100%)**, sender errors 0 |
| Throughput (displayed peak) | **1,703 EPS** on this machine during blast |
| Drain3 structural novelty alerts | 34 (first-sight cluster events — alerts, not errors) |
| Merkle blocks anchored | **8** (1,000 events/batch trigger) |
| Ledger entries | **8** (`data/full_out/ledger.jsonl`) |
| `ulpf inspect` | UUIDv7 + leaf index + SHA-256 + lossless raw + OCSF endpoints all present |
| `ulpf verify` on all 8 blocks | **8 PASS / 0 FAIL** |
| `ulpf tamper` (leaf 0 → `10.99.99.99`) | detected: `DigestMismatch` stored `8da2c102…` vs calculated `f9629a67…`, verdict **“integrity is broken — fabricated evidence rejected”** |
| Control: untouched `block_00001` | still **PASS** after the attack |

Notes: `--dataset all` in `ulpf-generator` hard-requires `kaggle_firewall.csv`
(absent from the full corpus) — per-family `-D` blasts were used instead.
`verify` prints the forensic verdict but exits 0 either way (automation caveat,
see §6).

---

## 5. Air-gapped onboarding of a brand-new format

4 samples of an invented `PORTSEC` switch format (holdout untouched — freeze respected):

- Synthesis **2.48 ms**, validation **100% (4/4)**, confidence 1.0.
- Exported `campus_switch.json` + `.yaml` with 14 action-mapping verbs.
- First sample normalized to OCSF 1.3: `src 10.20.30.14 → dst 198.51.100.20`.
- Learned quirks, documented: a field **constant across all samples** (first attempt
  used the same `dst`) is generalized to a literal instead of a capture group —
  vary every field you want captured; with no transport port in the format, the
  `vlan` number was captured as `src_port` (honest mislabel for a portless format).

---

## 6. Gates & final state

- Verification gate: **clippy 0 / fmt clean / 95 passed + 1 ignored**
  (holdout remains frozen; not regenerated, not re-run post-freeze).
- Committed corpora re-validated after the sidecar fix:
  core **dump 0, all-100, p50 3.30 µs**; adversarial **Action Inviolability 100%,
  GA 98.41 vs baseline 100** (12 `panos_threat` relay/encoding grouping failures,
  deny-class only — zero ALLOW/DENY mixing); holdout **untouched**.
- Everything deterministic: dataset md5-stable across double runs; audits
  (`audit*_dump.jsonl`) gitignored; `data/raw/full/` + `data/full_out/` gitignored.

### Honest limitations

1. `ulpf verify` exit code does not encode failure — detection lives in the
   printed verdict (scripts must grep, not `if verify`).
2. Onboarder portless formats: no `port` token ⇒ a numeric token (`vlan`) gets
   captured as `src_port`.
3. `ulpf-generator --dataset all` requires `kaggle_firewall.csv` to exist.
4. UDP ingest trusts the loopback blast (0 errors observed here); production
   feeds should size the socket buffer for line rate.
5. Full dataset is generated-on-demand, not committed (9.2 MB ≫ ~1 MB fixture budget).

---

## Appendix — exact command sequence

```bash
python3 scripts/gen_adversarial.py --full 1200        # dataset (seed 777, deterministic)

# Evaluation (release build, repo root cwd)
./target/release/ulpf evaluate --corpus core --data-dir data/raw/full --engine all \
  --duration 3 --threads 16 --samples 10000 \
  --out eval_full_report.md --audit-dump audit_full_dump.jsonl

# Live integrity chain (outputs under data/full_out/, never the tracked fixtures)
./target/release/ulpf ingest --udp 127.0.0.1:5141 --tcp 127.0.0.1:5142 \
  --parquet-dir data/full_out/parquet --ledger data/full_out/ledger.jsonl \
  --batch-size 1000 --batch-timeout 1000 &
for d in cisco fortigate paloalto suricata pfsense; do
  ./target/release/ulpf-generator --target 127.0.0.1:5141 --proto udp \
    --rate 1200 --duration 1 -D "$d" --data-dir data/raw/full
done
./target/release/ulpf inspect --file data/full_out/parquet/block_00000.parquet --count 1
for b in data/full_out/parquet/*.parquet; do
  ./target/release/ulpf verify --file "$b" --ledger data/full_out/ledger.jsonl
done
./target/release/ulpf tamper --file data/full_out/parquet/block_00000.parquet --leaf 0 --ip 10.99.99.99
./target/release/ulpf verify --file data/full_out/parquet/block_00000.parquet \
  --ledger data/full_out/ledger.jsonl          # -> DigestMismatch detected

# Air-gapped onboarding
./target/release/ulpf onboard --sample data/full_out/onboard_sample.log \
  --vendor campus_switch --model portsec --out data/full_out/parsers
```
