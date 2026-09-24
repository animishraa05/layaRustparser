# ULPF 3-Tier Pipeline Overhaul — Master Plan (parser-lab track)

**Track:** `/home/ani/parser-lab` (independent fork of `/home/ani/parser` @ `9d11d2a`)
**Strategy:** Full v3 spine + corpus ownership. Byte-identical fork point; every claim below is
either (a) verified against source with `file:line` evidence, or (b) explicitly flagged as a
hypothesis to be settled by the mismatch dump before any tuning.
**Counterpart:** the original `/home/ani/parser` folder is executing a sibling plan. Neither
folder may be read from or written to by the other until the end-of-race comparison.

---

## 0. Non-negotiable invariants (from AGENTS.md — survive this overhaul)

1. **Air-gapped:** zero runtime network calls. Dataset downloads are dev-time scripts only.
2. **Lossless provenance:** raw line byte-for-byte in `raw_log`, `raw_hash` = SHA-256(raw),
   UUIDv7 event IDs. Never truncate/re-encode input.
3. **Action inviolability:** ALLOW/PERMIT/ACCEPT must never merge into one template cluster with
   DENY/DROP/BLOCK/REJECT. Enforced in `crates/ulpf-ai/src/drain.rs`, tested by
   `crates/ulpf-ai/tests/ai_tests.rs::test_drain_unique_event_patterns_anchor_tokens`.
   **This overhaul extends, never weakens, that enforcement (see P6.1 — verified kv gap).**
4. **Zero-copy hot path:** `&[u8]`/`&str` slices; no `to_string()`/`format!` per-packet.
5. **Tier-3 out-of-band:** novel-cluster triage over bounded `crossbeam-channel`s, never blocking
   line-rate ingest.
6. **No ML/LLMs anywhere.** Deterministic logic only.

## 1. Repo map (verified)

| Crate | Overhaul-relevant contents |
|---|---|
| `crates/ulpf-core` | `parser/classifier.rs` (Aho-Corasick `VendorFormat`), `parser/mod.rs` (`UniversalParser` = baseline engine), `parser/lru_cache.rs`, `parser/extractors/{cisco_asa,fortigate,paloalto,pfsense,suricata,mod}.rs`, `schema/ocsf.rs` |
| `crates/ulpf-ai` | `drain.rs` (`DrainMiner`), `pipeline.rs` (`TieredPipeline`), `laya.rs` (`LayaDecisionEngine`), `onboarder.rs` (`Onboarder`, `DynamicParserRegistry`), `evaluator.rs` (accuracy audit + benchmarks) |
| `crates/ulpf-cli` | `main.rs` subcommands; **gotcha:** `evaluate|benchmark` panic in debug builds (clap duplicate `-d`) — always release |
| `crates/ulpf-integrity` | untouched by this plan |
| `crates/ulpf-generator` | traffic blaster; untouched except corpus load additions later if needed |

**Baseline vs 3-Tier structure (critical for interpreting every metric):**
`TieredPipeline = UniversalParser (the baseline) + Tier-1 LRU + Tier-2 Drain + Tier-3 Laya`.
Field extraction is **shared code**. Therefore:

- VCA / field-F1 / protocol / disposition for the two engines **move together** on any extractor
  or ground-truth change — a tie is *expected and correct* on shared known logs.
- The engines can only differ on: **GA/TA (Tier-2 clustering)**, novel-template discovery,
  onboarding count, and (after P3) any Tier-3-only dynamic-parser paths.
- Any success claim must respect this; "strictly wins on fields" would indicate a bug, not a win.

## 2. Diagnosis — every metric bug, with evidence

### 2.1 VCA = 78.00% is a label bug, exactly
- `evaluator.rs:1080-1081`: `parsed_vendor.contains(&expected_vendor) || expected_vendor.contains(...)`
- Suricata extractor emits `Product::new("OISF", …)` → vendor `oisf`; GT expects `suricata` →
  fails both directions. pfSense emits `Netgate` vs GT `pfSense`.
- Audit does `corpus.iter().take(1000)`: 260 ASA + 260 FGT + 260 PAN + 220 Suricata = 1000
  (**all pfSense excluded**, 40 Suricata unsampled). All 220 audited Suricata fail →
  **780/1000 = 78.00%** — reproduces the report exactly.
- Expanding audit to 1300 **without** the label map → 780/1300 = **60.00%**. The map is a hard
  prerequisite of full-audit coverage (ordering inside P1 is mandatory).

### 2.2 Protocol ≈70.3% is auditor punishing correct IANA mapping
- Audit: `raw.to_ascii_uppercase().contains(proto_name)`. FortiGate kv lines carry `proto=17`;
  extractor correctly maps 17→UDP; raw contains "17", not "UDP" → counted wrong (208 kv records
  at risk). The 52 CEF lines classify `Unknown` → protocol `None` → wrong.
- Fix: numeric-equivalence check using the IANA tables already in `extractors/mod.rs`
  (`protocol_num_from_name` / `protocol_name_from_num`), full table — not hardcoded 6/17 only.

### 2.3 Disposition ≈71.8% is a GT vocabulary error + unparseable lines
- GT maps `Deny/deny → "Dropped"`; extractors map deny → `BLOCKED`. **Extractors are right:**
  OCSF `disposition_id`: `1 Allowed, 2 Blocked`; `schema/ocsf.rs` follows it. GT must change to
  `deny → Blocked`, strict equality kept (no Blocked/Dropped interchange — that weakens the ruler).
- FGT session-end actions with **no GT rule** → GT `None`; `timeout` parses to `Unknown` → wrong:
  `timeout×43, close×23, client-rst×40, server-rst×43` (kv) + CEF `act=timeout/close/...`.
  OCSF-correct: session ended = `disposition Allowed` (if not denied) + `activity CLOSE`.
- CEF lines → no extractor → `Unknown` → wrong whenever GT is `None`. Fixed by P4.

### 2.4 Two fake metrics
- **TA:** `template.contains("<*>") || !template.is_empty()` — the second clause is true for any
  non-empty template → TA ≡ 100% mathematically. Replace with exact token-sequence match against
  the GT template (Token-F1 = 1.0 required; no tunable threshold).
- **Baseline GA:** baseline `cluster_fn` hashes the *ground-truth template* → oracle, ~100% by
  construction. Replace with **exact post-mask skeleton hash** ("naive exact-match baseline");
  keep the GT-hash variant but re-label output as **"oracle ceiling"**.

### 2.5 GA metric pathology (drives the honest success bar)
GA = majority-vote purity = `Σ max_tag|cluster∩tag| / N`.
- **Over-splitting is never penalized:** singleton-per-line partition scores GA = 100.0.
- Exact-mask baseline on clean corpus ≈ GT-optimal → GA ≈ 100 → Drain (96 today) can **tie at
  best, never strictly win**; a coarser baseline would make "Drain wins" trivial/strawman.
- Therefore Drain's genuine win lives in **TA + template count + cache-hit** (generalization under
  messy values where exact-match fragments), while GA is a **non-regression** bar (≥ baseline).
  Success criteria below are written accordingly.

### 2.6 Tier-3 is dead in practice
- Triage worker sends **1 exemplar** per novel cluster; `Onboarder::generate_parser` errors when
  samples < 3 → permanent `Err` → `tier3_auto_onboarded_count` is always 0. ("Deadlock" in the
  sibling spec — it's a silent logic failure, fix is an accumulator.)
- `DynamicParserRegistry` receives `register()` but **nothing ever queries it** — dead end.
- `classify_action` / `score_threat_risk` outputs are discarded (`let _`).

### 2.7 Verified kv anchor gap (new find, confirmed at code level)
- `drain.rs:315` tokenizes via `split_whitespace()` → `action="allow"` is **one token**.
- Anchor check `drain.rs:444-447`: compares `t1_upper` against bare list (`ALLOW`, `DENY`, …);
  `ACTION="ALLOW"` never equals `ALLOW` → **anchor never fires on kv-format logs.**
- Consequences: (a) real `allow`/`deny` FGT lines can merge → Action Inviolability violated in
  production data; (b) **GA can't detect it** — all FGT lines share GT tag `fortigate_traffic`;
  (c) the inviolability test evidently feeds bare tokens → passes while real kv lines break.
- Edge case during fix: if the masker strips quoted values first, both sides become
  `action=<*>` and merge *silently with the action already gone*. Anchor must evaluate the kv
  value **pre-mask** (or store protected tokens).

### 2.8 Field-accuracy holes (shared extractor — fixes raise both engines, by design)
- ASA **113019** (37 records) has no branch in `cisco_asa.rs` (handled: `302013|302015|302020`,
  `302014|302016|302021`, `106023`, `106001|106006|106007`) → lossless fallback → `None` fields.
- PAN ICMP lines: `get(24)/get(25)` parse "0" → `port: Some(0)`; OCSF-correct is `None`
  (audit's `1..=65535` rejects 0 — correct rejection of wrong data; fix the emission).
- src/dst role swaps are **invisible** to the audit (`raw.contains(ip)` matches either role) —
  documented blind spot; role-aware audit deferred, no claim depends on it in this race.

### 2.9 Report fabrication
`evaluator.rs` report hardcodes `tier2_clusters_count: 12` and `tier2_unique_anchor_enforced:
true` — replace with computed values.

### 2.10 Corpus is self-generated happy-path (train=test)
`scripts/populate_datasets.py`: `random.seed(42)`, round-robin `m_type = i % 7`, fixed doc-range
IP pools, fixed port list — every line the generator can emit, the eval sees. Corpus inventory
(260 lines each): ASA 7 codes (302013×38, 302014/15/16/106023/106001/113019 ×37), FGT
(52 CEF + 208 kv; actions accept31/close23/deny28/timeout43/client-rst40/server-rst43), PAN
(subtype deny55/drop66/end74/start65; action allow139/deny49/drop72), Suricata
(alert87/dns86/flow87), pfSense (block129/pass131). Zero truncation, zero encoding mess, zero
relay prefixes, zero unseen vendors. → P7.

## 3. Execution phases

> **Gate before every commit (verbatim from AGENTS.md — there is no CI):**
> ```bash
> cargo clippy --workspace --all-targets -- -A clippy::too_many_arguments -A clippy::field_reassign_with_default -D warnings
> cargo fmt --all -- --check
> cargo test --workspace        # 56 tests today; ~40s
> ```
> Known flaky under load: `ulpf-core/tests/parser_tests.rs::test_classification_sub_microsecond_benchmark` —
> re-run before assuming regression. `evaluate|benchmark` require `--release` (clap `-d` clash).

### P1 — Measurement first (rulers before engines)
**Files:** `crates/ulpf-ai/src/evaluator.rs` only.

1. **Vendor label map** (must land *with* or *before* item 3): explicit match table —
   `oisf → Suricata`, `netgate → pfSense` — applied GT-side before the `contains` check at
   :1080. Not fuzzy/edit-distance; a wrong vendor must never pass.
2. **TA rewrite:** exact token-sequence match of produced template vs GT template
   (Token-F1 = 1.0; whitespace-normalized; no threshold constant).
3. **Audit coverage:** `audit_count = 1000.min(...)` → `corpus.len()` (1300). Include all pfSense.
4. **Baseline GA decoupling:** replace GT-hash `cluster_fn` with exact post-mask-skeleton hash;
   label it in the report as `baseline (naive exact-match)`; re-label existing GT-hash column
   `oracle ceiling`.
5. **`--audit-dump <path>` flag:** JSONL of every failing record per metric
   `{engine, metric, raw, gt, parsed, cluster_id, gt_tag}`. This is the *dependency* for P6.
6. **Telemetry:** compute real cluster count / anchor-enforcement status; delete the two constants.
7. **Protocol audit:** numeric equivalence via IANA tables (full table: GRE 47, ESP 50, …).
8. **Disposition GT:** `deny/block → Blocked` (OCSF ID 2), strict equality; FGT
   `close/timeout/client-rst/server-rst → Allowed + CLOSE` (matches extractor changes in P2/P4).

**Expected post-P1 (both engines equally):** VCA → 100.00 (1300/1300), protocol ≈ 90+,
disposition ≈ 88–92, TA drops from fake 100 to a real number (honest dip — expected).
**Tests:** add unit tests for GT-label map, protocol equivalence, disposition GT cases.

### P2 — Extractor fixes + safe Tier-3 logic
**Files:** `extractors/cisco_asa.rs`, `extractors/fortigate.rs`, `extractors/paloalto.rs`,
`onboarder.rs`, `laya.rs`, `pipeline.rs`.

1. **ASA 113019 branch** (37 records → real fields; inspect corpus samples for exact structure
   before writing the regex; map to OCSF per its real semantics).
2. **ICMP ports → `None`** (PAN `get(24)/get(25)`: skip when proto is ICMP; FGT `proto=1`
   icmp path; ASA if applicable). Engine-side, never evaluator-side.
3. **FGT session-end disposition:** `timeout/close/client-rst/server-rst → ALLOWED` +
   `activity_id::CLOSE` in `fortigate.rs` (CEF `act=` equivalent in P4).
4. **3-exemplar accumulator** in the triage worker: buffer `AsyncTriageTask` per `cluster_id`
   in a map; only call `Onboarder::generate_parser` at ≥3 samples; keep channel bounded —
   buffer must not grow unbounded (cap per-cluster buffer, e.g. 8, drop extras).
5. **Onboarder hardening (verified fixes):** stop naming 3rd+ numeric group `(?P<dst_port>)`
   (duplicate-name regex compile failure); `synthesize_kv_regex` handles quoted values and
   key aliases; `Ipv4Addr::from_str → IpAddr::from_str` for IPv6.
6. **Laya priors:** `VendorPrior { fingerprint: 10.0, structural: 4.0 }` replacing flat +2.5 —
   fingerprint = exact `CEF:`, `%ASA-`, `logid="`, `devname=`-class tokens; structural = weak
   cues. Keep the ≥0.85 gate.
7. **Wire discarded heads:** `classify_action` / `score_threat_risk` results attach to triage
   outcome flags (feeds P8 adjudication metrics).
**Tests:** 113019 samples, ICMP-None cases, accumulator reaches 3 and succeeds / caps at 8,
kv-regex compiles with quoted action, IPv6 validation.

### P3 — Hot-path wiring (poisoning-safe)
**Files:** `pipeline.rs`, `onboarder.rs` (`DynamicParserRegistry`).

1. **ValidationReport gate:** registration into the registry only if
   `ValidationReport.passed && match_percentage == 100.0`. One bad draft must never parse again.
2. **Pinned order on Tier-1 miss:** native extractor → `dynamic_registry.parse_any(raw)` →
   `parse_lossless`. Native always wins for known formats; registry handles unknown shapes only.
3. **Registry bound:** capacity limit (e.g. 256 entries) + eviction (LRU by last-use) — no
   unbounded regex memory.
4. **LRU promotion:** successful registry parse → insert into `parser.cache` under the line's
   masked signature → future same-shape lines skip registry *and* Drain mutex.
5. **Differential regression test (success-criterion-1 instrument):** for every corpus line where
   the native extractor fires, assert baseline `parse(raw)` and `tiered.process(raw)` produce
   **identical OCSF output modulo `event_id`/`ingest_time`**. Byte-exactness beats aggregate F1
   ties at catching wiring regressions.
**Perf check:** registry lookup runs only on native-miss lines (unknown-heavy worst case) —
measure with P7 adversarial stream; expected cost bounded by capacity×single regex test.

### P4 — Standalone CEF extractor
**Files:** NEW `extractors/cef.rs`; `extractors/mod.rs`; `classifier.rs` (register `CEF:0|`
prefix → new `VendorFormat::CEF` or route-by-header); `parser/mod.rs` dispatch.

1. Parse header `CEF:Version|Vendor|Product|Version|SigID|Name|Severity|` (pipe-escaped),
   then extension kv: `src, dst, spt, dpt, proto, act, in, out, app, ...` per CEF spec.
2. **Vendor from Header Field 2** — VCA correct for *any* vendor's CEF (Cisco/PAN/…), not just
   the 52 Fortinet lines. Product from field 3.
3. OCSF mapping: `act=accept/allow → Allowed`, `deny/blocked → Blocked`, `drop → Dropped`,
   `close/timeout → Allowed+CLOSE`; `proto` numeric via IANA table; ICMP → ports None.
4. Wrap dispatch: syslog-prefixed CEF (`<PRI>... CEF:0|...`) must strip prefix first (corpus
   lines carry `<134>`-style prefixes).
**Tests:** the 52 corpus CEF lines parse with non-null src/dst/proto; vendor = header vendor;
synthetic Cisco-CEF line classifies as Cisco (regression for the Fortinet-hardcode trap).

### P5 — Strict evaluator rules
**Files:** `evaluator.rs` (items not already done in P1.7/P1.8). If done in P1, this phase is a
no-op checkpoint — the point is *all* GT/audit changes precede any Tier-2 tuning.
- deny→Blocked strict; full IANA; ICMP None audited as correct (`None` on ICMP = pass).
- Success-criteria labels updated in report generation (see §5).

### P6 — Tier-2 Drain changes (sequential, gated, dump-driven)
**Files:** `drain.rs`, `tests/ai_tests.rs`.

Order is deliberate — cheapest/highest-confidence first, each with a full gate run:

1. **KV anchor fix (verified bug — do first):** during `compute_similarity`, normalize each
   token before anchor comparison: if token matches `key="value"`/`key=value` shape, also test
   the value part (and/or strip key prefix) against `unique_anchor_tokens`. Pre-mask values so
   the masker can't erase the anchor. **Expand
   `test_drain_unique_event_patterns_anchor_tokens` with kv-format cases**
   (`action="allow"` vs `action="deny"` must land in different clusters; real FGT corpus lines
   as fixtures). Extend default anchor list with lifecycle verbs:
   `BUILT, TEARDOWN, CLOSE, RESET, RST, CLOSED` (covers 302013↔302014 merge hypothesis).
   *Gate:* full tests; GA from `--audit-dump` must not drop.
2. **Masker upgrade:** IPv6, MAC, ISO/syslog/epoch timestamps, pure numbers — added patterns
   must not swallow kv keys or syslog tag (`%ASA-6-302013:` protection must survive).
   *Gate:* tests + `p50 < 5.0 µs` + GA non-regression + TA delta reported.
3. **Dual-branch prefix search:** candidates from exact-token *and* wildcard branches.
   *Gate:* same as (2). Watch: more candidates → higher merge propensity → run kv-anchor test.
4. **Bi-directional wildcard similarity:** `<*>` vs literal counts as match. Inflates sim →
   compensating threshold review **only after** `--audit-dump` analysis. Never tune blind.
5. **`similarity_threshold`:** current value stays unless the dump shows under-merging
   (too many templates). If changed (candidate 0.60), one step at a time with GA/TA/latency
   recorded before/after.
**Hard rules:** Action Inviolability test green after *every* step; if GA drops after (3)/(4),
   suspect anchor coverage first (safety net), not threshold.

### P7 — Corpora (our lane; sibling marked this "future")
**Files:** NEW `scripts/gen_adversarial.py`, `scripts/fetch_external.sh`,
`evaluator.rs --corpus`, `.gitignore` negations.

1. **Adversarial generator** (deterministic seed ≠ 42) → `data/raw/adversarial/` + sidecar GT
   JSONL `{"raw", "gt_vendor", "gt_template_tag", "gt_fields", "gt_disposition",
   "gt_protocol", "difficulty", "origin"}`. Mutations applied to expanded templates:
   - truncation at 512/1024/2048 bytes mid-token
   - relay artifacts: double syslog prefixes, missing `<PRI>`, `Oct  5` double-space
   - encoding: UTF-8 names, mojibake, BOM, CRLF
   - field damage: unclosed quotes, short PAN CSV, broken JSON, `proto=47`, port `0`, IPv6,
     epoch/millis timestamps
   - high-cardinality: long URLs, hashes, session IDs (stresses LRU hit rate + Drain mutex)
2. **Vendor-doc format expansion:** more ASA codes (incl. VPN/AAA), FGT logids (utm/dns/app-ctrl),
   PAN subtypes (threat/urlfilter), pfSense IPv6 — generated *with* GT.
3. **Novel-vendor holdout (frozen):** 2–3 never-seen formats (MikroTik-style, Juniper SRX-style,
   one fictitious vendor) in `data/raw/holdout/`, **separate seed, not executed until final
   freeze.** Tests classifier novelty path → registry → onboarding end-to-end.
4. **`fetch_external.sh`** (dev-time only; license notes; gitignored `data/external/`; never
   committed): LogHub (comparability), vendor-doc references (format matrices). Note: downloaded
   data has **no field GT** → coverage/robustness metrics only, never accuracy claims.
5. **Evaluator `--corpus core|adversarial|holdout|all`** → separate scorecard sections +
   robustness block: parse-success %, no-panic %, lossless %, **null-vs-wrong discipline**
   (any non-null field failing GT counts worse than null), p99 latency under cardinality.
6. **`.gitignore`:** `*.log` is ignored except `data/raw/*` — new dirs need explicit negation
   rules; sidecars `.jsonl` fine. Keep total committed corpus < ~1 MB.

### P8 — Final scorecard & merge prep
- Run identical commands in both folders; produce three-column comparison
  (core / adversarial / holdout) × two engines (baseline / 3-tier).
- `git diff --no-index /home/ani/parser /home/ani/parser-lab` for code-level attribution.
- Per-phase merge recommendations (their micro-fixes vs our rulers/corpus); Tier-2 algorithm
  choices decided by measured deltas only.
- Regenerate `eval_hardcore_report.md` (tracked; expect diff).

## 4. Throughput measurement (half the stated goal — currently unmeasured)
- Before/after EPS + p50/p99 on **identical corpus, release build, same threads**:
  `./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out eval_hardcore_report.md`
- Report baseline-EPS vs tiered-EPS delta explicitly; the P3 LRU promotion is the expected lever
  (fewer Drain-mutex entries), the P6 masker/dual-branch are expected *costs* — both must show.
- No fabricated targets (the sibling plan's "3.2M EPS / 275B/day" claim is not adopted; we
  measure and report the number we get).

## 5. Success bar (falsifiable)

| # | Criterion | Exact form |
|---|---|---|
| 1 | Shared extraction safety | Differential test: native-path OCSF output **byte-identical** baseline vs tiered (modulo event_id/ingest_time) on all known-format corpus lines. Aggregate field-F1 ≥ baseline as a secondary check. |
| 2 | Tier-2 quality | **TA strictly > naive baseline**; **GA ≥ naive baseline** (non-regression, not strict win — see §2.5); **template count strictly < naive baseline at equal GA** (compression/generalization is the real win); oracle ceiling reported alongside. |
| 3 | Throughput | Measured EPS + p50/p99 before/after, identical corpus; tiered must not regress p50 > 5.0 µs; report delta, no target numbers invented. |
| 4 | Tier-3 alive | `tier3_auto_onboarded > 0` on core corpus with 0 validation-gate failures (no bad drafts registered). |
| 5 | Hard-data verification | Three-column scorecard (core/adversarial/holdout); holdout run **only at freeze**. Inviolability 100% across all corpora including kv-format fixtures. |
| 6 | Repo gates | clippy (with the two `-A` flags) + fmt + full tests green at every commit. |

**Fail conditions (explicit):** any Action-Inviolability test failure; any lossless-provenance
violation; registry accepting a non-100% validation report; GA dropping below naive baseline
after a P6 step; p50 ≥ 5.0 µs after any step.

## 6. Risk register

| Risk | Mitigation |
|---|---|
| TA "dip" after P1 misread as regression | Documented here as expected: fake 100 → honest number |
| VCA 60% transient if audit-coverage lands before label map | Enforce ordering inside P1 (single commit) |
| Bi-directional wildcard + dual-branch silently break inviolability | kv-anchor fix + expanded fixtures land **first**; tripwire after every step |
| Masker swallows syslog tags/kv keys → template garbage | Tag-protection assertions in masker unit tests |
| Onboarded bad parser poisons hot path | ValidationReport 100% gate + native-first order + registry eviction |
| Registry lookup cost on unknown-heavy streams | Capacity bound; measured via P7 adversarial high-cardinality corpus |
| Flaky sub-µs benchmark misread as regression | Re-run rule noted in §3 gate |
| Corpus gitignore traps (`*.log`) | Explicit negations in P7.6; verify `git status` shows fixtures |
| `onboarder.rs` upstream merge conflicts (fork carries user's uncommitted state) | Baseline commit frozen at `9d11d2a`; diff/merge against that SHA |
| Crossing folders mid-race | Ground rule: zero reads/writes outside `/home/ani/parser-lab` |

## 7. Ground rules

1. Work only in `/home/ani/parser-lab`. Never touch `/home/ani/parser` (counterpart's track).
2. Run binaries from the lab cwd (CLI defaults: `data/raw`, `data/parquet`, `data/ledger.jsonl`).
3. Never run `scripts/run_demo.sh` casually — it `rm -rf`s tracked fixtures; restore via
   `git checkout -- data/` if hit.
4. Commit per phase (or per gated step in P6) with the metric delta in the message.
5. No network at runtime; fetch scripts are explicit dev-time invocations only.

## 8. Execution log (append-only)

### P1 — rulers fixed (`ef046e6`, corrections `f1e4f23`)
- Implemented every P1 item: label map, exact TA (`template_is_valid`: tokenize-identical
  token alignment + GT syslog-tag containment), full-corpus audit, fair naive baseline
  (full-content `DefaultHasher` over `mask_line`), oracle ceiling column, `--audit-dump`
  JSONL, real tier2 telemetry, IANA numeric protocol equivalence, OCSF GT dispositions
  (deny→Blocked, FGT session-end→Allowed incl. `timeout` engine arm, CEF GT branch,
  PAN positional action), `mask_line` exposed from `drain.rs`, `tier2_cluster_count()`
  accessor, 6 new ruler tests.
- **First dump run found 3 defects** (fixed in `f1e4f23`): (a) my TA check compared
  tokenized masked-line vs `split_whitespace` template → baseline fake-fail 802×;
  (b) baseline cluster key used the LRU **structural signature hash** (vendor + selected
  tokens) → merged all Suricata JSON into one cluster — the sole baseline GA impurity;
  (c) GT keyed Suricata only on `event_type` while EVE `action` (blocked/allowed) is
  authoritative → 43×2 spurious disposition failures.
- **Dump-confirmed failure families awaiting later phases:** vendor 52 (CEF→P4),
  protocol/ip 89 (CEF 52 + ASA 113019 37→P2/P4), ports 204/engine (CEF 52 + 113019 37 +
  ICMP 115→P2 extractor + P5 null-correct audit rule), disposition 132 (CEF 52 + 113019 37
  + Suricata action 43), tiered template 108 = **100% GT-tag-wildcarded** (ASA message-code
  cross-merges → P6.1 dynamic syslog-code anchors), tiered grouping 40 = ASA code merges
  only (no Suricata cross-merges — length bucketing holds).
- Success-criterion note: with a correct naive baseline, baseline GA → 100.00 on the clean
  corpus, so `GA ≥ baseline` requires tiered GA = 100 (zero cross-tag merges). The dump
  shows the only cross-tag merges are ASA message codes → P6.1 message-code anchoring is
  both necessary and plausibly sufficient for the GA bar.

### P2 — dump-driven extractor fixes + Tier-3 onboarding (committed `d8de390`)
- **Extractors:** ASA `%ASA-4-113019` branch (peer IP → src endpoint, honest null
  ports/protocol, username/group/session/duration/reason → unmapped, xmt/rcv → Traffic,
  ALLOWED+CLOSE); PAN + FGT ICMP → ports `None` (never `Some(0)`); FGT zero-port cleanup.
- **Tier-3 made possible:** exemplar budget 8/format key (was exactly 1 — `generate_parser`
  needs ≥3, so `tier3_laya_onboarded` was structurally impossible at 0), worker-side
  per-key buffer with `report.passed && match_percentage == 100.0` gate + retry-to-cap,
  budget key = Tier-1 signature hash on **all three** `process()` paths (LRU promotion was
  starving exemplar collection at 2 samples), tier-1 fast path gated by one atomic read
  (`exemplar_budget_open`), heads wired → `laya_action_flags`/`laya_threat_flags`.
- **Onboarder:** `IpAddr::from_str`, 3rd+ ip/port columns unnamed (duplicate group names
  failed `Regex::new`), kv action capture tolerates quotes+hyphens (`action="client-rst"`).
- **Laya:** fingerprint priors weight 10.0 vs structural 4.0 (was flat 2.5).
- **+9 tests** (71 total). Gate: clippy 0 / fmt ok / workspace ok.
- **Post-P2 eval (release, all engines, 1300 records):** VCA 96.00/96.00 · GA
  100.00/96.92 · TA 100.00/91.69 · **disposition 93.15 → 96.00/96.00** (+37 113019, both
  engines share the extractor) · src_ip dump-failures 89 → 52 (CEF only, →P4) ·
  p50 67.75/3.45 µs (tiered gate <5.0 ✓) · LRU 95.99% (gate >90 ✓) · Action Inviolability
  100% · lossless 100% · Tier-2 clusters 19 · Tier-3 dispatches 224 · dump 1780 → **1632**
  (exact predicted −148 = (src_ip 37 + disposition 37)×2 engines).
- **Remaining dump families:** vendor 52 (CEF→P4) · dst_ip 89 = CEF 52 + 113019 37 ·
  ports 204 = CEF 52 + 113019 37 + ICMP 115 (honest nulls — audit `None` branch is an
  unconditional fail → P5 null-correct rule, generalized from the pre-registered
  "ICMP None audited as correct") · protocol 89 = CEF 52 + 113019 37 (same P5 family) ·
  template 108 + grouping 40 (→P6.1).

### P3 — hot-path wiring: pinned order, bounded registry, promotion, differential
- **Pinned parse order on every Tier-1 miss:** native extractor → dynamic
  registry → lossless. Native owns known formats absolutely — the registry is
  consulted only when `classify == Unknown` (a catch-all dynamic parser can
  never hijack a native shape; proven by
  `test_pinned_order_native_wins_over_registry`). Registry parse success
  promotes; native parse success now promotes too (previously promotion only
  happened on `!is_new`, so the first sight of every cluster parsed lossless —
  that first-sight gap is where the disposition gain came from).
- **Registry bound + LRU:** `REGISTRY_CAPACITY = 256`, LRU-by-last-use with
  lexicographic tie-break (fully deterministic), keys `vendor:device_model`
  (bare-vendor keys silently overwrote sibling clusters), regex compiled once
  at register (`ParserDefinition::parse_with_regex`), BTreeMap iteration so
  `parse_any` has a deterministic winner.
- **Tier-1b promotion routes:** registry/pipeline-level `sig_hash → registry
  key` map gated by one atomic (`dynamic_routes_open`); repeat unknown shapes
  skip both the Drain mutex and the full registry scan; stale routes (evicted
  by the bound) self-remove and fall through; a route is never allowed to
  shadow a native-classified line (classify guard inside Tier-1b).
- **Differential instrument (success-criterion-1):**
  `test_differential_baseline_vs_tiered` asserts byte-identical OCSF (modulo
  `event_id`/`ingest_time`/`time` — `time` is the extractors' `Utc::now()`
  clock for ASA/pfSense, so two sequential parses land in different ms) for
  all >1000 native-firing corpus lines between baseline `parse()` and
  `tiered.process()`. It caught the third clock field on first run.
- **Tests 71 → 75** (+registry bound/LRU, +pinned order, +route promotion,
  +differential). Gate: clippy 0 / fmt ok / workspace ok.
- **Post-P3 eval:** VCA 96.00/96.00 · GA 100.00/96.92 · TA 100.00/91.69 ·
  **disposition 96.00 → 97.85 tiered** (baseline 96.00) · p50 72.43/3.81 µs
  (<5.0 gate ✓) · Action Inviolability 100% · lossless 100% · Tier-3
  dispatches 224 (unchanged) · **Tier-2 clusters 19 → 11** — expected: sig
  buckets (ASA message codes etc.) are promoted by their first member, so
  bucket-mates no longer visit Drain; dispatch/exemplars unaffected (budget
  keyed by sig on all three paths). · dump 1632 → **1452** (tiered 710 =
  baseline-shared 658 + grouping 40 + template 108; baseline 742 unchanged).
- **Dump-confirmed post-P3 families:** tiered src_ip **52 → 0**, dst_ip
  89 → 37, protocol 89 → 37 (the worker onboarded a CEF dynamic parser —
  endpoints/protocol now parse through the registry while `vendor` stays 52
  because the Laya label ≠ `cef`; **transitional: P4's native CEF extractor
  takes over via pinned order and removes the async-onboarding race from the
  numbers**) · disposition tiered 52 → 28 (CEF `act=` mapped by the onboarded
  kv parser for allow-side values; blocked-side still wrong → P4 native
  `act=` mapping) · ports 204 unchanged (CEF `spt=`/`dpt=` absent from kv
  key patterns → P4 native ports; 113019 37 + ICMP 115 honest nulls → P5
  null-correct rule) · dst_ip/protocol 37 = 113019 honest nulls → P5 ·
  template 108 + grouping 40 → P6.1.

### P4 — native ArcSight CEF extractor
- **`VendorFormat::Cef` + `extractors/cef.rs`:** header split on `CEF:0|...|`
  (8 fields), `vendor_name` from the **Device Vendor header field** (what GT
  reads — never a hardcoded brand), Device Product/Version → `Product`,
  extension iterated with the shared kv `KvTokenizer` (src/dst/spt/dpt/proto/
  act/in/out), ICMP keeps ports `None`, `in`/`out` → `Traffic` bytes,
  signature-id/name/severity → `unmapped` (nothing dropped). Wired into the
  Aho-Corasick table (`CEF:`), classifier fallback, `parse()` and
  `parse_with_format()`, plus a single `cef_extension` signature bucket
  (vendor-neutral envelope = one cached format).
- **Disposition parity with GT** (`act=`): `accept|allow|allowed → Allowed`,
  `deny|denied|blocked|block → Blocked`, `drop → Dropped`,
  `close|closed|timeout|client-rst|server-rst|reset → Allowed (CLOSE)`.
- **GT vocab completion (ruler fix, pre-P6):** `action_from_kv_token` now
  resolves `allowed`/`denied` — previously `None` meant the disposition check
  was silently skipped for those verbs. Corpus has zero such lines (verified),
  so this makes GT *stricter* without moving any existing number. Both callers
  are the CEF `act=` and FGT `action=` branches.
- **Shared-extractor decision (user: "Include them"):** baseline gains the CEF
  extractor too — its 52 CEF failures vanish identically. Strict wins now live
  where the engines genuinely differ: GA/TA.
- **Tests 75 → 81** (+5 extractor unit tests, +`test_cef_parsing_suite` with 6
  fixtures incl. syslog-prefixed + foreign-vendor lines and byte-for-byte
  SHA-256 preservation, classifier CEF case). Gate: clippy 0 / fmt ok /
  workspace **81 passed** (flaky sub-µs benchmark re-ran green alone).
- **Post-P4 eval:** **VCA 96.00 → 100.00 / 100.00** · **disposition
  96.00/97.85 → 100.00 / 100.00** (async-onboarding race eliminated — CEF is
  now native, deterministic) · GA 100.00/96.92 · TA 100.00/91.69 (unchanged →
  P6.1) · p50 76.74/3.69 µs (<5.0 ✓) · p99.9 184.11/14.54 µs · Action
  Inviolability 100% · lossless 100% · Tier-3 dispatches 224 → 96 (CEF no
  longer floods novel-cluster dispatch — first sight is now promoted native) ·
  Tier-2 clusters 11 · dump 1452 → **904**.
- **Dump families (both engines, symmetric):** src_port/dst_port 152 (ICMP 115
  + 113019 37 honest nulls → **P5**), dst_ip 37 + protocol 37 (113019 → P5),
  vendor/disposition/src_ip families **eliminated**; tiered-only template 108
  + grouping 40 → **P6.1**.
