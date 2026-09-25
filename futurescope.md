# ULPF Future Scope — measured gaps, in priority order

> Source: vanilla-vs-3-tier duel (`eval_duel_report.md`), frozen holdout
> (`eval_holdout_report.md`), release benchmarks. Nothing here is
> speculative — every item traces to a measured number. Rule for all
> future work: **no tuning against the corpus that exposed the gap**
> (fresh validation data only).

## 1. Vendor expansion — P10.2 (highest return)

**Gap:** holdout disposition 0/0 — no extractor means `Unknown` fields and
disposition on every line of an unseen vendor (baseline VCA 0%, tiered 40%
on structure alone; clustering TA held 100% on both, so degradation is
graceful but extraction-blind).
**Work:** ~10 ISRO-relevant zero-copy extractors (recipe: `AGENTS.md`
extension recipe — enum variant, prefix, extractor, `UniversalParser`
wiring, 5+ sample lines + SHA-256 tests).
**Done when:** holdout-class vendors resolve disposition above 0% with zero
regression on core/full/adversarial gates.

## 2. `onboard` as the production runbook

**Gap:** today a new firewall in production means silent `Unknown`s until a
developer writes an extractor.
**Work:** document the operational path — collect 3–5 sample lines, run
`ulpf onboard`, deploy the spec to `data/parsers/`. No code change; docs +
one worked example.
**Done when:** a new vendor goes from samples to parsed output following
only the runbook.

## 3. Tokenizer mixed-path fix — validated on fresh data only

**Gap (finding, not tuned away):** R2 shows 10/81 tiered clusters mixing
dispositions (vanilla 17/53). Root cause: a relay prefix or mid-line CR
keeps a space in the payload, the whitespace tokenizer path fuses the
CSV/JSON into one token, and the buried action word never reaches the
anchor vocabulary (`eval_duel_report.md` disclosure).
**Work:** fix on principle (comma-aware split / prefix strip), then
validate on a **newly generated fuzz corpus (new seed)** — R2 stays
labelled "discovery corpus" forever and is never re-reported as blind.
**Done when:** fresh-corpus mixed clusters drop with GA non-regressing.

## 4. Benchmark ritual (methodology, zero code)

**Gap:** wall-clock latency swings with machine load (baseline p50 seen
73 µs idle → 1,104 µs busy); small-corpus tiered throughput 0.82–0.97×
(Drain bookkeeping, expected — tiers pay off at scale: 2.15× at 224k).
**Work:** document the ritual in `AGENTS.md` — idle machine, thread
pinning, median of 3 runs, always quote same-run baseline-vs-tiered
ratios (absolute µs never stand alone). Small-corpus ratio is accepted
as designed, not chased.
**Done when:** any two engineers reproduce latency rows within noise.

## Explicitly out of scope

- Keyword-guessing disposition for extractor-less vendors (inflates
  numbers, breaks measurement honesty).
- Cold-corpus fast-path branching (complexity for a benchmark artifact,
  not a production shape).
- Any threshold/tokenizer change validated only on R2 or the frozen
  holdout (test-set leakage by definition).
