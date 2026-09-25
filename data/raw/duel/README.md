# Duel fixtures — vanilla Drain vs 3-tier

Frozen inputs for the `ulpf scorecard` duel (rounds R1/R3). Nothing here is
read by `ulpf ingest`; these files are evaluation-only. The duel runs fully
offline — no runtime download.

| File | Lines | Ground truth | Provenance |
| :--- | :--- | :--- | :--- |
| `security_probe.log` + `security_probe.gt.jsonl` | 12 | authored full-line templates | written for this repo (R1) |
| `BGL_2k.log` + `BGL_2k.log_structured.csv` | 2000 | `EventTemplate` CSV column | LogHub, `BGL/` (R3) |
| `Thunderbird_2k.log` + `Thunderbird_2k.log_structured.csv` | 2000 | `EventTemplate` CSV column | LogHub, `Thunderbird/` (R3) |

Round 2 reuses `../adversarial/` (757 mutated lines + `gt.jsonl`).

The probe is untagged by design: three families (bare firewall, kv firewall,
IDS), two action verdicts each, two instances per verdict. Equal token counts
per family, so a merge can only be prevented by the anchor subsystem — that
is exactly what the duel measures. The sidecar's `gt_template_tag` holds the
full ground-truth template (the probe's GT classes ARE templates).

## Attribution (BGL / Thunderbird)

Vendored byte-for-byte from **LogHub**:
<https://github.com/logpai/loghub> (branch `master`), files
`BGL/BGL_2k.log`, `BGL/BGL_2k.log_structured.csv`,
`Thunderbird/Thunderbird_2k.log`, `Thunderbird/Thunderbird_2k.log_structured.csv`.

Cite when using these samples:

- He, Liu, Zhu, Zhang, ... "Drain: An Online Log Parsing Approach with Fixed
  Depth Tree", ICSE 2019.
- Zhu, He, ... "LogHub: A Large Collection of System Log Datasets for
  AI-driven Log Analytics", ISSRE 2023. <https://loghub.datasets.top>

Underlying sources: BGL (Blue Gene/L, IBM) and Thunderbird (Sandia National
Laboratories) system logs, redistributed by LogHub for research. Used here
for offline evaluation research only; upstream terms apply.

## SHA-256 (byte integrity)

```
2a819ea540909db682005c9cf948387a40729b5c2e9f19d430e29ce704825496  BGL_2k.log
3fe74103c0b02a28514534e2a47257a3f770135ca61afd425bbd3b9d6a31fe26  BGL_2k.log_structured.csv
903bbfa61c34d4803e4adcb0d726ff2eeb9a2e11971243269a2035fa6c3bbeb0  Thunderbird_2k.log
c62196d8a3449de765501bbf58c2093452e9d1add439053301d29fdad8a06809  Thunderbird_2k.log_structured.csv
```
