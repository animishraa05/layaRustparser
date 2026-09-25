# ULPF Docs — Start Here

| Doc | What it is | Who reads it |
| :--- | :--- | :--- |
| [`ARCHITECTURE_FINAL.md`](ARCHITECTURE_FINAL.md) | **Canonical architecture.** Subsystem-by-subsystem walkthrough: original proposal → why it fails in practice → what we built. **Read this first.** | Everyone, judges |
| [`DEMO.md`](DEMO.md) | 2-minute video script + terminal timeline. Run via `scripts/run_demo.sh`. | Demo / video owner |
| [`PRESENTATION.md`](PRESENTATION.md) | 5-slide technical pitch + deliverables checklist. | Pitch owner |
| [`reference/Ulpf-proposal.pdf`](reference/Ulpf-proposal.pdf) | Original proposal document. Historical context only — implementation overruled it where noted in `ARCHITECTURE_FINAL.md`. | Curious |
| [`archive/`](archive/) | Superseded docs (stale 2-tier spec, overlapping dossiers). **Do not cite.** Kept for history. | Nobody |
| `ULPF_*.pdf` (this dir) | Generated frozen PDF exports for submission. Regenerate from `*_template.html` if content changes. | Submission |

Related, at repo root:

| File | What |
| :--- | :--- |
| [`../README.md`](../README.md) | Operational guide: quickstart, usage steps, crate map |
| [`../AGENTS.md`](../AGENTS.md) | Agent handbook: invariants, verification gate, gotchas, extension recipes |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Team workflow: branches, gate, PR checklist |
| [`../remainingStuff.md`](../remainingStuff.md) | Roadmap: what is done vs what each teammate builds next |

Conventions:

- Real CLI flags come from `ulpf --help`. If README and `--help` disagree, `--help` wins.
- Run binaries from the repo root (defaults assume `data/raw`, `data/parquet`, `data/ledger.jsonl`).
- `evaluate` / `benchmark` only work in **release** builds (debug panics on a duplicate `-d` clap flag).
