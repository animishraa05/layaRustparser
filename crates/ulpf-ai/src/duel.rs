//! Vanilla Drain vs the 3-tier pipeline — the measurement duel behind
//! `ulpf scorecard` (evidence, **not** a gate).
//!
//! Both engines run on byte-identical corpus lines through ULPF's own
//! tokenizer (`mask_line` + `DrainMiner::tokenize`), so every delta isolates
//! clustering policy, not preprocessing:
//!
//! - **vanilla Drain** — `DrainConfig { anchors_enabled: false, .. }`: stock
//!   depth-4 prefix tree, similarity threshold, anchor subsystem off.
//! - **3-tier pipeline** — `TieredPipeline::new()` as shipped. Quality rows
//!   are graded out-of-band with a parallel `DrainMiner::new(DrainConfig::default())`
//!   (the evaluator's convention: the pipeline exposes no per-line cluster
//!   id); capability rows (panics, lossless SHA-256) come from real
//!   `TieredPipeline::process()` calls.
//!
//! Round fixtures: `data/raw/duel/` (probe + LogHub BGL/Thunderbird) and
//! `data/raw/adversarial/` (R2). The frozen holdout corpus is never read.

use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::drain::{DrainConfig, DrainMiner};
use crate::evaluator::load_sidecar_gt;
use crate::pipeline::TieredPipeline;
use ulpf_core::parser::compute_sha256;

/// One engine's quality numbers for one round.
#[derive(Debug, Clone, Serialize)]
pub struct EngineDuelScore {
    /// Distinct clusters the engine minted over the round's lines.
    pub clusters: usize,
    /// Σ majority-GT-count per cluster ÷ lines (the evaluator's GA formula).
    pub grouping_accuracy_pct: f64,
    /// Lines whose mined template reproduces the GT template (token-suffix,
    /// canonicalised). `None` when the corpus carries no full templates.
    pub parsing_accuracy_pct: Option<f64>,
    /// Set-level F1 over unique templates. `None` with no full templates.
    pub template_f1_pct: Option<f64>,
    /// Clusters mixing allow-side and deny-side dispositions. `None` when
    /// the corpus carries no disposition GT.
    pub action_violations: Option<usize>,
}

/// One corpus round, both engines side by side.
#[derive(Debug, Clone, Serialize)]
pub struct DuelRound {
    /// Display name, e.g. `R1 probe`.
    pub name: String,
    /// Corpus lines graded.
    pub lines: usize,
    /// Unique ground-truth classes (templates or tags) in this round.
    pub gt_classes: usize,
    pub vanilla: EngineDuelScore,
    pub tiered: EngineDuelScore,
    /// `TieredPipeline::process()` panics over this round's lines.
    pub tiered_panics: usize,
    /// Lines whose `raw_hash` still equals SHA-256(raw) byte-for-byte.
    pub tiered_lossless_ok: usize,
    /// Grading caveat shown next to the round (honest-claim context).
    pub note: Option<String>,
}

/// Full duel output — rendered by `ulpf scorecard` and `to_markdown()`.
#[derive(Debug, Clone, Serialize)]
pub struct DuelReport {
    pub rounds: Vec<DuelRound>,
    /// Lines pushed through the real 3-tier pipeline (capability rows).
    pub tiered_lines: usize,
    pub tiered_lossless_ok: usize,
    pub tiered_panics: usize,
}

impl DuelReport {
    /// Rounds won on grouping accuracy: `(tiered, vanilla)`. Exact ties
    /// (within 1e-9) go to neither side.
    pub fn ga_wins(&self) -> (usize, usize) {
        let mut tiered = 0;
        let mut vanilla = 0;
        for r in &self.rounds {
            let d = r.tiered.grouping_accuracy_pct - r.vanilla.grouping_accuracy_pct;
            if d.abs() < 1e-9 {
                continue;
            }
            if d > 0.0 {
                tiered += 1;
            } else {
                vanilla += 1;
            }
        }
        (tiered, vanilla)
    }

    /// Committed markdown evidence: engines, exact formulas, per-round
    /// numbers and the disclosures that keep the claim honest.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# ULPF Duel — vanilla Drain vs 3-tier pipeline\n\n");
        md.push_str(
            "**What this is:** measurement evidence surfaced by `ulpf scorecard`. \
             The duel is **not a gate** — the scorecard's six gates are unchanged by it.\n\n",
        );

        md.push_str("## Engines\n\n");
        md.push_str(
            "- **vanilla Drain** (`Engine A`) — \
             `DrainMiner::new(DrainConfig { anchors_enabled: false, ..Default::default() })`: \
             stock Drain (depth-4 prefix tree, similarity threshold, max 100 children) with \
             ULPF's anchor subsystem switched off — no anchor vocabulary, no syslog-tag \
             homogeneity (P6.1), no key-aware class partition (P7.2).\n",
        );
        md.push_str(
            "- **3-tier pipeline** (`Engine B`) — `TieredPipeline::new()` as shipped \
             (Tier-1 signature LRU → Tier-2 anchored Drain → Tier-3 Laya). Quality rows \
             are graded **out-of-band** with a parallel \
             `DrainMiner::new(DrainConfig::default())` fed the same lines — the \
             evaluator's convention: the pipeline exposes no per-line cluster id. \
             Capability rows (panics, lossless SHA-256) come from real \
             `TieredPipeline::process()` calls over every line.\n",
        );
        md.push_str(
            "- Both engines share ULPF's tokenizer (`mask_line` + `DrainMiner::tokenize`), \
             so every delta isolates clustering policy, not preprocessing.\n\n",
        );

        md.push_str("## Metrics\n\n");
        md.push_str(
            "- **GA (grouping accuracy)** = Σ over clusters of the cluster's majority \
             ground-truth class count ÷ total lines (the evaluator's exact formula).\n",
        );
        md.push_str(
            "- **PA (parsing accuracy)** = lines whose mined template reproduces the \
             ground-truth template as an exact **token suffix** after canonicalisation: \
             whitespace-normalised token sequences, any digit-bearing token compared as \
             `<*>` (tokenizer alignment between ULPF's masker and LogPAI's), trailing \
             `,;:` ignored.\n",
        );
        md.push_str(
            "- **FTA (template F1, set-level)** = F1 over unique templates — precision = \
             unique mined templates that suffix-match some ground-truth template; recall = \
             unique ground-truth templates reproduced by some mined template.\n",
        );
        md.push_str(
            "- **Action violations** = clusters holding both an allow-side and a deny-side \
             disposition (vocabulary: allowed/allow/accept/accepted/pass/permit/permitted \
             vs blocked/block/deny/denied/drop/dropped/reject/rejected).\n\n",
        );

        md.push_str("## Fixtures\n\n");
        md.push_str(
            "- **R1 probe** — `data/raw/duel/security_probe.log`, 12 authored lines \
             (3 families × 2 actions × 2 instances), full-template sidecar GT.\n",
        );
        md.push_str(
            "- **R2 fuzzed** — `data/raw/adversarial/`, 757 mutated lines, tag-level \
             sidecar GT (PA/FTA not graded).\n",
        );
        md.push_str(
            "- **R3 BGL / R3 TBird** — LogHub BGL_2k and Thunderbird_2k samples vendored \
             under `data/raw/duel/` (attribution: `data/raw/duel/README.md`).\n\n",
        );

        md.push_str("## Results\n\n");
        md.push_str(
            "| Round | Lines | GT classes | Engine | Clusters | GA % | PA % | FTA % | Violations |\n",
        );
        md.push_str("| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |\n");
        for r in &self.rounds {
            for (label, e) in [("vanilla Drain", &r.vanilla), ("3-tier", &r.tiered)] {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {:.2}% | {} | {} | {} |\n",
                    r.name,
                    r.lines,
                    r.gt_classes,
                    label,
                    e.clusters,
                    e.grouping_accuracy_pct,
                    opt_pct(e.parsing_accuracy_pct),
                    opt_pct(e.template_f1_pct),
                    opt_count(e.action_violations),
                ));
            }
        }
        md.push_str(&format!(
            "\n**3-tier capability over all duel lines:** lossless {}/{} \
             (`raw_hash` == SHA-256(raw)), panics {}.\n\n",
            self.tiered_lossless_ok, self.tiered_lines, self.tiered_panics
        ));

        let notes: Vec<&DuelRound> = self.rounds.iter().filter(|r| r.note.is_some()).collect();
        if !notes.is_empty() {
            md.push_str("## Round notes\n\n");
            for r in notes {
                md.push_str(&format!(
                    "- **{}** — {}\n",
                    r.name,
                    r.note.as_deref().unwrap_or("")
                ));
            }
            md.push('\n');
        }

        let (tiered_wins, vanilla_wins) = self.ga_wins();
        md.push_str("## Disclosures\n\n");
        md.push_str(&format!(
            "- **Winner on GA:** 3-tier {} / vanilla {} of {} rounds (exact ties uncounted).\n",
            tiered_wins,
            vanilla_wins,
            self.rounds.len()
        ));
        md.push_str(
            "- **Tokenizer alignment, not LogPAI parity:** absolute PA/FTA levels are not \
             comparable to published LogPAI numbers — their per-dataset preprocessor differs \
             (LogPAI maps `2005.06.03` to `<*>` where ULPF yields `<*>.06.03`). Only the \
             vanilla-vs-3-tier delta under one shared tokenizer is claimed here.\n",
        );
        // Corpus-wide disposition purity is this duel's stricter, newly
        // measured metric — when it shows mixed clusters, say so plainly.
        // The finding is reported, never tuned away against the corpus it
        // was found on (a fix must be validated on unseen data).
        let mixed: Vec<String> = self
            .rounds
            .iter()
            .filter(|r| r.tiered.action_violations.unwrap_or(0) > 0)
            .map(|r| {
                format!(
                    "{} (vanilla {}, 3-tier {})",
                    r.name,
                    r.vanilla.action_violations.unwrap_or(0),
                    r.tiered.action_violations.unwrap_or(0)
                )
            })
            .collect();
        if !mixed.is_empty() {
            md.push_str(&format!(
                "- **Mixed-action clusters remain (finding, not tuned away):** {} — a relay \
                 prefix or mid-line CR keeps a space in the payload, the tokenizer then fuses \
                 the record into one token, and the buried action word never reaches the \
                 anchor vocabulary, so cross-action merges stay possible. The scorecard gate \
                 `Action inviolability (ALLOW/DENY)` is the bare-token canary (a weaker, \
                 pre-existing check); corpus-wide disposition purity is this duel's stricter, \
                 newly measured metric. No tokenizer or threshold was changed in response to \
                 this result — such a fix must be validated on data the code has never seen.\n",
                mixed.join("; ")
            ));
        }
        md.push_str(
            "- The frozen holdout corpus is never read by the duel — holdout inputs stay \
             untouched.\n",
        );
        md.push_str(
            "- Speed is out of scope: `ulpf scorecard` already reports latency and \
             throughput for both engines.\n",
        );
        md
    }
}

/// `12.34%` or `n/a`.
fn opt_pct(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{v:.2}%"),
        None => "n/a".to_string(),
    }
}

/// Count or `n/a`.
fn opt_count(v: Option<usize>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "n/a".to_string(),
    }
}

/// Per-round input assembled from fixtures before grading.
struct RoundInput {
    name: &'static str,
    lines: Vec<String>,
    /// Per-line GT class for GA (sidecar template tag or LogPAI template).
    gt_class: Vec<String>,
    /// Full per-line GT templates when the corpus has them.
    gt_template: Option<Vec<String>>,
    /// Per-line sidecar disposition; `None` entries carry no expectation.
    gt_disp: Vec<Option<String>>,
    note: Option<&'static str>,
}

/// Raw-line corpus reader mirroring the CLI's `load_corpus` trim semantics
/// (trim each line, drop empties) so fixture line counts stay identical to
/// what `evaluate`/`scorecard` grade.
fn read_trimmed_lines(path: &Path) -> Result<Vec<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// Sidecar-GT round (R1 probe, R2 fuzzed). `full_templates` selects whether
/// `gt_template_tag` doubles as the full per-line template (R1) or is only a
/// GA class (R2's tag-level sidecar → PA/FTA `None`).
fn sidecar_round(
    name: &'static str,
    log_path: &Path,
    gt_path: &Path,
    full_templates: bool,
    note: Option<&'static str>,
) -> Result<RoundInput> {
    let lines = read_trimmed_lines(log_path)?;
    let gt = load_sidecar_gt(gt_path)?;
    let mut gt_class = Vec::with_capacity(lines.len());
    let mut gt_template: Option<Vec<String>> = full_templates.then(Vec::new);
    let mut gt_disp = Vec::with_capacity(lines.len());
    for (i, raw) in lines.iter().enumerate() {
        let rec = gt.get(raw).with_context(|| {
            format!(
                "{}: line {} has no entry in sidecar {}",
                log_path.display(),
                i + 1,
                gt_path.display()
            )
        })?;
        gt_class.push(rec.gt_template_tag.clone());
        if let Some(v) = gt_template.as_mut() {
            v.push(rec.gt_template_tag.clone());
        }
        gt_disp.push(rec.gt_disposition.clone());
    }
    Ok(RoundInput {
        name,
        lines,
        gt_class,
        gt_template,
        gt_disp,
        note,
    })
}

/// LogHub round (R3): index-aligned `EventTemplate` column from the
/// committed `*_structured.csv` (parsed at load time, no CSV crate).
fn loghub_round(name: &'static str, log_path: &Path, csv_path: &Path) -> Result<RoundInput> {
    let log_text = std::fs::read_to_string(log_path)
        .with_context(|| format!("reading {}", log_path.display()))?;
    // Keep every line (including any empty one) — dropping a line would
    // break index alignment with the CSV ground truth.
    let lines: Vec<String> = log_text.lines().map(str::to_string).collect();
    let templates = read_event_templates(csv_path)?;
    anyhow::ensure!(
        lines.len() == templates.len(),
        "{}: {} log lines vs {} CSV templates — index alignment broken",
        log_path.display(),
        lines.len(),
        templates.len()
    );
    let n = lines.len();
    Ok(RoundInput {
        name,
        lines,
        gt_class: templates.clone(),
        gt_template: Some(templates),
        gt_disp: vec![None; n],
        note: Some("LogPAI EventTemplate is content-only: PA/FTA use token-suffix match"),
    })
}

/// Quote-aware last-column reader for a LogPAI structured CSV (templates may
/// contain commas; embedded `""` is an escaped quote).
fn csv_last_field(line: &str) -> String {
    let line = line.trim_end_matches('\r');
    let mut in_quotes = false;
    let mut start = 0;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => start = i + 1,
            _ => {}
        }
    }
    let field = &line[start..];
    if field.len() >= 2 && field.starts_with('"') && field.ends_with('"') {
        field[1..field.len() - 1].replace("\"\"", "\"")
    } else {
        field.to_string()
    }
}

/// Read the `EventTemplate` column (last field of every row) from a
/// LogPAI structured CSV; the header names the column we rely on.
fn read_event_templates(path: &Path) -> Result<Vec<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut rows = text.lines();
    let header = rows
        .next()
        .with_context(|| format!("{}: empty CSV", path.display()))?;
    let last = csv_last_field(header);
    anyhow::ensure!(
        last == "EventTemplate",
        "{}: last CSV column is {last:?}, expected EventTemplate",
        path.display()
    );
    Ok(rows.map(csv_last_field).collect())
}

/// One engine's pass over a round: per-line cluster id + the template the
/// miner returned for that line (post-update, exactly what production emits).
fn run_miner(lines: &[String], cfg: DrainConfig) -> (Vec<usize>, Vec<String>) {
    let mut miner = DrainMiner::new(cfg);
    let mut clusters = Vec::with_capacity(lines.len());
    let mut templates = Vec::with_capacity(lines.len());
    for raw in lines {
        let res = miner.add_log(raw);
        clusters.push(res.cluster_id);
        templates.push(res.template);
    }
    (clusters, templates)
}

/// Grouping accuracy: Σ over clusters of the cluster's majority GT class
/// count ÷ lines — the same formula the scorecard's GA gate uses.
fn grouping_accuracy(gt_class: &[String], clusters: &[usize]) -> f64 {
    if gt_class.is_empty() {
        return 0.0;
    }
    let mut map: HashMap<usize, HashMap<&str, usize>> = HashMap::new();
    for (gt, cid) in gt_class.iter().zip(clusters) {
        *map.entry(*cid).or_default().entry(gt.as_str()).or_default() += 1;
    }
    let correct: usize = map
        .values()
        .map(|counts| counts.values().copied().max().unwrap_or(0))
        .sum();
    correct as f64 / gt_class.len() as f64 * 100.0
}

/// Canonical token form for template comparison: whitespace-split, trailing
/// `,;:` dropped, and any digit-bearing token or `<*>` collapses to `<*>`
/// (ULPF masks integers ≥ 3 digits, LogPAI masks all of them — aligning the
/// two is what makes the comparison about clustering, not masking).
fn canon_token(tok: &str) -> String {
    let t = tok.trim().trim_end_matches([',', ';', ':']);
    if t.contains("<*>") || t.bytes().any(|b| b.is_ascii_digit()) {
        "<*>".to_string()
    } else {
        t.to_string()
    }
}

/// Does `mined` reproduce `gt` as an exact token suffix after
/// canonicalisation? Suffix (not prefix) because LogPAI GT templates cover
/// only the content portion of each line while ULPF templates span the
/// full masked line.
fn template_match(mined: &str, gt: &str) -> bool {
    let gt_toks: Vec<String> = gt.split_whitespace().map(canon_token).collect();
    if gt_toks.is_empty() {
        return false;
    }
    let mined_toks: Vec<String> = mined.split_whitespace().map(canon_token).collect();
    if mined_toks.len() < gt_toks.len() {
        return false;
    }
    mined_toks[mined_toks.len() - gt_toks.len()..] == gt_toks[..]
}

/// Line-level parsing accuracy (%).
fn parsing_accuracy(templates: &[String], gt: &[String]) -> f64 {
    if gt.is_empty() {
        return 0.0;
    }
    let hits = templates
        .iter()
        .zip(gt)
        .filter(|(mined, expect)| template_match(mined, expect))
        .count();
    hits as f64 / gt.len() as f64 * 100.0
}

/// Set-level F1 over unique templates (P∩G via `template_match`).
fn template_f1(templates: &[String], gt: &[String]) -> f64 {
    let mined_set: HashSet<&str> = templates.iter().map(String::as_str).collect();
    let gt_set: HashSet<&str> = gt.iter().map(String::as_str).collect();
    if mined_set.is_empty() || gt_set.is_empty() {
        return 0.0;
    }
    let mined_hit = mined_set
        .iter()
        .filter(|m| gt_set.iter().any(|g| template_match(m, g)))
        .count();
    let gt_hit = gt_set
        .iter()
        .filter(|g| mined_set.iter().any(|m| template_match(m, g)))
        .count();
    let precision = mined_hit as f64 / mined_set.len() as f64;
    let recall = gt_hit as f64 / gt_set.len() as f64;
    if precision + recall == 0.0 {
        0.0
    } else {
        // Percent, like every other *_pct field — F1 was leaking 0..1.
        100.0 * (2.0 * precision * recall / (precision + recall))
    }
}

/// Disposition side: `Some(true)` allow, `Some(false)` deny, `None` = no
/// expectation (missing / unmapped vocabulary).
fn disposition_side(disp: &str) -> Option<bool> {
    match disp {
        "allowed" | "allow" | "accept" | "accepted" | "pass" | "permit" | "permitted" => Some(true),
        "blocked" | "block" | "deny" | "denied" | "drop" | "dropped" | "reject" | "rejected" => {
            Some(false)
        }
        _ => None,
    }
}

/// Clusters that mix an allow-side with a deny-side disposition.
fn action_violations(clusters: &[usize], disp: &[Option<String>]) -> usize {
    let mut state: HashMap<usize, (bool, bool)> = HashMap::new();
    for (cid, d) in clusters.iter().zip(disp) {
        let Some(d) = d else { continue };
        let Some(side) = disposition_side(&d.to_ascii_lowercase()) else {
            continue;
        };
        let seen = state.entry(*cid).or_insert((false, false));
        if side {
            seen.0 = true;
        } else {
            seen.1 = true;
        }
    }
    state
        .values()
        .filter(|(allow, deny)| *allow && *deny)
        .count()
}

/// Real 3-tier pipeline capability pass: panics + lossless `raw_hash`.
fn pipeline_capability(pipeline: &TieredPipeline, lines: &[String]) -> (usize, usize) {
    let mut lossless_ok = 0;
    let mut panics = 0;
    for raw in lines {
        let outcome = catch_unwind(AssertUnwindSafe(|| pipeline.process(raw)));
        match outcome {
            Ok(activity) => {
                if activity.metadata.raw_hash == compute_sha256(raw.as_bytes()) {
                    lossless_ok += 1;
                }
            }
            Err(_) => panics += 1,
        }
    }
    (lossless_ok, panics)
}

/// Run the duel over whatever fixtures exist under `data_dir`.
///
/// Returns `Ok(None)` when the probe fixture is absent (tmp dirs, minimal
/// installs) — the scorecard then prints a plain skip line instead of the
/// duel section rows.
pub fn run_duel(data_dir: &Path) -> Result<Option<DuelReport>> {
    let duel_dir = data_dir.join("duel");
    let probe_log = duel_dir.join("security_probe.log");
    let probe_gt = duel_dir.join("security_probe.gt.jsonl");
    if !probe_log.is_file() || !probe_gt.is_file() {
        return Ok(None);
    }

    let mut inputs = Vec::new();
    inputs.push(sidecar_round(
        "R1 probe", &probe_log, &probe_gt, true, None,
    )?);

    let adv_dir = data_dir.join("adversarial");
    if adv_dir.join("adversarial.log").is_file() && adv_dir.join("gt.jsonl").is_file() {
        inputs.push(sidecar_round(
            "R2 fuzzed",
            &adv_dir.join("adversarial.log"),
            &adv_dir.join("gt.jsonl"),
            false,
            Some("sidecar GT is tag-level: PA/FTA not graded"),
        )?);
    }
    for (name, stem) in [("R3 BGL", "BGL_2k"), ("R3 TBird", "Thunderbird_2k")] {
        let log = duel_dir.join(format!("{stem}.log"));
        let csv = duel_dir.join(format!("{stem}.log_structured.csv"));
        if log.is_file() && csv.is_file() {
            inputs.push(loghub_round(name, &log, &csv)?);
        }
    }

    // Quality is graded with two fresh miners per round; capability comes
    // from one shared pipeline instance (LRU state across rounds is fine —
    // panics/losslessness don't depend on cache warmth).
    let vanilla_cfg = || DrainConfig {
        anchors_enabled: false,
        ..Default::default()
    };
    let pipeline = TieredPipeline::new();
    let mut rounds = Vec::with_capacity(inputs.len());
    let mut tiered_lines = 0;
    let mut tiered_lossless_ok = 0;
    let mut tiered_panics = 0;

    for spec in &inputs {
        let (v_clusters, v_templates) = run_miner(&spec.lines, vanilla_cfg());
        let (t_clusters, t_templates) = run_miner(&spec.lines, DrainConfig::default());
        let (lossless_ok, panics) = pipeline_capability(&pipeline, &spec.lines);

        tiered_lines += spec.lines.len();
        tiered_lossless_ok += lossless_ok;
        tiered_panics += panics;

        let gt_template = spec.gt_template.as_deref();
        let violations_on = spec.gt_disp.iter().any(Option::is_some);
        rounds.push(DuelRound {
            name: spec.name.to_string(),
            lines: spec.lines.len(),
            gt_classes: spec.gt_class.iter().collect::<HashSet<_>>().len(),
            vanilla: score_run(&v_clusters, &v_templates, spec, gt_template, violations_on),
            tiered: score_run(&t_clusters, &t_templates, spec, gt_template, violations_on),
            tiered_panics: panics,
            tiered_lossless_ok: lossless_ok,
            note: spec.note.map(str::to_string),
        });
    }

    Ok(Some(DuelReport {
        rounds,
        tiered_lines,
        tiered_lossless_ok,
        tiered_panics,
    }))
}

/// Grade one engine's per-line results against a round's ground truth.
fn score_run(
    clusters: &[usize],
    templates: &[String],
    spec: &RoundInput,
    gt_template: Option<&[String]>,
    violations_on: bool,
) -> EngineDuelScore {
    EngineDuelScore {
        clusters: clusters.iter().collect::<HashSet<_>>().len(),
        grouping_accuracy_pct: grouping_accuracy(&spec.gt_class, clusters),
        parsing_accuracy_pct: gt_template.map(|gt| parsing_accuracy(templates, gt)),
        template_f1_pct: gt_template.map(|gt| template_f1(templates, gt)),
        action_violations: violations_on.then(|| action_violations(clusters, &spec.gt_disp)),
    }
}
