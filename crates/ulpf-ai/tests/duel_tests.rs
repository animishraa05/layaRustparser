//! Scorecard duel: vanilla Drain (anchors off) vs the 3-tier pipeline.
//!
//! Fixtures: `data/raw/duel/` (probe + LogHub BGL/Thunderbird) and
//! `data/raw/adversarial/` (mutation corpus, R2). Holdout is never touched.

use ulpf_ai::duel::{run_duel, DuelReport, DuelRound};

/// Tests run with cwd = crate dir; fixtures live at the workspace root.
fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/raw")
}

fn report() -> DuelReport {
    run_duel(&data_dir())
        .expect("duel must not error on committed fixtures")
        .expect("committed duel fixtures must be discovered")
}

fn round<'a>(r: &'a DuelReport, name: &str) -> &'a DuelRound {
    r.rounds.iter().find(|x| x.name == name).unwrap_or_else(|| {
        let names: Vec<&str> = r.rounds.iter().map(|x| x.name.as_str()).collect();
        panic!("round {name:?} missing; loaded: {names:?}")
    })
}

#[test]
fn all_four_rounds_load_with_full_coverage() {
    let r = report();
    assert_eq!(
        r.rounds.len(),
        4,
        "probe + adversarial + both LogHub corpora"
    );

    let probe = round(&r, "R1 probe");
    assert_eq!(probe.lines, 12);
    assert_eq!(probe.gt_classes, 6, "3 families x 2 action templates");

    let fuzzed = round(&r, "R2 fuzzed");
    assert_eq!(fuzzed.lines, 757, "adversarial corpus line count");
    assert_eq!(fuzzed.gt_classes, 19, "sidecar carries 19 GT tags");

    assert_eq!(round(&r, "R3 BGL").lines, 2000);
    assert_eq!(round(&r, "R3 TBird").lines, 2000);

    // 3-tier capability rows over every duel line.
    assert_eq!(r.tiered_lines, 12 + 757 + 2000 + 2000);
    assert_eq!(
        r.tiered_lossless_ok, r.tiered_lines,
        "raw_hash == SHA-256(raw) on every duel line"
    );
    assert_eq!(r.tiered_panics, 0, "no parse panic on any duel round");
}

#[test]
fn probe_round_vanilla_merges_actions_while_tiered_splits() {
    let r = report();
    let p = round(&r, "R1 probe");

    // Clustering: vanilla folds each family into one mixed cluster (3),
    // the anchor subsystem keeps all six GT templates apart.
    assert_eq!(
        p.vanilla.clusters, 3,
        "vanilla merges ALLOW/DENY inside each of the 3 families"
    );
    assert_eq!(p.tiered.clusters, 6, "3-tier keeps every GT template apart");
    assert_eq!(
        p.vanilla.grouping_accuracy_pct, 50.0,
        "mixed clusters score majority"
    );
    assert_eq!(p.tiered.grouping_accuracy_pct, 100.0);

    // Template fidelity: add_log returns the POST-update template, so the
    // first two lines of each family (same side, template unchanged) still
    // reproduce GT; the cross-action merge wildcards the action word from
    // line 3 on → 6 of 12 lines match. FTA: only the 3 allow-side mined
    // templates survive suffix-match → P=R=50 → F1 50.
    assert_eq!(
        p.vanilla.parsing_accuracy_pct,
        Some(50.0),
        "merged clusters keep the first side literal, wildcard the second"
    );
    assert_eq!(p.tiered.parsing_accuracy_pct, Some(100.0));
    assert_eq!(p.vanilla.template_f1_pct, Some(50.0));
    assert_eq!(p.tiered.template_f1_pct, Some(100.0));

    // Action Inviolability: every vanilla family cluster mixes sides.
    assert_eq!(p.vanilla.action_violations, Some(3));
    assert_eq!(
        p.tiered.action_violations,
        Some(0),
        "anchor subsystem holds: zero mixed-disposition clusters"
    );
}

#[test]
fn adversarial_round_tiered_grouping_at_least_vanilla() {
    let r = report();
    let p = round(&r, "R2 fuzzed");
    assert!(
        p.tiered.grouping_accuracy_pct >= p.vanilla.grouping_accuracy_pct,
        "tiered GA ({:.2}) must be >= vanilla GA ({:.2}) on mutations",
        p.tiered.grouping_accuracy_pct,
        p.vanilla.grouping_accuracy_pct
    );
    // Measured: vanilla 17 mixed clusters (415 disposition lines), tiered 10
    // (116). Anchors REDUCE but do not eliminate mixing on this corpus: a
    // syslog/relay prefix or mid-line CR keeps a space in the payload, so the
    // tokenizer fuses the CSV/JSON into one token and the action word never
    // reaches the anchor vocabulary. Finding is reported, NOT tuned away —
    // the fix must be validated on unseen data (see eval_duel_report.md).
    assert!(
        p.tiered.action_violations < p.vanilla.action_violations,
        "anchors must reduce mixing: tiered {:?} vs vanilla {:?}",
        p.tiered.action_violations,
        p.vanilla.action_violations
    );
    // The sidecar carries tags, not full templates: PA/FTA are honestly n/a.
    assert_eq!(p.vanilla.parsing_accuracy_pct, None);
    assert_eq!(p.tiered.parsing_accuracy_pct, None);
    assert_eq!(p.vanilla.template_f1_pct, None);
}

#[test]
fn loghub_rounds_compute_metrics_within_bounds() {
    let r = report();
    for name in ["R3 BGL", "R3 TBird"] {
        let p = round(&r, name);
        assert_eq!(p.lines, 2000);
        assert!(
            p.gt_classes >= 100,
            "LogPAI EventTemplates loaded for {name}"
        );
        for (label, e) in [("vanilla", &p.vanilla), ("3-tier", &p.tiered)] {
            assert!(e.clusters >= 1, "{name}/{label} mined at least one cluster");
            for (metric, v) in [
                ("GA", e.grouping_accuracy_pct),
                (
                    "PA",
                    e.parsing_accuracy_pct.expect("LogHub GT is full-template"),
                ),
                (
                    "FTA",
                    e.template_f1_pct.expect("LogHub GT is full-template"),
                ),
            ] {
                assert!(
                    (0.0..=100.0).contains(&v),
                    "{name}/{label} {metric} out of bounds: {v}"
                );
            }
            assert_eq!(e.action_violations, None, "no disposition GT on LogHub");
        }
        assert_eq!(p.tiered_panics, 0);
        assert_eq!(p.tiered_lossless_ok, p.lines);
        // No pre-asserted winner here: the duel reports whatever the corpora
        // say. Both directions are legitimate outcomes.
    }
}

#[test]
fn markdown_documents_formulas_engines_and_caveats() {
    let md = report().to_markdown();
    for needle in [
        "GA (grouping accuracy)",
        "PA (parsing accuracy)",
        "FTA (template F1, set-level)",
        "anchors_enabled",
        "out-of-band",
        "R1 probe",
        "R3 TBird",
        "LogHub",
        "suffix",
        "not a gate",
        "not tuned away",
    ] {
        assert!(
            md.contains(needle),
            "report must document {needle:?}:\n{md}"
        );
    }
}
