//! `ulpf scorecard` — one-command, screenshot-ready evaluation dashboard.
//!
//! Runs both engines (frozen `UniversalParser` baseline vs the 3-tier
//! pipeline) over the requested corpus and prints a single ASCII-only box:
//! run config, throughput, latency spectrum with deltas, ground-truth
//! accuracy audit, tier telemetry, pass/fail gates and a plain-words verdict.
//!
//! Design rules (see README review feedback):
//! - **ASCII-only** (plus `µs`): no ANSI escapes, so a copy-paste or
//!   screenshot always lines up; every row is padded to fixed column widths
//!   (36 / 21 / 21 / 13 = 100 columns total).
//! - **Honest gates**: Action Inviolability must be 100%, GA over 90%, LRU
//!   hit rate over 90%, lossless SHA-256 = 100%, zero panics, and the p50
//!   under 5.0 µs (core-corpus calibrated; over-the-line results on non-core
//!   corpora are reported as `TRACKED`, matching README section 14, not FAIL).
//! - The verdict block prints the report path and the exact re-run command.

use ulpf_ai::evaluator::{BenchmarkTierResult, EvaluationReport};

/// Total box width in columns (matches the width judges know from the
/// original dashboard).
const W: usize = 100;
/// Label column width.
const W_LABEL: usize = 36;
/// Baseline / 3-tier value column width.
const W_VAL: usize = 21;
/// Delta / status column width.
const W_DELTA: usize = 13;

/// Render the full scorecard box for a dual-engine evaluation report.
///
/// `report_path` is echoed in the verdict so a screenshot carries the
/// pointer to the committed markdown evidence.
pub fn render(report: &EvaluationReport, report_path: &str) -> String {
    let (Some(b), Some(t)) = (&report.baseline, &report.tiered_pipeline) else {
        let mut out = String::new();
        out.push_str(&rule('='));
        out.push_str(&title("ULPF SCORECARD - EVALUATION INCOMPLETE"));
        out.push_str("  Both engines were not measured. Run:\n");
        out.push_str("  ./target/release/ulpf evaluate --engine all\n");
        out.push_str(&rule('='));
        return out;
    };

    let mut out = String::new();
    out.push_str(&rule('='));
    out.push_str(&title("ULPF SCORECARD - BASELINE vs 3-TIER PIPELINE"));
    out.push_str(&rule('='));

    out.push_str(&config(
        "Execution Mode",
        &format!("{} (baseline vs 3-tier)", report.mode.to_uppercase()),
    ));
    out.push_str(&config("CPU Threads", &report.threads.to_string()));
    out.push_str(&config(
        "Duration",
        &format!("{} seconds per engine", report.duration_secs),
    ));
    out.push_str(&config(
        "Corpus",
        &format!(
            "{}, {} lines ({:.2} KB in RAM)",
            report.corpus_kind,
            commas(report.corpus_size as u64),
            report.corpus_total_bytes as f64 / 1024.0
        ),
    ));
    out.push_str(&config("Generated", &report.timestamp));
    out.push_str(&rule('-'));

    // --- Throughput & bandwidth ---------------------------------------
    out.push_str(&section("THROUGHPUT & BANDWIDTH"));
    let (be, te) = (b.throughput.events_per_sec, t.throughput.events_per_sec);
    out.push_str(&row(
        "Events per second",
        &commas_f(be),
        &commas_f(te),
        &ratio(be, te),
    ));
    let (bb, tb) = (
        b.throughput.megabytes_per_sec,
        t.throughput.megabytes_per_sec,
    );
    out.push_str(&row(
        "Bandwidth (MB/s)",
        &format!("{bb:.2}"),
        &format!("{tb:.2}"),
        &ratio(bb, tb),
    ));
    let (bt, tt) = (
        b.throughput.total_processed as f64,
        t.throughput.total_processed as f64,
    );
    out.push_str(&row(
        "Total events processed",
        &commas(b.throughput.total_processed),
        &commas(t.throughput.total_processed),
        &ratio(bt, tt),
    ));
    let (bp, tp) = (b.throughput.per_core_eps, t.throughput.per_core_eps);
    out.push_str(&row(
        "Per-core throughput EPS",
        &commas_f(bp),
        &commas_f(tp),
        &ratio(bp, tp),
    ));
    out.push_str(&rule('-'));

    // --- Latency spectrum ----------------------------------------------
    out.push_str(&section("LATENCY DISTRIBUTION (µs)"));
    for (label, bv, tv) in [
        (
            "Minimum latency (p0)",
            b.latency.min_micros,
            t.latency.min_micros,
        ),
        (
            "1st percentile (p1)",
            b.latency.p1_micros,
            t.latency.p1_micros,
        ),
        (
            "Median latency (p50)",
            b.latency.p50_micros,
            t.latency.p50_micros,
        ),
        (
            "90th percentile (p90)",
            b.latency.p90_micros,
            t.latency.p90_micros,
        ),
        (
            "99th percentile (p99)",
            b.latency.p99_micros,
            t.latency.p99_micros,
        ),
        (
            "99.9th percentile (p99.9)",
            b.latency.p999_micros,
            t.latency.p999_micros,
        ),
        (
            "Worst case (max)",
            b.latency.max_micros,
            t.latency.max_micros,
        ),
        (
            "Latency jitter (StdDev)",
            b.latency.std_dev_micros,
            t.latency.std_dev_micros,
        ),
    ] {
        out.push_str(&row(label, &us(bv), &us(tv), &delta_pct(bv, tv)));
    }
    out.push_str(&rule('-'));

    // --- Accuracy audit -------------------------------------------------
    out.push_str(&section("ACCURACY AUDIT (GROUND-TRUTH GRADED)"));
    for (label, bv, tv) in [
        (
            "Vendor classification (VCA)",
            b.accuracy.vendor_classification_accuracy_pct,
            t.accuracy.vendor_classification_accuracy_pct,
        ),
        (
            "Grouping accuracy (GA)",
            b.accuracy.grouping_accuracy_ga_pct,
            t.accuracy.grouping_accuracy_ga_pct,
        ),
        (
            "Template accuracy (TA)",
            b.accuracy.template_accuracy_ta_pct,
            t.accuracy.template_accuracy_ta_pct,
        ),
        (
            "Mean field accuracy (aka Macro F1)",
            b.accuracy.field_extraction_f1_pct,
            t.accuracy.field_extraction_f1_pct,
        ),
        (
            "  - source IP",
            b.accuracy.src_ip_accuracy_pct,
            t.accuracy.src_ip_accuracy_pct,
        ),
        (
            "  - destination IP",
            b.accuracy.dst_ip_accuracy_pct,
            t.accuracy.dst_ip_accuracy_pct,
        ),
        (
            "  - source port",
            b.accuracy.src_port_accuracy_pct,
            t.accuracy.src_port_accuracy_pct,
        ),
        (
            "  - destination port",
            b.accuracy.dst_port_accuracy_pct,
            t.accuracy.dst_port_accuracy_pct,
        ),
        (
            "  - protocol",
            b.accuracy.protocol_accuracy_pct,
            t.accuracy.protocol_accuracy_pct,
        ),
        (
            "Disposition resolution accuracy",
            b.accuracy.disposition_accuracy_pct,
            t.accuracy.disposition_accuracy_pct,
        ),
        (
            "UUIDv7 event IDs",
            b.accuracy.valid_uuid_v7_pct,
            t.accuracy.valid_uuid_v7_pct,
        ),
    ] {
        out.push_str(&row(label, &pct(bv), &pct(tv), &pt_delta(bv, tv)));
    }
    // Action inviolability: the baseline has no template clustering, so its
    // value is meaningless (n/a) — only the 3-tier engine is graded here.
    let inviol = t.accuracy.action_inviolability_pct;
    out.push_str(&row(
        "Action inviolability (ALLOW/DENY)",
        "n/a",
        &pct(inviol),
        if inviol >= 99.999 {
            "100% held"
        } else {
            "BREACH"
        },
    ));
    out.push_str(&row(
        "Unique templates (compression)",
        &commas(b.accuracy.unique_clusters as u64),
        &commas(t.accuracy.unique_clusters as u64),
        &compression(
            t.accuracy.unique_clusters as u64,
            b.accuracy.unique_clusters as u64,
        ),
    ));
    out.push_str(&rule('-'));

    // --- Multi-tier telemetry (3-tier only) ------------------------------
    out.push_str(&section("MULTI-TIER TELEMETRY"));
    if let Some(d) = &t.tier_diagnostics {
        out.push_str(&row(
            "Tier-1 LRU hit ratio",
            "n/a (no cache)",
            &pct(d.tier1_lru_hit_rate * 100.0),
            "-",
        ));
        out.push_str(&row(
            "Tier-2 Drain clusters",
            "0",
            &commas(d.tier2_clusters_count as u64),
            "-",
        ));
        out.push_str(&row(
            "Tier-2 anchor tokens enforced",
            "n/a",
            if d.tier2_unique_anchor_enforced {
                "enforced"
            } else {
                "VIOLATED"
            },
            "-",
        ));
        out.push_str(&row(
            "Tier-3 Laya dispatches",
            "0",
            &commas(d.tier3_laya_dispatches),
            "-",
        ));
        out.push_str(&row(
            "AI deduplication ratio",
            "n/a",
            &pct(d.tier3_ai_deduplication_pct),
            "-",
        ));
    } else {
        out.push_str(&row("Tier telemetry", "n/a", "not reported", "-"));
    }
    out.push_str(&rule('-'));

    // --- Gates -----------------------------------------------------------
    out.push_str(&section_named(
        "GATE CHECKS",
        "MEASURED",
        "THRESHOLD",
        "STATUS",
    ));
    let gate_rows = build_gates(report, t);
    for g in &gate_rows {
        out.push_str(&row(g.label, &g.measured, g.threshold, g.status));
    }
    out.push_str(&rule('='));

    // --- Verdict ---------------------------------------------------------
    let total = gate_rows.len();
    let pass = gate_rows.iter().filter(|g| g.status == "PASS").count();
    let fail = gate_rows.iter().filter(|g| g.status == "FAIL").count();
    let tracked = gate_rows.iter().filter(|g| g.status == "TRACKED").count();

    out.push_str("VERDICT\n");
    out.push_str(&format!(
        "  VCA {}, GA {}, TA {}, mean field accuracy {}\n",
        pct(t.accuracy.vendor_classification_accuracy_pct),
        pct(t.accuracy.grouping_accuracy_ga_pct),
        pct(t.accuracy.template_accuracy_ta_pct),
        pct(t.accuracy.field_extraction_f1_pct),
    ));
    out.push_str(&format!(
        "  Latency: median {} ({}), p99 {} ({}) vs baseline\n",
        us(t.latency.p50_micros),
        delta_pct(b.latency.p50_micros, t.latency.p50_micros),
        us(t.latency.p99_micros),
        delta_pct(b.latency.p99_micros, t.latency.p99_micros),
    ));
    out.push_str(&format!(
        "  Throughput: {} EPS ({} vs baseline)\n",
        commas_f(te),
        ratio(be, te),
    ));
    let mut tally = format!("  Gates: {pass}/{total} PASS");
    if fail > 0 {
        tally.push_str(&format!(" ({fail} FAIL)"));
    }
    if tracked > 0 {
        tally.push_str(&format!(" ({tracked} TRACKED - README 14)"));
    }
    out.push_str(&tally);
    out.push('\n');
    out.push_str(&format!("  Report: {report_path}\n"));
    out.push_str(&format!(
        "  Re-run: ./target/release/ulpf scorecard --corpus {}\n",
        report.corpus_kind
    ));
    out.push_str(&rule('='));

    out
}

/// One computed gate row (label / measured / threshold / status).
struct GateRow {
    label: &'static str,
    measured: String,
    threshold: &'static str,
    status: &'static str,
}

/// The gate set, shared by the GATE CHECKS section and the verdict tally.
///
/// The p50 < 5.0 µs gate is calibrated on the core corpus (README section 14):
/// a non-core corpus that misses it is reported `TRACKED`, not `FAIL`, so the
/// display never contradicts the honest-limitations section.
fn build_gates(report: &EvaluationReport, t: &BenchmarkTierResult) -> Vec<GateRow> {
    let mut g = Vec::new();
    let a = &t.accuracy;

    g.push(GateRow {
        label: "Action inviolability (ALLOW/DENY)",
        measured: pct(a.action_inviolability_pct),
        threshold: "must be 100%",
        status: if a.action_inviolability_pct >= 99.999 {
            "PASS"
        } else {
            "FAIL"
        },
    });
    g.push(GateRow {
        label: "Grouping accuracy (GA)",
        measured: pct(a.grouping_accuracy_ga_pct),
        threshold: "> 90%",
        status: if a.grouping_accuracy_ga_pct > 90.0 {
            "PASS"
        } else {
            "FAIL"
        },
    });
    if let Some(d) = &t.tier_diagnostics {
        g.push(GateRow {
            label: "Tier-1 LRU hit ratio",
            measured: pct(d.tier1_lru_hit_rate * 100.0),
            threshold: "> 90%",
            status: if d.tier1_lru_hit_rate > 0.90 {
                "PASS"
            } else {
                "FAIL"
            },
        });
    }
    g.push(GateRow {
        label: "Lossless SHA-256 (every line)",
        measured: pct(a.lossless_sha256_match_pct),
        threshold: "must be 100%",
        status: if a.lossless_sha256_match_pct >= 99.999 {
            "PASS"
        } else {
            "FAIL"
        },
    });
    if t.robustness.lines_total > 0 {
        g.push(GateRow {
            label: "No parse panics",
            measured: format!(
                "{} / {}",
                commas(t.robustness.no_panic as u64),
                commas(t.robustness.lines_total as u64)
            ),
            threshold: "0 panics",
            status: if t.robustness.no_panic == t.robustness.lines_total {
                "PASS"
            } else {
                "FAIL"
            },
        });
    }
    g.push(GateRow {
        label: "Median latency p50 (core gate)",
        measured: us(t.latency.p50_micros),
        threshold: "< 5.00 µs (core gate)",
        status: if t.latency.p50_micros < 5.0 {
            "PASS"
        } else if report.corpus_kind == "core" {
            "FAIL"
        } else {
            "TRACKED"
        },
    });
    g
}

/// `====...` separator line of the box width.
fn rule(ch: char) -> String {
    format!("{}\n", ch.to_string().repeat(W))
}

/// Centered box title.
fn title(text: &str) -> String {
    format!("{:^W$}\n", text)
}

/// Two-space indented config line.
fn config(label: &str, value: &str) -> String {
    format!("  {label:<21}: {value}\n")
}

/// Section header row over the standard three comparison columns.
fn section(name: &str) -> String {
    section_named(name, "BASELINE", "3-TIER PIPELINE", "VS BASE")
}

/// Section header row with custom column names.
fn section_named(name: &str, c2: &str, c3: &str, c4: &str) -> String {
    row(name, c2, c3, c4)
}

/// One aligned table row: 36 / 21 / 21 / 13 columns (= 100 total).
fn row(label: &str, b: &str, t: &str, d: &str) -> String {
    format!("{label:<W_LABEL$} | {b:<W_VAL$} | {t:<W_VAL$} | {d:<W_DELTA$}\n")
}

/// Thousands-grouped integer.
fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.char_indices() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Thousands-grouped, rounded float (EPS-style values).
fn commas_f(v: f64) -> String {
    commas(v.round().max(0.0) as u64)
}

/// `100.00%`
fn pct(v: f64) -> String {
    format!("{v:.2}%")
}

/// `3.02 µs`
fn us(v: f64) -> String {
    format!("{v:.2} µs")
}

/// Signed relative change: `(new - base) / base` as `-96.2%`.
fn delta_pct(base: f64, new: f64) -> String {
    if base == 0.0 {
        return "-".to_string();
    }
    format!("{:+.1}%", (new - base) / base * 100.0)
}

/// Throughput-style multiplier: `2.15x`.
fn ratio(base: f64, new: f64) -> String {
    if base == 0.0 {
        return "-".to_string();
    }
    format!("{:.2}x", new / base)
}

/// Percentage-point difference for accuracy rows: `=` / `-1.6 pt`.
fn pt_delta(base: f64, new: f64) -> String {
    if (new - base).abs() < 0.005 {
        "=".to_string()
    } else {
        format!("{:+.1} pt", new - base)
    }
}

/// Template-compression delta: fewer templates = `19.3x fewer`.
fn compression(tiered: u64, baseline: u64) -> String {
    if tiered == baseline {
        "=".to_string()
    } else if tiered < baseline {
        format!("{:.1}x fewer", baseline as f64 / tiered as f64)
    } else {
        format!("{:.1}x more", tiered as f64 / baseline as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulpf_ai::evaluator::{
        AccuracyAuditSummary, BenchmarkTierResult, HardwareThroughputSummary, LatencySummary,
        RobustnessSummary, TierDiagnosticsSummary,
    };

    fn acc(
        vca: f64,
        ga: f64,
        ta: f64,
        f1: f64,
        disp: f64,
        inviol: f64,
        clusters: usize,
    ) -> AccuracyAuditSummary {
        AccuracyAuditSummary {
            total_audited: 1720,
            vendor_classification_accuracy_pct: vca,
            grouping_accuracy_ga_pct: ga,
            template_accuracy_ta_pct: ta,
            field_extraction_f1_pct: f1,
            src_ip_accuracy_pct: 100.0,
            dst_ip_accuracy_pct: 100.0,
            src_port_accuracy_pct: 100.0,
            dst_port_accuracy_pct: 100.0,
            protocol_accuracy_pct: 100.0,
            disposition_accuracy_pct: disp,
            action_inviolability_pct: inviol,
            lossless_sha256_match_pct: 100.0,
            valid_uuid_v7_pct: 100.0,
            oracle_ga_pct: 100.0,
            unique_clusters: clusters,
        }
    }

    fn lat(p50: f64, p99: f64) -> LatencySummary {
        LatencySummary {
            min_micros: p50 * 0.8,
            p1_micros: p50 * 0.85,
            p5_micros: p50 * 0.9,
            p25_micros: p50 * 0.95,
            p50_micros: p50,
            p75_micros: p50 * 1.05,
            p90_micros: p50 * 1.1,
            p95_micros: p99 * 0.9,
            p99_micros: p99,
            p999_micros: p99 * 1.1,
            p9999_micros: p99 * 1.2,
            max_micros: p99 * 1.3,
            mean_micros: p50 * 1.1,
            std_dev_micros: p50 * 0.2,
            samples_count: 10000,
        }
    }

    fn thr(eps: f64) -> HardwareThroughputSummary {
        HardwareThroughputSummary {
            events_per_sec: eps,
            megabytes_per_sec: eps / 5090.0,
            events_per_ms_per_core: eps / 1000.0,
            per_core_eps: eps / 16.0,
            total_processed: 2_000_000,
            total_bytes_processed: 463_500,
            duration_secs: 3.0,
        }
    }

    fn diag() -> TierDiagnosticsSummary {
        TierDiagnosticsSummary {
            tier1_lru_hit_rate: 0.96,
            tier1_lookups: 1000,
            tier1_hits: 960,
            tier1_misses: 40,
            tier1_evictions: 5,
            tier1_entries_count: 8192,
            tier2_clusters_count: 73,
            tier2_cluster_matches: 900,
            tier2_unique_anchor_enforced: true,
            tier3_laya_dispatches: 12,
            tier3_ai_deduplication_pct: 100.0,
            tier3_auto_onboarded_count: 0,
        }
    }

    fn engine(
        name: &str,
        eps: f64,
        p50: f64,
        p99: f64,
        accuracy: AccuracyAuditSummary,
        diag: Option<TierDiagnosticsSummary>,
    ) -> BenchmarkTierResult {
        BenchmarkTierResult {
            name: name.to_string(),
            throughput: thr(eps),
            latency: lat(p50, p99),
            accuracy,
            tier_diagnostics: diag,
            failures: Vec::new(),
            robustness: RobustnessSummary {
                lines_total: 1720,
                no_panic: 1720,
                lossless_ok: 1720,
                ..RobustnessSummary::default()
            },
        }
    }

    fn sample_report() -> EvaluationReport {
        EvaluationReport {
            timestamp: "2026-09-24T12:00:00Z".to_string(),
            mode: "all".to_string(),
            threads: 16,
            duration_secs: 3,
            corpus_size: 1720,
            corpus_total_bytes: 463_500,
            baseline: Some(engine(
                "Baseline (UniversalParser)",
                395_842.0,
                79.23,
                1510.92,
                acc(100.0, 100.0, 100.0, 100.0, 100.0, 0.0, 1407),
                None,
            )),
            tiered_pipeline: Some(engine(
                "3-Tier (LRU+Drain+Laya)",
                849_481.0,
                3.02,
                10.97,
                acc(100.0, 96.41, 100.0, 100.0, 100.0, 100.0, 73),
                Some(diag()),
            )),
            throughput_speedup_factor: Some(2.1459),
            bandwidth_speedup_factor: Some(2.1459),
            latency_reduction_p50_pct: Some(96.19),
            latency_reduction_p99_pct: Some(99.27),
            corpus_kind: "core".to_string(),
        }
    }

    #[test]
    fn renders_nonempty_ascii_only_box() {
        let out = render(&sample_report(), "scorecard_report.md");
        assert!(!out.is_empty(), "render must produce output");
        for ch in out.chars() {
            assert!(
                ch.is_ascii() || ch == 'µ',
                "non-ASCII char {ch:?} in scorecard output:\n{out}"
            );
        }
        assert!(
            !out.contains('\u{1b}'),
            "no ANSI escapes (a pasted screenshot must line up):\n{out}"
        );
    }

    #[test]
    fn latency_and_throughput_deltas_computed() {
        let out = render(&sample_report(), "scorecard_report.md");
        assert!(
            out.contains("-96.2%"),
            "p50 79.23 -> 3.02 must show -96.2%:\n{out}"
        );
        assert!(
            out.contains("-99.3%"),
            "p99 1510.92 -> 10.97 must show -99.3%:\n{out}"
        );
        assert!(
            out.contains("2.15x"),
            "EPS 395,842 -> 849,481 must show 2.15x:\n{out}"
        );
    }

    #[test]
    fn every_table_row_has_fixed_column_widths() {
        let out = render(&sample_report(), "scorecard_report.md");
        let mut rows = 0;
        for line in out.lines().filter(|l| l.contains(" | ")) {
            rows += 1;
            let parts: Vec<&str> = line.split(" | ").collect();
            assert_eq!(parts.len(), 4, "row must have 4 columns: {line:?}");
            assert_eq!(parts[0].chars().count(), W_LABEL, "label width: {line:?}");
            assert_eq!(parts[1].chars().count(), W_VAL, "baseline width: {line:?}");
            assert_eq!(parts[2].chars().count(), W_VAL, "3-tier width: {line:?}");
            assert_eq!(parts[3].chars().count(), W_DELTA, "delta width: {line:?}");
        }
        assert!(rows >= 20, "expected a full table, got {rows} rows");
    }

    #[test]
    fn healthy_report_passes_all_gates() {
        let out = render(&sample_report(), "scorecard_report.md");
        assert!(out.contains("GATE CHECKS"), "gates section missing:\n{out}");
        assert!(
            !out.contains("FAIL"),
            "no gate may fail on the healthy sample:\n{out}"
        );
        assert!(
            out.contains("Gates: 6/6 PASS"),
            "verdict must tally 6/6 PASS:\n{out}"
        );
    }

    #[test]
    fn inviolability_drop_fails_the_gate() {
        let mut r = sample_report();
        r.tiered_pipeline
            .as_mut()
            .unwrap()
            .accuracy
            .action_inviolability_pct = 99.0;
        let out = render(&r, "scorecard_report.md");
        assert!(
            out.contains("FAIL"),
            "broken inviolability must FAIL:\n{out}"
        );
        assert!(
            out.contains("Gates: 5/6 PASS"),
            "verdict must show 5/6:\n{out}"
        );
    }

    #[test]
    fn over_gate_on_non_core_corpus_is_tracked_not_failed() {
        let mut r = sample_report();
        r.corpus_kind = "full".to_string();
        r.tiered_pipeline.as_mut().unwrap().latency.p50_micros = 7.28;
        let out = render(&r, "scorecard_report.md");
        assert!(
            out.contains("TRACKED"),
            "non-core over-gate is tracked (README 14):\n{out}"
        );
        assert!(!out.contains("FAIL"), "must not FAIL off-corpus:\n{out}");
    }

    #[test]
    fn verdict_carries_headlines_report_path_and_rerun_hint() {
        let out = render(&sample_report(), "my_report.md");
        assert!(out.contains("VERDICT"), "verdict block missing:\n{out}");
        assert!(out.contains("VCA 100.00%"), "VCA headline:\n{out}");
        assert!(out.contains("GA 96.41%"), "GA headline:\n{out}");
        assert!(out.contains("median"), "median latency headline:\n{out}");
        assert!(
            out.contains("my_report.md"),
            "report path must appear in the box:\n{out}"
        );
        assert!(
            out.contains("./target/release/ulpf scorecard"),
            "re-run hint must appear:\n{out}"
        );
    }

    #[test]
    fn no_line_exceeds_the_box_width() {
        let out = render(&sample_report(), "scorecard_report.md");
        for line in out.lines() {
            assert!(
                line.chars().count() <= W,
                "line wider than {W} ({} cols): {line:?}",
                line.chars().count()
            );
        }
    }

    #[test]
    fn missing_engine_renders_incomplete_instead_of_panicking() {
        let mut r = sample_report();
        r.tiered_pipeline = None;
        let out = render(&r, "scorecard_report.md");
        assert!(
            out.contains("INCOMPLETE"),
            "missing engine must render an incomplete notice:\n{out}"
        );
    }
}
