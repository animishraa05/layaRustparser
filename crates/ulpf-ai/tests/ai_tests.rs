use std::time::Instant;
use ulpf_ai::{
    AlertSeverity, AnomalyType, DrainConfig, DrainMiner, DynamicParserRegistry, Onboarder,
};
use ulpf_core::schema::ocsf::{activity_id, disposition, CLASS_UID_NETWORK_ACTIVITY};

// ============================================================================
// 1. DRAIN3 TEMPLATE EXTRACTION & CLUSTERING TESTS
// ============================================================================

#[test]
fn test_drain_template_clustering_cisco_asa() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    let log1 = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 (203.0.113.54/25) to inside:10.1.6.180/52369 (198.51.100.209/52369)";
    let log2 = "%ASA-6-302013: Built outbound TCP connection 1000673 for outside:198.51.100.12/80 (198.51.100.12/80) to inside:10.2.4.99/44123 (198.51.100.210/44123)";
    let log3 = "%ASA-6-302013: Built outbound TCP connection 1000674 for outside:192.0.2.1/443 (192.0.2.1/443) to inside:10.3.1.20/33120 (198.51.100.211/33120)";

    let res1 = miner.add_log(log1);
    assert_eq!(res1.cluster_id, 1);
    assert!(
        res1.anomaly.is_some(),
        "First occurrence should trigger NewTemplate alert"
    );
    assert_eq!(res1.anomaly.unwrap().anomaly_type, AnomalyType::NewTemplate);

    let res2 = miner.add_log(log2);
    assert_eq!(
        res2.cluster_id, 1,
        "Log 2 should match existing Cisco ASA template"
    );
    assert!(
        res2.anomaly.is_none(),
        "Matched template should not trigger alert"
    );

    let res3 = miner.add_log(log3);
    assert_eq!(
        res3.cluster_id, 1,
        "Log 3 should match existing Cisco ASA template"
    );

    let cluster = miner.get_cluster(1).expect("Cluster 1 must exist");
    assert_eq!(cluster.count, 3);
    assert!(
        cluster.template.contains("<*>"),
        "Template should contain wildcard token"
    );
}

#[test]
fn test_drain_template_clustering_fortinet() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    let log1 = r#"date=2026-09-21 time=14:00:02 devname="FGT-DC-EDGE" devid="FGT60D4614041123" logid="0000000019" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.7.45 srcport=29853 dstip=203.0.113.46 dstport=53 proto=17 action="timeout""#;
    let log2 = r#"date=2026-09-21 time=14:00:05 devname="FGT-CORP-FW01" devid="FGT100E391780045" logid="0000000003" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.5.14 srcport=50470 dstip=198.51.100.22 dstport=3389 proto=6 action="accept""#;

    let res1 = miner.add_log(log1);
    assert!(res1.is_new);
    assert!(
        res1.template.contains("<*>"),
        "Fortinet template must contain masked tokens: {}",
        res1.template
    );

    let res2 = miner.add_log(log2);
    assert!(res2.template.contains("<*>"));
}

#[test]
fn test_drain_template_clustering_palo_alto() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    let log1 = "1,2026/09/21 14:00:01,001801000001,TRAFFIC,deny,2304,2026/09/21 14:00:00,192.168.1.19,203.0.113.87,198.51.100.32,203.0.113.87,Trust_to_Untrust,acme\\agarcia,,ping,vsys1,DMZ,WAN,ethernet1/1,ethernet1/2,default,,100412,1,0,0,0,0,0x400000,icmp,drop,4983547,454039,4529508,9510,2026/09/21 13:56:28,213,web-hosting,0,100000129,0x0";
    let log2 = "1,2026/09/21 14:00:04,001801000003,TRAFFIC,drop,2304,2026/09/21 14:00:04,192.168.1.19,198.51.100.128,198.51.100.30,198.51.100.128,Trust_to_Untrust,acme\\dchen,,ntp,vsys1,Trust,Untrust,ethernet1/1,ethernet1/2,default,,100674,1,37269,123,37269,123,0x400000,udp,drop,3271827,863823,2408004,5870,2026/09/21 13:54:12,352,content-delivery-networks,0,100002795,0x0";

    let res1 = miner.add_log(log1);
    assert!(res1.is_new);
    assert!(
        res1.template.contains("<*>"),
        "Palo Alto template must mask dynamic fields: {}",
        res1.template
    );

    let res2 = miner.add_log(log2);
    assert!(res2.template.contains("<*>"));
}

// ============================================================================
// 2. ANOMALY DETECTION TESTS
// ============================================================================

#[test]
fn test_drain_anomaly_detection_unknown_template() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    // Ingest standard logs
    miner.add_log("%ASA-6-302013: Built outbound TCP connection 1001 for outside:1.1.1.1/80 to inside:2.2.2.2/1000");
    miner.add_log("%ASA-6-302013: Built outbound TCP connection 1002 for outside:1.1.1.2/80 to inside:2.2.2.3/1001");

    // Ingest radically different structural log (e.g. unknown proprietary alert)
    let attack_log = "ALERT_MALICIOUS_BUFFER_OVERFLOW: exploit attempt detected from 45.33.32.156 target_port=445 payload_size=1024";
    let res = miner.add_log(attack_log);

    assert_eq!(
        res.cluster_id, 2,
        "Novel structural log must create a new cluster"
    );
    assert!(res.anomaly.is_some(), "Must generate anomaly alert");
    let alert = res.anomaly.unwrap();
    assert_eq!(alert.anomaly_type, AnomalyType::NewTemplate);
    assert_eq!(alert.severity, AlertSeverity::Medium);
}

#[test]
fn test_drain_rare_cluster_surge() {
    let config = DrainConfig {
        rare_count_threshold: 3,
        surge_multiplier: 1.0,
        ..Default::default()
    };
    let mut miner = DrainMiner::new(config);

    // Establish baseline cluster
    for i in 0..20 {
        miner.add_log(&format!("SYSTEM_HEARTBEAT: status=OK node=worker-{}", i));
    }

    // Create a rare anomaly cluster
    let rare_log = "SECURITY_ALERT: Unauthorized privilege escalation detected by user admin";
    let res_rare1 = miner.add_log(rare_log);
    assert!(res_rare1.is_new);

    // Blast the rare cluster with a sudden surge in traffic
    let mut surge_alert_triggered = false;
    for _ in 0..10 {
        let res = miner.add_log(rare_log);
        if let Some(ref alert) = res.anomaly {
            if alert.anomaly_type == AnomalyType::RareClusterSurge {
                surge_alert_triggered = true;
                assert_eq!(alert.severity, AlertSeverity::High);
                break;
            }
        }
    }

    assert!(
        surge_alert_triggered,
        "Surging traffic on a previously rare cluster must trigger RareClusterSurge alert"
    );
}

// ============================================================================
// 3. 1-CLICK AIR-GAPPED ONBOARDING TESTS
// ============================================================================

#[test]
fn test_onboarder_synthesize_juniper_srx() {
    let samples = vec![
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.200.1.4/51234->198.51.100.25/80 None None 6 web-out trust untrust 12347 N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 172.16.5.20/38112->203.0.113.88/8080 None None 6 app-out trust dmz 12349 N/A(N/A) ge-0/0/1.0",
    ];

    let (parser_def, report) = Onboarder::generate_parser("juniper_srx", "srx-300", &samples)
        .expect("Synthesis must succeed");

    assert!(
        report.passed,
        "Synthesized parser must pass 100% validation: {:?}",
        report.errors
    );
    assert_eq!(report.total_samples, 3);
    assert_eq!(report.matched_samples, 3);

    // Test parsing a 4th unseen sample using the generated parser
    let test_log = "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.99.100/60000->8.8.8.8/53 None None 17 dns-out trust untrust 99999 N/A(N/A) ge-0/0/0.0";
    let event = parser_def.parse(test_log).expect("Must parse test log");

    assert_eq!(event.class_uid, CLASS_UID_NETWORK_ACTIVITY);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.99.100"));
    assert_eq!(event.src_endpoint.port, Some(60000));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("8.8.8.8"));
    assert_eq!(event.dst_endpoint.port, Some(53));
    assert_eq!(event.metadata.product.vendor_name, "juniper_srx");
    assert_eq!(event.activity_id, activity_id::OPEN);
    assert_eq!(event.disposition, disposition::ALLOWED);
}

#[test]
fn test_onboarder_checkpoint_format() {
    let samples = vec![
        "2026-09-21 14:00:01 CheckPoint-FW drop 192.168.10.15:52341 -> 10.0.0.25:443 proto TCP rule 101",
        "2026-09-21 14:00:02 CheckPoint-FW accept 192.168.10.16:52342 -> 10.0.0.25:80 proto TCP rule 102",
        "2026-09-21 14:00:03 CheckPoint-FW drop 192.168.10.17:52343 -> 10.0.0.26:53 proto UDP rule 103",
    ];

    let (parser_def, report) = Onboarder::generate_parser("CheckPoint", "Quantum", &samples)
        .expect("Failed to generate CheckPoint parser");

    assert!(
        report.passed,
        "Sandbox validation passed: {:?}",
        report.errors
    );
    assert_eq!(report.matched_samples, 3);

    let event1 = parser_def.parse(samples[0]).unwrap();
    assert_eq!(event1.src_endpoint.ip.as_deref(), Some("192.168.10.15"));
    assert_eq!(event1.src_endpoint.port, Some(52341));
    assert_eq!(event1.dst_endpoint.ip.as_deref(), Some("10.0.0.25"));
    assert_eq!(event1.dst_endpoint.port, Some(443));
    assert_eq!(event1.disposition, disposition::DROPPED);
    assert_eq!(event1.connection_info.protocol_name.as_deref(), Some("TCP"));

    let event2 = parser_def.parse(samples[1]).unwrap();
    assert_eq!(event2.disposition, disposition::ALLOWED);
    assert_eq!(event2.src_endpoint.ip.as_deref(), Some("192.168.10.16"));
}

#[test]
fn test_dynamic_parser_registry() {
    let mut registry = DynamicParserRegistry::new();

    let samples = vec![
        "FIREWALL_EVENT: pass proto=TCP src=192.168.1.10 srcport=44300 dst=10.0.0.5 dstport=80 action=allow",
        "FIREWALL_EVENT: pass proto=UDP src=192.168.1.15 srcport=53000 dst=8.8.8.8 dstport=53 action=allow",
        "FIREWALL_EVENT: pass proto=TCP src=192.168.1.20 srcport=44301 dst=10.0.0.6 dstport=80 action=allow",
    ];

    let (parser_def, report) =
        Onboarder::generate_parser("custom_waf", "waf-v1", &samples).expect("Synthesis");
    assert!(report.passed);
    registry.register(parser_def);

    assert_eq!(registry.len(), 1);

    let test_log = "FIREWALL_EVENT: pass proto=TCP src=172.16.0.1 srcport=33000 dst=192.168.1.1 dstport=22 action=allow";
    let parsed = registry
        .parse("custom_waf", test_log)
        .expect("Parse with custom_waf");
    assert_eq!(parsed.src_endpoint.ip.as_deref(), Some("172.16.0.1"));
    assert_eq!(parsed.src_endpoint.port, Some(33000));
    assert_eq!(parsed.dst_endpoint.ip.as_deref(), Some("192.168.1.1"));
    assert_eq!(parsed.dst_endpoint.port, Some(22));
}

// ============================================================================
// 4. MICROSECOND CPU PERFORMANCE VALIDATION
// ============================================================================

#[test]
fn test_drain_microsecond_performance() {
    let mut miner = DrainMiner::new(DrainConfig::default());
    let log = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 to inside:10.1.6.180/52369";

    // Warm-up
    miner.add_log(log);

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let res = miner.add_log(log);
        assert!(!res.is_new);
    }
    let total_micros = start.elapsed().as_micros();
    let avg_micros = (total_micros as f64) / (iterations as f64);

    #[cfg(debug_assertions)]
    let max_allowed_micros = 300.0; // Debug builds without compiler optimizations and under parallel thread contention
    #[cfg(not(debug_assertions))]
    let max_allowed_micros = 25.0; // Release optimized build

    assert!(
        avg_micros < max_allowed_micros,
        "Drain3 log template mining should take < {:.0} µs on CPU, took {:.2} µs",
        max_allowed_micros,
        avg_micros
    );
}

#[test]
fn test_drain_unique_event_patterns_anchor_tokens() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    // Two firewall logs with identical length and structure, differing only in action: ALLOW vs DENY
    let log_allow =
        "FIREWALL connection 1001 protocol TCP action ALLOW src 192.168.1.10 dst 10.0.0.1";
    let log_deny =
        "FIREWALL connection 1002 protocol TCP action DENY src 192.168.1.10 dst 10.0.0.1";

    let res1 = miner.add_log(log_allow);
    assert_eq!(res1.cluster_id, 1);
    assert!(res1.is_new);

    let res2 = miner.add_log(log_deny);
    // In vanilla Drain without anchor tokens, 8 out of 9 tokens match (88% similarity > 50% threshold),
    // which would improperly merge them into "FIREWALL connection <*> protocol TCP action <*> src <*> dst <*>".
    // With DrainDotNet's UniqueEventPatterns anchor tokens, ALLOW != DENY forces similarity to 0.0,
    // creating a distinct cluster!
    assert_eq!(
        res2.cluster_id, 2,
        "Anchor tokens (ALLOW vs DENY) must NEVER be merged into a single cluster"
    );
    assert!(res2.is_new);

    let cluster1 = miner.get_cluster(1).unwrap();
    let cluster2 = miner.get_cluster(2).unwrap();

    assert!(cluster1.template.contains("ALLOW"));
    assert!(cluster2.template.contains("DENY"));
}

#[test]
fn test_evaluator_comparative_run() {
    use ulpf_ai::EvaluatorEngine;

    let sample_corpus = vec![
        "%ASA-6-302013: Built inbound UDP connection 1001 for outside:1.1.1.1/53 to inside:2.2.2.2/53".to_string(),
        "%ASA-6-302013: Built inbound UDP connection 1002 for outside:1.1.1.2/53 to inside:2.2.2.3/53".to_string(),
        r#"date=2026-09-21 time=14:00:02 devname="FGT-DC-EDGE" type="traffic" srcip=10.0.0.1"#.to_string(),
        "1,2026/09/21 14:00:01,001801000001,TRAFFIC,deny,2304,2026/09/21 14:00:00,192.168.1.19,203.0.113.87,198.51.100.32,203.0.113.87,Trust_to_Untrust,acme\\agarcia,,ping,vsys1,DMZ,WAN,ethernet1/1,ethernet1/2,default,,100412,1,0,0,0,0,0x400000,icmp,drop,4983547,454039,4529508,9510,2026/09/21 13:56:28,213,web-hosting,0,100000129,0x0".to_string(),
    ];

    let report = EvaluatorEngine::evaluate(&sample_corpus, 1, 2);

    let baseline = report
        .baseline
        .as_ref()
        .expect("Baseline result should be present");
    assert!(baseline.throughput.events_per_sec > 0.0);
    assert!(baseline.accuracy.lossless_sha256_match_pct >= 99.0);
    assert!(baseline.accuracy.vendor_classification_accuracy_pct >= 95.0);

    let tiered = report
        .tiered_pipeline
        .as_ref()
        .expect("Tiered result should be present");
    assert!(tiered.throughput.events_per_sec > 0.0);
    assert!(tiered.accuracy.action_inviolability_pct >= 100.0);
    assert!(tiered.accuracy.grouping_accuracy_ga_pct >= 75.0);
    assert!(tiered.latency.p50_micros > 0.0);

    let md = report.to_markdown();
    assert!(md.contains("ULPF Hardcore Architectural"));

    let terminal_dash = report.render_terminal_dashboard();
    assert!(terminal_dash.contains("ULPF HARDCORE ARCHITECTURAL & ACCURACY EVALUATOR"));
}

// ============================================================================
// P1 — EVALUATOR GROUND-TRUTH / RULER TESTS (measurement-first fixes)
// ============================================================================

use ulpf_ai::drain::mask_line;
use ulpf_ai::EvaluatorEngine;

/// OCSF disposition alignment: deny is Blocked (disposition_id 2), never Dropped;
/// session-end states of permitted traffic are Allowed.
#[test]
fn test_gt_disposition_ocfs_alignment() {
    // ASA deny-by-policy -> Blocked
    let asa_deny = "<164>Sep 21 14:00:00 fw %ASA-4-106023: Deny tcp src outside:198.51.100.5/1234 dst inside:10.0.0.2/80 access-group out";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(asa_deny);
    assert_eq!(act.as_deref(), Some("Blocked"));

    // ASA built -> Allowed
    let asa_built = "<162>Sep 21 14:00:00 fw %ASA-6-302013: Built outbound TCP connection 1 for outside:10.0.0.1/1000 to inside:10.0.0.2/80";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(asa_built);
    assert_eq!(act.as_deref(), Some("Allowed"));

    // FortiGate deny -> Blocked
    let fgt_deny = r#"<189>date=2026-09-21 time=14:00:02 devname="FGT" logid="0000000019" type="traffic" action="deny" srcip=10.0.0.1 dstip=203.0.113.1 proto=6"#;
    let (v, t, act) = EvaluatorEngine::extract_ground_truth(fgt_deny);
    assert_eq!(v, "Fortinet");
    assert_eq!(t, "fortigate_traffic");
    assert_eq!(act.as_deref(), Some("Blocked"));

    // FortiGate session-end (timeout/close/rst) -> Allowed, not Unknown
    for action in ["timeout", "close", "client-rst", "server-rst"] {
        let raw = format!(
            r#"<189>date=2026-09-21 time=14:00:02 devname="FGT" logid="0000000019" type="traffic" action="{action}" srcip=10.0.0.1 dstip=203.0.113.1 proto=6"#
        );
        let (_, _, act) = EvaluatorEngine::extract_ground_truth(&raw);
        assert_eq!(act.as_deref(), Some("Allowed"), "action={action}");
    }
}

/// CEF ground truth: vendor comes from Header Field 2 (any vendor's CEF),
/// disposition from the `act=` extension token.
#[test]
fn test_gt_cef_vendor_and_action() {
    let cef_accept = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|deviceExternalId=FGT1 src=192.168.1.1 spt=25297 dst=203.0.113.1 dpt=80 proto=6 act=accept";
    let (v, t, act) = EvaluatorEngine::extract_ground_truth(cef_accept);
    assert_eq!(v, "Fortinet");
    assert_eq!(t, "cef");
    assert_eq!(act.as_deref(), Some("Allowed"));

    let cef_deny = "CEF:0|Cisco|ASA|v9.16|4-106023|Deny|2|src=192.0.2.1 spt=443 dst=10.0.0.1 dpt=22 proto=6 act=deny";
    let (v, _, act) = EvaluatorEngine::extract_ground_truth(cef_deny);
    assert_eq!(v, "Cisco");
    assert_eq!(act.as_deref(), Some("Blocked"));

    let cef_timeout =
        "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic|3|act=timeout src=10.0.0.1";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(cef_timeout);
    assert_eq!(act.as_deref(), Some("Allowed"));
}

/// Explicit vendor label map — fixed table, never fuzzy matching.
#[test]
fn test_audit_vendor_label_map() {
    assert_eq!(EvaluatorEngine::map_audit_vendor("oisf"), "suricata");
    assert_eq!(EvaluatorEngine::map_audit_vendor("netgate"), "pfsense");
    assert_eq!(EvaluatorEngine::map_audit_vendor("cisco"), "cisco");
    assert_eq!(EvaluatorEngine::map_audit_vendor("unknown"), "unknown");
}

/// Suricata EVE ground truth: an explicit event-level `action` is authoritative;
/// without one, alert = Blocked (detection), dns/flow = Allowed.
#[test]
fn test_gt_suricata_eve_action() {
    let alert_allowed = r#"{"timestamp": "2026-09-21T14:00:06.4554+0000", "event_type": "alert", "src_ip": "10.0.0.8", "alert": {"action": "allowed", "signature": "ET SCAN", "severity": 3}}"#;
    let (_, tag, act) = EvaluatorEngine::extract_ground_truth(alert_allowed);
    assert_eq!(tag, "suricata_alert");
    assert_eq!(act.as_deref(), Some("Allowed"), "explicit allowed must win");

    let alert_blocked = r#"{"timestamp": "2026-09-21T14:00:06.4554+0000", "event_type": "alert", "src_ip": "10.0.0.8", "alert": {"action": "blocked", "signature": "ET SCAN", "severity": 2}}"#;
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(alert_blocked);
    assert_eq!(act.as_deref(), Some("Blocked"));

    let alert_no_action = r#"{"timestamp": "2026-09-21T14:00:06.4554+0000", "event_type": "alert", "src_ip": "10.0.0.8", "alert": {"signature": "ET SCAN", "severity": 2}}"#;
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(alert_no_action);
    assert_eq!(act.as_deref(), Some("Blocked"));

    let dns = r#"{"timestamp": "2026-09-21T14:00:05.1653+0000", "event_type": "dns", "src_ip": "10.0.0.83", "dns": {"type": "query"}}"#;
    let (_, tag, act) = EvaluatorEngine::extract_ground_truth(dns);
    assert_eq!(tag, "suricata_flow");
    assert_eq!(act.as_deref(), Some("Allowed"));
}

/// Numeric IANA protocol equivalence: `proto=17` in raw validates an extracted UDP.
#[test]
fn test_protocol_numeric_equivalence_audit() {
    assert!(EvaluatorEngine::raw_contains_numeric(
        "date=2026-01-01 proto=17 spt=5",
        17
    ));
    assert!(EvaluatorEngine::raw_contains_numeric(r#"{"proto": 6}"#, 6));
    assert!(EvaluatorEngine::raw_contains_numeric("...,4,17,...", 17));
    // Must not match on unrelated content
    assert!(!EvaluatorEngine::raw_contains_numeric(
        "proto=TCP spt=443",
        17
    ));
    assert!(!EvaluatorEngine::raw_contains_numeric("proto=17", 6));
}

/// Template validity (honest TA): token-aligned generalization of the masked line,
/// syslog GT tag preserved. No `|| !template.is_empty()` escape hatch remains.
#[test]
fn test_template_validity_alignment() {
    let raw = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 (203.0.113.54/25) to inside:10.1.6.180/52369 (198.51.100.209/52369)";
    let masked = mask_line(raw);

    // A template equal to (or a wildcard-generalization of) the masked line is valid
    assert!(EvaluatorEngine::template_is_valid(
        raw,
        &masked,
        "%ASA-6-302013"
    ));

    // Wildcards at masked positions remain valid
    let generalized = masked.replace("203.0.113.54/25", "<*>");
    assert!(EvaluatorEngine::template_is_valid(
        raw,
        &generalized,
        "%ASA-6-302013"
    ));

    // A divergent literal (Built -> Teardown) must FAIL — old metric passed this
    let bogus = masked.replace("Built", "Teardown");
    assert!(!EvaluatorEngine::template_is_valid(
        raw,
        &bogus,
        "%ASA-6-302013"
    ));

    // A template that lost the syslog tag must FAIL
    let tagless = masked.replace("%ASA-6-302013:", "");
    assert!(!EvaluatorEngine::template_is_valid(
        raw,
        &tagless,
        "%ASA-6-302013"
    ));

    // Empty template must FAIL (old metric's `!is_empty()` clause is gone)
    assert!(!EvaluatorEngine::template_is_valid(
        raw,
        "",
        "%ASA-6-302013"
    ));
}
