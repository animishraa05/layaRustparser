#!/usr/bin/env python3
"""ULPF P7 deterministic corpus generator (plan: OVERHAUL_PLAN.md §3 P7).

Produces, from templates + seeded mutations (stdlib only, zero network):

  data/raw/adversarial/adversarial.log   P7.1 — mutated raw lines, one/record
  data/raw/adversarial/gt.jsonl          P7.1 — sidecar GT, same order, `raw`
                                         verbatim (authoritative: mutations may
                                         destroy in-line GT markers)
  data/raw/cisco_asa_vpn.log             P7.2 — ASA VPN/AAA expansion (in-line
                                         GT compatible: syslog-tagged, verdict
                                         phrases known to BOTH the evaluator's
                                         extract_ground_truth and the engine's
                                         cisco_asa fallback, marker-safe)
  data/raw/fortigate_utm.log             P7.2 — FGT type=dns/utm/app-ctrl
  data/raw/paloalto_threat.log           P7.2 — PAN ,THREAT, subtypes
  data/raw/pfsense_ipv6.log              P7.2 — filterlog IPv6 layout

  --holdout ALSO writes (seed 9090, separate, FROZEN until P8 freeze):
  data/raw/holdout/holdout.log + gt.jsonl — 3 never-seen formats for the
  classifier novelty path (MikroTik-style, Juniper SRX-style, fictitious).

Determinism: seed 1337 (deliberately != 42) for adversarial/expansion,
seed 9090 for holdout. Same seed => byte-identical outputs. No RNG use
outside this file; no timestamps (all fixed epoch).

difficulty vocabulary (sidecar): clean | truncation | relay | encoding |
field-damage | cardinality.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SEED_ADV = 1337
SEED_HOLDOUT = 9090

# Truncation cut points (bytes; ASCII => char index equals byte index).
TRUNC_CUTS = (512, 1024, 2048)

IPV4 = [
    "192.168.{}".format, "10.{}.{}".format, "172.16.{}.{}".format,
]
PEERS = [
    "203.0.113.", "198.51.100.", "192.0.2.",
]


def ipv4(rng: random.Random, internal: bool = True) -> str:
    if internal:
        return f"10.{rng.randint(1, 60)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}"
    return rng.choice(PEERS) + str(rng.randint(1, 250))


def record(raw: str, gt_vendor: str, gt_template_tag: str, gt_fields: dict,
           gt_disposition: str | None, gt_protocol: str | None,
           difficulty: str, origin: str) -> dict:
    return {
        "raw": raw,
        "gt_vendor": gt_vendor,
        "gt_template_tag": gt_template_tag,
        "gt_fields": gt_fields,
        "gt_disposition": gt_disposition,
        "gt_protocol": gt_protocol,
        "difficulty": difficulty,
        "origin": origin,
    }


# ---------------------------------------------------------------------------
# Base line builders — each returns (raw, gt dict without difficulty/origin).
# gt_fields always describes the FULL field content of the base (mutations
# may destroy some of it in `raw`; the audit's null-vs-wrong rule credits
# honest nulls and punishes wrong non-nulls harder).
# ---------------------------------------------------------------------------

def asa_build(rng: random.Random, udp: bool = False) -> dict:
    proto = "UDP" if udp else "TCP"
    code = "302015" if udp else "302013"
    host = rng.choice(["asa-core-fw", "asa-edge-01", "asa-dc-01"])
    sip, dip = ipv4(rng, False), ipv4(rng, True)
    sport, dport = rng.randint(1024, 65000), rng.choice([53, 443, 80, 3389, 1433])
    direction = rng.choice(["inbound", "outbound"])
    peer_intf, local_intf, peer, local = ("outside", "inside", sip, dip)
    if direction == "outbound":
        peer, local = dip, sip
    raw = (f"<166>Sep 21 14:00:{rng.randint(10, 59)} {host} %ASA-6-{code}: "
           f"Built {direction} {proto} connection {rng.randint(1000000, 1999999)} "
           f"for {peer_intf}:{peer}/{sport} ({peer}/{sport}) "
           f"to {local_intf}:{local}/{dport} ({local}/{dport})")
    return record(raw, "Cisco", f"%ASA-6-{code}:",
                  {"src_ip": peer, "dst_ip": local, "src_port": sport,
                   "dst_port": dport, "protocol": proto.lower()},
                  "Allowed", proto.lower(), "clean", f"base:asa-{code}")


def asa_teardown(rng: random.Random) -> dict:
    host = rng.choice(["asa-core-fw", "asa-dc-01"])
    sip, dip = ipv4(rng, False), ipv4(rng, True)
    sport, dport = rng.randint(1024, 65000), rng.randint(1024, 65000)
    reason = rng.choice(["Reset-I", "Reset-O", "SYN Timeout", "normal-close"])
    tail = reason.split()  # "SYN Timeout" is two whitespace tokens
    raw = (f"<166>Sep 21 14:01:{rng.randint(10, 59)} {host} %ASA-6-302014: "
           f"Teardown TCP connection {rng.randint(1000000, 1999999)} "
           f"for outside:{sip}/{sport} to inside:{dip}/{dport} "
           f"duration {rng.randint(0, 2)}:{rng.randint(10, 59)}:{rng.randint(10, 59)} "
           f"bytes {rng.randint(1000, 9999999)} " + " ".join(tail))
    return record(raw, "Cisco", "%ASA-6-302014:",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": "tcp"},
                  "Allowed", "tcp", "clean", "base:asa-302014")


def asa_denied(rng: random.Random, code: str = "106001") -> dict:
    sip, dip = ipv4(rng, False), ipv4(rng, True)
    sport, dport = rng.randint(1024, 65000), rng.choice([8080, 443, 22, 23])
    proto = rng.choice(["TCP", "UDP"])
    if code == "106001":
        raw = (f"<162>Sep 21 14:02:{rng.randint(10, 59)} asa-dc-01 %ASA-2-106001: "
               f"Inbound {proto} connection denied from {sip}/{sport} "
               f"to {dip}/{dport} flags ACK on interface outside")
        tag = "%ASA-2-106001:"
    else:  # 106007: dropped by access-list
        raw = (f"<164>Sep 21 14:02:{rng.randint(10, 59)} asa-edge-01 %ASA-4-106007: "
               f"dropped {proto} from {sip}/{sport} to {dip}/{dport}, "
               f"access-list outside_in denied icmp {dip} -> {sip}")
        tag = "%ASA-4-106007:"
    # GT disposition vocabulary: bare `drop` in the ASA branch maps Blocked
    # (deny-by-policy), engine fallback maps dropped->DROPPED only when the
    # word is lowercase `drop`/`dropped` AND code has no dedicated arm.
    # 106001/106007 have dedicated engine arms (DROPPED); GT None => the
    # disposition rule credits engine's non-Unknown value, so keep GT None.
    return record(raw, "Cisco", tag,
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": proto.lower()},
                  None, proto.lower(), "clean", f"base:asa-{code}")


def asa_vpn_ok(rng: random.Random) -> dict:
    ip = ipv4(rng, False)  # exactly ONE IPv4: fallback endpoints are None and
    # a single IP with no src=/dst= keys is NOT endpoint evidence (marker rule).
    grp = rng.choice(["vpn-users", "contractors", "remote-admins"])
    code = rng.choice(["713041", "713049"])
    raw = (f"<130>Sep 21 14:03:{rng.randint(10, 59)} asa-vpn-gw01 "
           f"%ASA-6-{code}: Group = {grp}, IP = {ip}, IPsec tunnel established.")
    return record(raw, "Cisco", f"%ASA-6-{code}:",
                  {"src_ip": None, "dst_ip": None, "src_port": None,
                   "dst_port": None, "protocol": None},
                  "Allowed", None, "clean", f"base:asa-vpn-ok")


def asa_vpn_fail(rng: random.Random) -> dict:
    ip = ipv4(rng, False)
    grp = rng.choice(["vpn-users", "guest-wifi"])
    code = rng.choice(["713172", "713041"])
    raw = (f"<164>Sep 21 14:03:{rng.randint(10, 59)} asa-vpn-gw01 "
           f"%ASA-4-{code}: Group = {grp}, IP = {ip}, "
           f"IPsec tunnel, authentication failed from gateway.")
    return record(raw, "Cisco", f"%ASA-4-{code}:",
                  {"src_ip": None, "dst_ip": None, "src_port": None,
                   "dst_port": None, "protocol": None},
                  "Blocked", None, "clean", f"base:asa-vpn-fail")


def asa_aaa_ok(rng: random.Random) -> dict:
    ip = ipv4(rng, False)
    user = rng.choice(["jdoe", "asmith", "klee", "mikrotik-ops"])
    grp = rng.choice(["vpn-users", "network-admins"])
    raw = (f"<130>Sep 21 14:04:{rng.randint(10, 59)} asa-vpn-gw01 "
           f"%ASA-6-716059: Group = {grp}, Username = {user}, IP = {ip}, "
           f"Successful login to server.")
    return record(raw, "Cisco", "%ASA-6-716059:",
                  {"src_ip": None, "dst_ip": None, "src_port": None,
                   "dst_port": None, "protocol": None},
                  "Allowed", None, "clean", "base:asa-aaa-ok")


def asa_aaa_fail(rng: random.Random) -> dict:
    ip = ipv4(rng, False)
    user = rng.choice(["root", "admin", "test", "svc_backup"])
    grp = rng.choice(["vpn-users", "guest-wifi"])
    raw = (f"<164>Sep 21 14:04:{rng.randint(10, 59)} asa-vpn-gw01 "
           f"%ASA-4-716060: Group = {grp}, Username = {user}, IP = {ip}, "
           f"authentication failed.")
    return record(raw, "Cisco", "%ASA-4-716060:",
                  {"src_ip": None, "dst_ip": None, "src_port": None,
                   "dst_port": None, "protocol": None},
                  "Blocked", None, "clean", "base:asa-aaa-fail")


def fgt_kv(rng: random.Random, type_: str = "traffic", action: str = "accept",
           long_url: bool = False) -> dict:
    dev = rng.choice(["FGT-CORP-FW01", "FGT-DC-EDGE", "FGT-DMZ-02"])
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([443, 53, 80, 8443, 8080])
    proto = rng.choice([("6", "tcp"), ("17", "udp")])
    logid = {"traffic": "0000000003", "dns": "0001000013",
             "utm": "0000000016", "app-ctrl": "0001000125"}[type_]
    tail = f'action="{action}" policyid={rng.randint(10, 99)} proto={proto[0]}'
    if type_ == "traffic":
        line_tail = (f'srcip={sip} srcport={sport} srcintf="trust" '
                     f'dstip={dip} dstport={dport} dstintf="wan1" '
                     f'sessionid={rng.randint(1000000, 1999999)} {tail} '
                     f'sentbyte={rng.randint(64, 999999)} '
                     f'rcvdbyte={rng.randint(64, 999999)}')
        proto_gt = proto[1]
    elif type_ == "dns":
        line_tail = (f'srcip={sip} srcport={sport} srcintf="trust" '
                     f'dstip={dip} dstport=53 dstintf="wan1" '
                     f'sessionid={rng.randint(1000000, 1999999)} {tail} '
                     f'qtype=A qname="svc{rng.randint(1, 99)}.example.net" '
                     f'msg="query refused"')
        proto_gt = "udp"
    elif type_ == "utm":
        url = (f'https://cdn.example.net/asset/{rng.randint(1, 9999)}/main.css'
               if not long_url else
               'https://cdn.example.net/' + "/".join(
                   f"seg{i:02d}" for i in range(300)) + '/payload.bin')
        line_tail = (f'srcip={sip} srcport={sport} srcintf="trust" '
                     f'dstip={dip} dstport={dport} dstintf="wan1" '
                     f'sessionid={rng.randint(1000000, 1999999)} {tail} '
                     f'service="HTTP" cat="Malicious Networks" '
                     f'url="{url}"')
        proto_gt = "tcp"
    else:  # app-ctrl
        line_tail = (f'srcip={sip} srcport={sport} srcintf="trust" '
                     f'dstip={dip} dstport={dport} dstintf="wan1" '
                     f'sessionid={rng.randint(1000000, 1999999)} {tail} '
                     f'app="TikTok" appcat="Low Risk"')
        proto_gt = "tcp"
    raw = (f'<189>date=2026-09-21 time=14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} '
           f'devname="{dev}" logid="{logid}" type="{type_}" '
           f'subtype="forward" level="notice" vd="root" {line_tail}')
    disp = {"accept": "Allowed", "blocked": "Blocked", "deny": "Blocked",
            "drop": "Dropped"}[action]
    return record(raw, "Fortinet", f"fortigate_{type_ if type_ != 'traffic' else 'traffic'}",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": 53 if type_ == "dns" else dport,
                   "protocol": proto_gt},
                  disp, proto_gt, "clean", f"base:fgt-{type_}")


def pan_row(rng: random.Random, type_: str = "TRAFFIC",
            subtype: str = "start", action: str = "allow") -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([443, 80, 53, 3389])
    proto = rng.choice(["tcp", "udp"])
    # Column layout mirrors TRAFFIC exactly (type token at CSV index 3, action
    # at index 30) so both the extractor's `unwrap_or(3)` offset and the GT's
    # `traffic_pos + 27` land on the same action column for THREAT rows.
    fields = [
        "1", f"2026/09/21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)}",
        f"001801{rng.randint(100000, 999999)}", type_, subtype, "2304",
        f"2026/09/21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)}",
        sip, dip, sip, dip,
        rng.choice(["Trust_to_Untrust", "Inter-VLAN", "LAN_to_WAN"]),
        rng.choice(["acme\\agarcia", "acme\\bwilson", "acme\\cnguyen"]),
        "",
        rng.choice(["ssl", "web-browsing", "dns", "threat-scan"]),
        "vsys1", "LAN", "WAN", "ethernet1/1", "ethernet1/2", "default", "",
        str(rng.randint(100000, 999999)), "1", str(sport), str(dport),
        str(rng.randint(1, 65535)), "0", "0x400000", proto, action,
        str(rng.randint(1000, 999999)), str(rng.randint(1000, 999999)),
        str(rng.randint(1000, 999999)), str(rng.randint(1, 9999)),
        "2026/09/21 14:00:00", str(rng.randint(10, 99)),
        rng.choice(["web-hosting", "networking", "business"],),
        "0", str(rng.randint(1000000, 9999999)), "0x0",
        "192.168.0.0-192.168.255.255", "US", "0", "612", "8898", "",
        "0", "0", "0", "0", "vsys1", "PA-5220-FW01", "from-policy",
        "", "", "0", "0", "0", "", "N/A", "0", "0", "0", "0",
    ]
    raw = ",".join(fields)
    disp = {"allow": "Allowed", "deny": "Blocked", "drop": "Dropped",
            "start": "Allowed"}[action]
    tag = "panos_threat" if type_ == "THREAT" else "panos_traffic"
    return record(raw, "Palo Alto", tag,
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": proto},
                  disp, proto, "clean", f"base:pan-{type_.lower()}")


def pfsense_v4(rng: random.Random, action: str = "pass") -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([443, 80, 22])
    proto_num, proto_name = rng.choice([(6, "tcp"), (17, "udp")])
    raw = (f"Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} pfSense "
           f"filterlog[{rng.randint(20000, 29999)}]: "
           f"{rng.randint(1, 99)},16777216,,1000000{rng.randint(10, 99)},"
           f"igb{rng.randint(0, 3)},match,{action},in,4,0x0,,255,"
           f"{rng.randint(1000, 60000)},0,DF,{proto_num},{proto_name},"
           f"{rng.randint(400, 1500)},{sip},{dip},{sport},{dport},"
           f"{rng.randint(100, 1460)},PA,{rng.randint(100000, 999999)},,"
           f"65535,,mss;sackOK;TS")
    disp = {"pass": "Allowed", "block": "Blocked", "reject": "Blocked"}[action]
    return record(raw, "pfSense", "pfsense_filterlog",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": proto_name},
                  disp, proto_name, "clean", "base:pfsense-v4")


def pfsense_v6(rng: random.Random, action: str = "pass") -> dict:
    # Official pfSense filterlog IPv6 layout (Netgate docs "Raw Filter Log
    # Format" BNF): after the 9 common fields,
    #   [9]=class [10]=flow-label [11]=hop-limit [12]=protocol-text
    #   [13]=protocol-id [14]=length [15]=src [16]=dst [17]/[18]=ports
    # (v6 puts protocol TEXT before ID — opposite of v4's id,text order.)
    sip = f"2001:db8:{rng.randint(1, 65535):x}::{rng.randint(1, 65535):x}"
    dip = f"2001:db8:aaaa::{rng.randint(1, 65535):x}"
    sport, dport = rng.randint(1024, 65000), rng.choice([443, 80, 53])
    proto_num, proto_name = rng.choice([(6, "tcp"), (17, "udp")])
    flow = rng.randint(0, 0xFFFFF)
    hlim = rng.choice([64, 128, 255])
    plen = rng.randint(60, 1500)
    dlen = rng.randint(20, 1400)
    tail = (
        f",{dlen},PA,{rng.randint(100000, 999999)},,65535,,"
        if proto_num == 6
        else f",{dlen}"
    )
    raw = (f"Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} pfSense "
           f"filterlog[{rng.randint(30000, 39999)}]: "
           f"{rng.randint(1, 99)},16777216,,1000000{rng.randint(10, 99)},"
           f"igb{rng.randint(0, 3)},match,{action},in,6,"
           f"0x0,{flow:05x},{hlim},{proto_name},{proto_num},"
           f"{plen},{sip},{dip},{sport},{dport}{tail}")
    disp = {"pass": "Allowed", "block": "Blocked"}[action]
    return record(raw, "pfSense", "pfsense_filterlog",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": proto_name},
                  disp, proto_name, "clean", "base:pfsense-v6")


def suricata(rng: random.Random, kind: str = "alert") -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([1521, 443, 53])
    ts = f"2026-09-21T14:0{rng.randint(0, 5)}:{rng.randint(10, 59)}.{rng.randint(100000, 999999)}+0000"
    if kind == "alert":
        action = rng.choice(["blocked", "allowed"])
        raw = (json.dumps({
            "timestamp": ts, "flow_id": rng.randint(1, 9 * 10**15), "in_iface": "eth0",
            "event_type": "alert", "src_ip": sip, "src_port": sport,
            "dest_ip": dip, "dest_port": dport, "proto": "TCP", "tx_id": 0,
            "alert": {"action": action, "gid": 1,
                      "signature_id": rng.randint(2000000, 2999999), "rev": 4,
                      "signature": rng.choice([
                          "ET POLICY Suspicious inbound to database port",
                          "ET TROjan Possible Cobalt Strike Beacon"]),
                      "category": "Potential Corporate Privacy Violation",
                      "severity": 2},
            "app_proto": "tls"}, separators=(",", ": ")))
        disp = "Blocked" if action == "blocked" else "Allowed"
        tag = "suricata_alert"
    elif kind == "flow":
        raw = (json.dumps({
            "timestamp": ts, "flow_id": rng.randint(1, 9 * 10**15), "in_iface": "eth0",
            "event_type": "flow", "src_ip": sip, "src_port": sport,
            "dest_ip": dip, "dest_port": dport, "proto": "TCP",
            "app_proto": "http",
            "flow": {"pkts_toserver": rng.randint(1, 99),
                     "pkts_toclient": rng.randint(1, 99),
                     "bytes_toserver": rng.randint(64, 99999),
                     "bytes_toclient": rng.randint(64, 99999),
                     "state": "closed", "reason": "timeout"}},
            separators=(",", ": ")))
        disp, tag = "Allowed", "suricata_flow"
    else:  # dns
        raw = (json.dumps({
            "timestamp": ts, "flow_id": rng.randint(1, 9 * 10**15), "in_iface": "eth0",
            "event_type": "dns", "src_ip": sip, "src_port": sport,
            "dest_ip": dip, "dest_port": 53, "proto": "UDP",
            "dns": {"type": "answer", "id": rng.randint(1, 65535),
                    "rrname": f"h{rng.randint(1, 999)}.example.net",
                    "rrtype": "A", "rcode": "NOERROR"}},
            separators=(",", ": ")))
        disp, tag = "Allowed", "suricata_flow"
    proto = "tcp" if kind != "dns" else "udp"
    return record(raw, "Suricata", tag,
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": 53 if kind == "dns" else dport,
                   "protocol": proto},
                  disp, proto, "clean", f"base:suricata-{kind}")


# ---------------------------------------------------------------------------
# Mutations (P7.1 classes) — each takes a clean record, returns a new record
# with `difficulty` set and `raw` damaged; GT stays the BASE's GT (honest:
# that is what the line meant before the relay/truncator hit it).
# ---------------------------------------------------------------------------

def mut_truncate(rec: dict, cut: int) -> dict | None:
    if len(rec["raw"]) <= cut:
        return None  # truncation only exists for lines longer than the cut
    out = dict(rec)
    out["raw"] = rec["raw"][:cut]  # mid-token byte cut (ASCII base lines)
    out["difficulty"] = "truncation"
    out["origin"] = rec["origin"] + f":trunc{cut}"
    return out


def mut_double_prefix(rec: dict, rng: random.Random) -> dict:
    # relay artifact: device behind two syslog forwarders
    head = f"<134>Oct  5 09:59:59 relay-agg-02 "
    out = dict(rec)
    out["raw"] = head + rec["raw"]
    out["difficulty"] = "relay"
    out["origin"] = rec["origin"] + ":dbl-prefix"
    return out


def mut_missing_pri(rec: dict) -> dict | None:
    raw = rec["raw"]
    if not (raw.startswith("<") and ">" in raw[:5]):
        return None
    out = dict(rec)
    out["raw"] = raw[raw.index(">") + 1:]  # PRI stripped by a broken relay
    out["difficulty"] = "relay"
    out["origin"] = rec["origin"] + ":no-pri"
    return out


def mut_oct_double_space(rec: dict, rng: random.Random) -> dict:
    # classic syslog-then space padding: `Sep 21` -> `Oct  5` (day < 10)
    raw = rec["raw"].replace("Sep 21", "Oct  5", 1)
    out = dict(rec)
    out["raw"] = raw
    out["difficulty"] = "relay"
    out["origin"] = rec["origin"] + ":oct-pad"
    return out


def mut_utf8_host(rec: dict) -> dict:
    raw = rec["raw"]
    for host in ("asa-core-fw", "asa-edge-01", "asa-dc-01", "asa-vpn-gw01",
                 "FGT-CORP-FW01", "FGT-DC-EDGE", "FGT-DMZ-02"):
        if host in raw:
            raw = raw.replace(host, host + "-é01", 1)
            break
    out = dict(rec)
    out["raw"] = raw
    out["difficulty"] = "encoding"
    out["origin"] = rec["origin"] + ":utf8"
    return out


def mut_mojibake(rec: dict) -> dict:
    # UTF-8 read as latin-1 (classic double-decode artifact)
    out = dict(rec)
    out["raw"] = rec["raw"].replace("é", "\u00e9")  # é -> Ã© shape via latin1
    if out["raw"] == rec["raw"]:
        out["raw"] = rec["raw"].replace("a", "Ã¡", 1) \
            if "a" in rec["raw"] else rec["raw"]
    out["raw"] = out["raw"].encode("latin-1", "ignore").decode("utf-8", "ignore") \
        or rec["raw"]
    out["difficulty"] = "encoding"
    out["origin"] = rec["origin"] + ":mojibake"
    return out


def mut_bom(rec: dict) -> dict:
    out = dict(rec)
    out["raw"] = "\ufeff" + rec["raw"]
    out["difficulty"] = "encoding"
    out["origin"] = rec["origin"] + ":bom"
    return out


def mut_mid_cr(rec: dict, rng: random.Random) -> dict:
    raw = rec["raw"]
    pos = raw.find(" ")
    if pos > 0 and pos + 1 < len(raw):
        raw = raw[:pos] + "\r" + raw[pos:]  # stray CR mid-line (NOT line-end;
        # the loader's trim() would erase a trailing CRLF and hide the damage)
    out = dict(rec)
    out["raw"] = raw
    out["difficulty"] = "encoding"
    out["origin"] = rec["origin"] + ":mid-cr"
    return out


def mut_unclosed_quote(rec: dict) -> dict | None:
    raw = rec["raw"]
    idx = raw.rfind('"')
    if idx == -1:
        return None
    out = dict(rec)
    out["raw"] = raw[:idx] + raw[idx + 1:]  # final quote lost in transit
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":unclosed"
    return out


def mut_short_pan(rec: dict) -> dict | None:
    if ",TRAFFIC," not in rec["raw"] and ",THREAT," not in rec["raw"]:
        return None
    fields = rec["raw"].split(",")
    if len(fields) < 20:
        return None
    out = dict(rec)
    out["raw"] = ",".join(fields[:17])  # short CSV: session cols truncated
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":short-csv"
    return out


def mut_broken_json(rec: dict) -> dict | None:
    raw = rec["raw"]
    if not raw.startswith("{"):
        return None
    out = dict(rec)
    out["raw"] = raw.rstrip("}").rstrip().rstrip(",") + '"}'  # unbalanced close
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":broken-json"
    return out


def mut_proto47(rec: dict) -> dict | None:
    if 'proto="6"' not in rec["raw"] and "proto=6" not in rec["raw"]:
        return None
    out = dict(rec)
    out["raw"] = rec["raw"].replace('proto="6"', 'proto="47"') \
        .replace("proto=6", "proto=47")
    out["gt_fields"]["protocol"] = "gre"
    out["gt_protocol"] = "gre"
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":proto47"
    return out


def mut_port0(rec: dict) -> dict | None:
    import re as _re
    raw = rec["raw"]
    if not _re.search(r"(dstport=|dpt=|,)\d+", raw):
        return None
    mutated = _re.sub(r"dstport=\d+", "dstport=0", raw, count=1)
    if mutated == raw:
        return None
    out = dict(rec)
    out["raw"] = mutated
    out["gt_fields"]["dst_port"] = None  # port 0 means "absent" (never valid)
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":port0"
    return out


def mut_epoch(rec: dict) -> dict | None:
    if "time=" not in rec["raw"]:
        return None
    out = dict(rec)
    out["raw"] = rec["raw"].replace("time=14:", "time=178997940", 1) \
        if "time=14:" in rec["raw"] else rec["raw"]
    if out["raw"] == rec["raw"]:
        return None
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":epoch"
    return out


def mut_ipv6(rec: dict, _rng: random.Random | None = None) -> dict:
    # rewrite every 4th IPv4 to an IPv6 literal (endpoint discipline stress)
    out = dict(rec)
    parts = rec["raw"].split(" ")
    changed = 0
    for i, tok in enumerate(parts):
        if changed < 2 and _looks_v4(tok):
            if changed == 0:
                parts[i] = tok.replace(_first_v4(tok), "2001:db8::77")
                out["gt_fields"]["src_ip"] = "2001:db8::77"
            else:
                parts[i] = tok.replace(_first_v4(tok), "2001:db8::88")
                out["gt_fields"]["dst_ip"] = "2001:db8::88"
            changed += 1
    out["raw"] = " ".join(parts)
    out["difficulty"] = "field-damage"
    out["origin"] = rec["origin"] + ":ipv6"
    return out


def _first_v4(tok: str) -> str | None:
    import re as _re
    m = _re.search(r"\d{1,3}(?:\.\d{1,3}){3}", tok)
    return m.group(0) if m else None


def _looks_v4(tok: str) -> bool:
    return _first_v4(tok) is not None


def mut_card_url(rec: dict) -> dict | None:
    # high-cardinality: 64-hex digest + oversized session id in a kv line
    if "sessionid=" not in rec["raw"]:
        return None
    out = dict(rec)
    out["raw"] = (rec["raw"].replace(
        "sessionid=", "sessionid=9" + "7" * 18)
        + ' hash="' + "a3f" * 21 + "b" + '"')
    out["difficulty"] = "cardinality"
    out["origin"] = rec["origin"] + ":card-kv"
    return out


def mut_card_sig(rec: dict) -> dict | None:
    if '"signature"' not in rec["raw"]:
        return None
    out = dict(rec)
    sig = "ET EXPLOIT probe path " + "/".join(f"p{i:03d}" for i in range(180))
    import json as _json
    try:
        obj = _json.loads(rec["raw"])
        obj["alert"]["signature"] = sig
        out["raw"] = _json.dumps(obj, separators=(",", ": "))
    except Exception:
        return None
    out["difficulty"] = "cardinality"
    out["origin"] = rec["origin"] + ":card-sig"
    return out


def mut_card_urlpath(rec: dict) -> dict | None:
    if "url=" not in rec["raw"]:
        return None
    out = dict(rec)
    long_url = 'url="https://track.example.org/' + \
        "-".join(f"hop{i:03d}" for i in range(120)) + '/x.js"'
    import re as _re
    out["raw"] = _re.sub(r'url="[^"]*"', long_url, rec["raw"], count=1)
    out["difficulty"] = "cardinality"
    out["origin"] = rec["origin"] + ":card-url"
    return out


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def build_bases(rng: random.Random) -> list[dict]:
    bases: list[dict] = []
    # 3 iterations keeps the committed corpus (logs + sidecars) near the
    # plan P7.6 ~1 MB budget while covering every family/mutation pair.
    for _ in range(3):
        bases.append(asa_build(rng))
        bases.append(asa_build(rng, udp=True))
        bases.append(asa_teardown(rng))
        bases.append(asa_denied(rng))
        bases.append(asa_denied(rng, code="106007"))
        bases.append(asa_vpn_ok(rng))
        bases.append(asa_vpn_fail(rng))
        bases.append(asa_aaa_ok(rng))
        bases.append(asa_aaa_fail(rng))
        bases.append(fgt_kv(rng, "traffic", "accept"))
        bases.append(fgt_kv(rng, "traffic", "deny"))
        bases.append(fgt_kv(rng, "dns", "blocked"))
        bases.append(fgt_kv(rng, "utm", "blocked"))
        bases.append(fgt_kv(rng, "app-ctrl", "blocked"))
        bases.append(pan_row(rng, "TRAFFIC", "start", "allow"))
        bases.append(pan_row(rng, "TRAFFIC", "end", "allow"))
        bases.append(pan_row(rng, "TRAFFIC", "drop", "drop"))
        bases.append(pan_row(rng, "THREAT", "end", "deny"))
        bases.append(pan_row(rng, "THREAT", "end", "drop"))
        bases.append(pfsense_v4(rng, "pass"))
        bases.append(pfsense_v4(rng, "block"))
        bases.append(pfsense_v6(rng, "pass"))
        bases.append(suricata(rng, "alert"))
        bases.append(suricata(rng, "flow"))
        bases.append(suricata(rng, "dns"))
    # long carriers for truncation-at-cut points (>=2048 bytes)
    for _ in range(3):
        long_fgt = fgt_kv(rng, "utm", "blocked", long_url=True)
        bases.append(long_fgt)
        long_sig = suricata(rng, "alert")
        long_sig["raw"] = long_sig["raw"].replace(
            "ET TROjan Possible Cobalt Strike Beacon",
            "ET ADVERSARIAL " + "/".join(f"stage{i:03d}" for i in range(140)))
        bases.append(long_sig)
    return bases


MUTATORS_SPECIAL = {
    "truncation-special": None,  # handled separately (needs cut points)
}


def mutate(rng: random.Random, base: dict) -> list[dict]:
    out = [dict(base)]  # the clean copy (difficulty=clean)
    # truncation: only if the base is long enough for at least one cut
    for cut in TRUNC_CUTS:
        t = mut_truncate(base, cut)
        if t:
            out.append(t)
    # relay
    out.append(mut_double_prefix(base, rng))
    mp = mut_missing_pri(base)
    if mp:
        out.append(mp)
    out.append(mut_oct_double_space(base, rng))
    # encoding
    out.append(mut_utf8_host(base))
    out.append(mut_bom(base))
    out.append(mut_mid_cr(base, rng))
    mb = mut_mojibake(base)
    if mb:
        out.append(mb)
    # field damage
    for fn in (mut_unclosed_quote, mut_short_pan, mut_broken_json,
               mut_proto47, mut_port0, mut_epoch, mut_ipv6):
        m = fn(base, rng) if fn is mut_ipv6 else fn(base)
        if m:
            out.append(m)
    # cardinality
    for fn in (mut_card_url, mut_card_sig, mut_card_urlpath):
        m = fn(base)
        if m:
            out.append(m)
    return out


def dedup_keep_order(records: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for r in records:
        if r["raw"] not in seen:
            seen.add(r["raw"])
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Expansion (P7.2): clean lines for the CORE corpus, in-line-GT compatible.
# ---------------------------------------------------------------------------

def build_expansion(rng: random.Random) -> dict[str, list[str]]:
    asa, fgt, pan, pfs = [], [], [], []
    for _ in range(30):
        r = asa_vpn_ok(rng)
        # expansion records are clean core lines — write raw only (GT derives
        # in-line from the syslog tag + the shared verdict phrases)
        asa.append(r["raw"])
        r = asa_vpn_fail(rng)
        asa.append(r["raw"])
        r = asa_aaa_ok(rng)
        asa.append(r["raw"])
        r = asa_aaa_fail(rng)
        asa.append(r["raw"])
    for _ in range(30):
        fgt.append(fgt_kv(rng, "dns", "blocked")["raw"])
        fgt.append(fgt_kv(rng, "dns", "accept")["raw"])
        fgt.append(fgt_kv(rng, "utm", "blocked")["raw"])
        fgt.append(fgt_kv(rng, "utm", "accept")["raw"])
        fgt.append(fgt_kv(rng, "app-ctrl", "blocked")["raw"])
    for _ in range(30):
        pan.append(pan_row(rng, "THREAT", "end", "deny")["raw"])
        pan.append(pan_row(rng, "THREAT", "start", "allow")["raw"])
        pan.append(pan_row(rng, "THREAT", "url", "allow")["raw"]
                   if False else pan_row(rng, "THREAT", "end", "drop")["raw"])
    for _ in range(30):
        pfs.append(pfsense_v6(rng, "pass")["raw"])
        pfs.append(pfsense_v6(rng, "block")["raw"])
    return {
        "cisco_asa_vpn.log": asa,
        "fortigate_utm.log": fgt,
        "paloalto_threat.log": pan,
        "pfsense_ipv6.log": pfs,
    }


# ---------------------------------------------------------------------------
# Holdout (P7.3): 3 never-seen formats, seed 9090, frozen until P8.
# ---------------------------------------------------------------------------

def holdout_mikrotik(rng: random.Random) -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    raw = (f"<134>Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} "
           f"gw-mikrotik-ccr system,info,account,"
           f"user admin logged in from {sip} via winbox")
    return record(raw, "MikroTik", "mikrotik_account",
                  {"src_ip": sip, "dst_ip": None, "src_port": None,
                   "dst_port": None, "protocol": None},
                  None, None, "clean", "base:mikrotik-info")


def holdout_mikrotik_fw(rng: random.Random) -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([443, 80])
    raw = (f"<134>Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} "
           f"gw-mikrotik-ccr firewall,info,"
           f"Allow forward in:ether1 out:ether2, proto TCP "
           f"{sip}:{sport}->{dip}:{dport}")
    return record(raw, "MikroTik", "mikrotik_firewall",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": "tcp"},
                  "Allowed", "tcp", "clean", "base:mikrotik-fw")


def holdout_juniper_srx(rng: random.Random) -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([443, 22])
    raw = (f"<134>Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} "
           f"srx1400 RT_FLOW: RT_FLOW_SESSION_CREATE - session created "
           f"{sip}/{sport}->{dip}/{dport} vpn-a|trust|untrust|N/A|N/A|root|"
           f"{rng.randint(10**15, 10**16 - 1):x}|20|6")
    return record(raw, "Juniper", "juniper_rt_flow",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": "tcp"},
                  "Allowed", "tcp", "clean", "base:juniper-create")


def holdout_juniper_deny(rng: random.Random) -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    sport, dport = rng.randint(1024, 65000), rng.choice([3389, 23])
    raw = (f"<134>Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} "
           f"srx1400 RT_FLOW: RT_FLOW_SESSION_CLOSE - session closed "
           f"{sip}/{sport}->{dip}/{dport} vpn-a|trust|untrust|N/A|N/A|root|"
           f"policy_denied|6|17")
    return record(raw, "Juniper", "juniper_rt_flow",
                  {"src_ip": sip, "dst_ip": dip, "src_port": sport,
                   "dst_port": dport, "protocol": "tcp"},
                  "Blocked", "tcp", "clean", "base:juniper-deny")


def holdout_fictitious(rng: random.Random) -> dict:
    sip, dip = ipv4(rng, True), ipv4(rng, False)
    verdict = rng.choice(["ALLOW", "DENY"])
    raw = (f"<134>Sep 21 14:0{rng.randint(0, 5)}:{rng.randint(10, 59)} "
           f"zfw-edge-01 zfw: RULE engine={verdict} policy=internet-out "
           f"src={sip} dst={dip} bytes={rng.randint(64, 999999)}")
    return record(raw, "ZypherFire", "zypherfire_rule",
                  {"src_ip": sip, "dst_ip": dip, "src_port": None,
                   "dst_port": None, "protocol": None},
                  "Allowed" if verdict == "ALLOW" else "Blocked", None,
                  "clean", "base:zypherfire")


def build_holdout(rng: random.Random) -> list[dict]:
    recs: list[dict] = []
    for _ in range(40):
        recs += [holdout_mikrotik(rng), holdout_mikrotik_fw(rng),
                 holdout_juniper_srx(rng), holdout_juniper_deny(rng),
                 holdout_fictitious(rng)]
    return dedup_keep_order(recs)


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def write_log(path: Path, raws: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(raws) + "\n", encoding="utf-8")


def write_sidecar(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False,
                                separators=(",", ":")) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--holdout", action="store_true",
                    help="ALSO generate data/raw/holdout/ (seed 9090; the "
                         "holdout is frozen until the P8 final freeze)")
    args = ap.parse_args()

    rng = random.Random(SEED_ADV)
    bases = build_bases(rng)
    adversarial = dedup_keep_order(
        [r for b in bases for r in mutate(rng, b)])
    # Keep the committed corpus bounded (plan P7.6: total < ~1 MB).
    assert len(adversarial) <= 2500, len(adversarial)

    adv_dir = REPO / "data" / "raw" / "adversarial"
    write_log(adv_dir / "adversarial.log", [r["raw"] for r in adversarial])
    write_sidecar(adv_dir / "gt.jsonl", adversarial)

    expansion = build_expansion(rng)
    for name, lines in expansion.items():
        write_log(REPO / "data" / "raw" / name, lines)

    total_bytes = sum(
        p.stat().st_size for p in (adv_dir / "adversarial.log",
                                   *[REPO / "data" / "raw" / n
                                     for n in expansion]))
    print(f"adversarial: {len(adversarial)} records -> {adv_dir}")
    print("expansion: " + ", ".join(
        f"{n} ({len(l)})" for n, l in expansion.items()))
    print(f"committed bytes: {total_bytes}")

    if args.holdout:
        hrng = random.Random(SEED_HOLDOUT)
        hold = build_holdout(hrng)
        hdir = REPO / "data" / "raw" / "holdout"
        write_log(hdir / "holdout.log", [r["raw"] for r in hold])
        write_sidecar(hdir / "gt.jsonl", hold)
        print(f"holdout (FROZEN until P8): {len(hold)} records -> {hdir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
