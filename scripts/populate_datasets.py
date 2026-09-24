#!/usr/bin/env python3
"""
Generator script to populate data/raw with high-fidelity perimeter network device datasets:
- cisco_asa.log (250+ lines)
- fortigate.log (250+ lines)
- paloalto.log (250+ lines)
- suricata.json (250+ lines)
- pfsense.log (250+ lines)
- kaggle_firewall.csv (2000+ records extracted from genuine UCI/Kaggle dataset)
"""

import os
import random
import json
import zipfile
from datetime import datetime, timedelta

random.seed(42)

# Script-relative output (repo's data/raw) — never a foreign hardcoded home.
# Override: ULPF_OUT_DIR=/path/to/raw python3 scripts/populate_datasets.py
OUT_DIR = os.environ.get(
    "ULPF_OUT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "raw"),
)
os.makedirs(OUT_DIR, exist_ok=True)

# -------------------------------------------------------------
# 1. Cisco ASA
# -------------------------------------------------------------
def generate_cisco_asa(count=260):
    hostnames = ["asa-edge-01", "asa-core-fw", "asa-dc-01", "asa-vpn-gw01"]
    interfaces = ["outside", "inside", "dmz", "management"]
    internal_ips = [f"10.1.{random.randint(1, 20)}.{random.randint(2, 250)}" for _ in range(30)]
    external_ips = [f"198.51.100.{random.randint(1, 250)}" for _ in range(25)] + \
                   [f"203.0.113.{random.randint(1, 250)}" for _ in range(25)]
    dmz_ips = [f"172.16.1.{random.randint(2, 50)}" for _ in range(10)]
    
    ports = [80, 443, 22, 53, 3389, 8080, 8443, 25, 110, 993, 1433, 3306, 5060, 123]
    usernames = ["jsmith", "dchen", "agarcia", "bwilson", "mkowalski", "tpatel", "alewis"]
    groups = ["AnyConnect-VPN", "RemoteAccess-Corp", "Contractors-VPN", "DefaultRAGroup"]
    reasons = ["TCP FINs", "SYN Timeout", "Reset-I", "Reset-O", "Idle Timeout", "Connection timeout", "Flow Closed by Inspection"]
    vpn_reasons = ["User Requested", "Idle Timeout", "Session Timeout", "Connection Lost", "Administrator Reset"]

    start_time = datetime(2026, 9, 21, 14, 0, 0)
    lines = []

    for i in range(count):
        cur_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 2))
        timestamp_rfc3164 = cur_time.strftime("%b %d %H:%M:%S")
        hostname = random.choice(hostnames)
        conn_id = 1000000 + i * 17 + random.randint(1, 1000)
        
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips)
        src_port = random.randint(10240, 65530)
        dst_port = random.choice(ports)
        nat_src_ip = f"198.51.100.{random.randint(200, 240)}"
        
        # Message types: builds (302013/302015), teardowns (302014/302016), denies (106023), drops (106001), VPN (113019/722022)
        m_type = i % 7
        if m_type == 0:
            # %ASA-6-302013 Built TCP
            direction = random.choice(["inbound", "outbound"])
            pri = "<166>"
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-6-302013: Built {direction} TCP connection {conn_id} for outside:{dst_ip}/{dst_port} ({dst_ip}/{dst_port}) to inside:{src_ip}/{src_port} ({nat_src_ip}/{src_port})"
        elif m_type == 1:
            # %ASA-6-302014 Teardown TCP
            duration = f"0:{random.randint(0, 59):02d}:{random.randint(1, 59):02d}"
            bytes_cnt = random.randint(250, 4500000)
            reason = random.choice(reasons)
            pri = "<166>"
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-6-302014: Teardown TCP connection {conn_id} for outside:{dst_ip}/{dst_port} to inside:{src_ip}/{src_port} duration {duration} bytes {bytes_cnt} {reason}"
        elif m_type == 2:
            # %ASA-6-302015 Built UDP
            direction = random.choice(["inbound", "outbound"])
            pri = "<166>"
            udp_port = random.choice([53, 123, 161, 500, 4500, 5060])
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-6-302015: Built {direction} UDP connection {conn_id} for outside:{dst_ip}/{udp_port} ({dst_ip}/{udp_port}) to inside:{src_ip}/{src_port} ({nat_src_ip}/{src_port})"
        elif m_type == 3:
            # %ASA-6-302016 Teardown UDP
            duration = f"0:00:{random.randint(1, 30):02d}"
            bytes_cnt = random.randint(64, 8192)
            udp_port = random.choice([53, 123, 161, 500, 4500, 5060])
            pri = "<166>"
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-6-302016: Teardown UDP connection {conn_id} for outside:{dst_ip}/{udp_port} to inside:{src_ip}/{src_port} duration {duration} bytes {bytes_cnt}"
        elif m_type == 4:
            # %ASA-4-106023 Deny
            proto = random.choice(["tcp", "udp"])
            pri = "<164>"
            acl = random.choice(["outside_access_in", "dmz_inbound_acl", "perimeter_filter"])
            hash1 = f"0x{random.randint(0x10000000, 0xffffffff):08x}"
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-4-106023: Deny {proto} src outside:{dst_ip}/{src_port} dst inside:{src_ip}/{dst_port} by access-group \"{acl}\" [{hash1}, 0x0]"
        elif m_type == 5:
            # %ASA-2-106001 Inbound drop
            pri = "<162>"
            flags = random.choice(["SYN", "SYN+ACK", "ACK", "FIN", "RST"])
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-2-106001: Inbound TCP connection denied from {dst_ip}/{src_port} to {src_ip}/{dst_port} flags {flags} on interface outside"
        else:
            # %ASA-4-113019 / %ASA-6-722022 VPN
            user = random.choice(usernames)
            grp = random.choice(groups)
            pri = "<164>"
            vpn_ip = random.choice(external_ips)
            dur_hrs = f"{random.randint(0, 3)}h:{random.randint(1, 59):02d}m:{random.randint(0, 59):02d}s"
            tx = random.randint(10000, 50000000)
            rx = random.randint(10000, 30000000)
            reason = random.choice(vpn_reasons)
            msg = f"{pri}{timestamp_rfc3164} {hostname} %ASA-4-113019: Group = {grp}, Username = {user}, IP = {vpn_ip}, Session disconnected. Session Type: SSL, Duration: {dur_hrs}, Bytes xmt: {tx}, Bytes rcv: {rx}, Reason: {reason}"

        lines.append(msg)

    with open(os.path.join(OUT_DIR, "cisco_asa.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Wrote {len(lines)} lines to {OUT_DIR}/cisco_asa.log")

# -------------------------------------------------------------
# 2. Fortinet FortiGate
# -------------------------------------------------------------
def generate_fortigate(count=260):
    devnames = ["FGT-CORP-FW01", "FGT-DC-EDGE", "FGT-BRANCH-02"]
    devids = ["FGT60D4614041123", "FGT100E391780045", "FGT200F581900120"]
    vd_names = ["root", "vdom-dmz"]
    intfs_src = ["port1", "port2", "lan", "internal", "trust"]
    intfs_dst = ["wan1", "wan2", "port3", "untrust", "dmz"]
    
    actions = ["accept", "deny", "close", "timeout", "client-rst", "server-rst"]
    services = [("HTTPS", 443, 6), ("HTTP", 80, 6), ("DNS", 53, 17), ("SSH", 22, 6), 
                ("NTP", 123, 17), ("RDP", 3389, 6), ("IMAPS", 993, 6), ("FTP", 21, 6)]
    
    src_ips = [f"192.168.{random.randint(1, 10)}.{random.randint(10, 200)}" for _ in range(40)]
    dst_ips = [f"203.0.113.{random.randint(1, 240)}" for _ in range(25)] + \
              [f"198.51.100.{random.randint(1, 240)}" for _ in range(25)]
    
    start_time = datetime(2026, 9, 21, 14, 0, 0)
    lines = []

    for i in range(count):
        cur_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 1))
        d_str = cur_time.strftime("%Y-%m-%d")
        t_str = cur_time.strftime("%H:%M:%S")
        epoch_nano = int(cur_time.timestamp() * 1e9) + random.randint(1000, 999999)
        
        devname = random.choice(devnames)
        devid = random.choice(devids)
        vd = random.choice(vd_names)
        logid = f"{random.randint(1, 20):010d}"
        
        srv, dstport, proto = random.choice(services)
        srcip = random.choice(src_ips)
        dstip = random.choice(dst_ips)
        srcport = random.randint(10240, 65530)
        srcintf = random.choice(intfs_src)
        dstintf = random.choice(intfs_dst)
        
        poluuid = f"{random.randint(0x10000000, 0xffffffff):08x}-4148-51ec-8962-e61e05d05051"
        sessionid = 1000000 + i * 31 + random.randint(1, 500)
        action = random.choice(actions)
        policyid = random.randint(1, 50)
        
        duration = random.randint(1, 3600)
        sentbyte = random.randint(128, 500000)
        rcvdbyte = random.randint(128, 2500000)
        sentpkt = max(1, sentbyte // random.randint(60, 1400))
        rcvdpkt = max(1, rcvdbyte // random.randint(60, 1400))
        transip = f"198.51.100.{random.randint(5, 50)}"
        
        if i % 5 == 0:
            # CEF format
            cef_line = (
                f"CEF:0|Fortinet|FortiGate|v7.0.2|{logid}|traffic:forward {action}|3|"
                f"deviceExternalId={devid} src={srcip} spt={srcport} dst={dstip} dpt={dstport} "
                f"proto={proto} act={action} cat=traffic:forward cs1={vd} cs1Label=vd "
                f"cs2={srcintf} cs2Label=srcintf cs3={dstintf} cs3Label=dstintf cn1={policyid} cn1Label=policyid "
                f"app={srv} in={sentbyte} out={rcvdbyte} dvchost={devname}"
            )
            lines.append(cef_line)
        else:
            # Key-Value format
            kv_line = (
                f"<189>date={d_str} time={t_str} devname=\"{devname}\" devid=\"{devid}\" "
                f"eventtime={epoch_nano} tz=\"+0000\" logid=\"{logid}\" type=\"traffic\" subtype=\"forward\" "
                f"level=\"notice\" vd=\"{vd}\" srcip={srcip} srcport={srcport} srcintf=\"{srcintf}\" "
                f"srcintfrole=\"lan\" dstip={dstip} dstport={dstport} dstintf=\"{dstintf}\" dstintfrole=\"wan\" "
                f"poluuid=\"{poluuid}\" sessionid={sessionid} proto={proto} action=\"{action}\" policyid={policyid} "
                f"policytype=\"policy\" service=\"{srv}\" trandisp=\"snat\" transip={transip} transport={srcport} "
                f"duration={duration} sentbyte={sentbyte} rcvdbyte={rcvdbyte} sentpkt={sentpkt} rcvdpkt={rcvdpkt} "
                f"appcat=\"unscanned\""
            )
            lines.append(kv_line)

    with open(os.path.join(OUT_DIR, "fortigate.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Wrote {len(lines)} lines to {OUT_DIR}/fortigate.log")

# -------------------------------------------------------------
# 3. Palo Alto PAN-OS CSV
# -------------------------------------------------------------
def generate_paloalto(count=260):
    serials = ["001801000001", "001801000002", "001801000003"]
    subtypes = ["end", "start", "drop", "deny"]
    rules = ["Trust_to_Untrust", "Web_Access", "Default_Deny", "DMZ_Outbound", "VPN_Internal", "Inter-VLAN"]
    users = ["acme\\jsmith", "acme\\dchen", "acme\\agarcia", "acme\\bwilson", ""]
    apps = [("web-browsing", 80, "tcp"), ("ssl", 443, "tcp"), ("dns", 53, "udp"), 
            ("ssh", 22, "tcp"), ("ping", 0, "icmp"), ("ms-rdp", 3389, "tcp"), ("ntp", 123, "udp")]
    zones_src = ["Trust", "LAN", "DMZ"]
    zones_dst = ["Untrust", "WAN", "External"]
    actions = ["allow", "deny", "drop", "reset-client", "reset-server", "reset-both"]
    categories = ["business-and-economy", "computer-and-internet-info", "networking", "content-delivery-networks", "web-hosting"]
    end_reasons = ["tcp-fin", "aged-out", "policy-deny", "tcp-rst-from-client", "threat"]

    src_ips = [f"192.168.1.{random.randint(10, 200)}" for _ in range(40)]
    dst_ips = [f"203.0.113.{random.randint(1, 240)}" for _ in range(25)] + \
              [f"198.51.100.{random.randint(1, 240)}" for _ in range(25)]

    start_time = datetime(2026, 9, 21, 14, 0, 0)
    lines = []

    for i in range(count):
        cur_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 1))
        recv_time = cur_time.strftime("%Y/%m/%d %H:%M:%S")
        gen_time = (cur_time - timedelta(seconds=random.randint(0, 2))).strftime("%Y/%m/%d %H:%M:%S")
        
        serial = random.choice(serials)
        subtype = random.choice(subtypes)
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        nat_src_ip = f"198.51.100.{random.randint(10, 50)}"
        nat_dst_ip = dst_ip
        rule = random.choice(rules)
        user = random.choice(users)
        app, dst_port, proto = random.choice(apps)
        src_port = random.randint(10240, 65530) if proto != "icmp" else 0
        action = "allow" if subtype in ["start", "end"] else random.choice(["deny", "drop"])
        
        bytes_sent = random.randint(100, 1000000)
        bytes_rcvd = random.randint(100, 5000000)
        total_bytes = bytes_sent + bytes_rcvd
        pkts_sent = max(1, bytes_sent // random.randint(100, 1400))
        pkts_rcvd = max(1, bytes_rcvd // random.randint(100, 1400))
        total_pkts = pkts_sent + pkts_rcvd
        elapsed = random.randint(1, 360)
        start_ts = (cur_time - timedelta(seconds=elapsed)).strftime("%Y/%m/%d %H:%M:%S")
        
        session_id = 100000 + i * 29 + random.randint(1, 999)
        seq_num = 100000000 + i * 1337 + random.randint(1, 500)
        category = random.choice(categories)
        end_reason = random.choice(end_reasons) if subtype == "end" else ""

        # Exactly 65 standard PAN-OS traffic fields (0 to 64)
        fields = [
            "1",                           # 0: FUTURE_USE
            recv_time,                     # 1: Receive Time
            serial,                        # 2: Serial Number
            "TRAFFIC",                     # 3: Type
            subtype,                       # 4: Subtype
            "2304",                        # 5: Config Version
            gen_time,                      # 6: Generate Time
            src_ip,                        # 7: Source IP
            dst_ip,                        # 8: Destination IP
            nat_src_ip,                    # 9: NAT Source IP
            nat_dst_ip,                    # 10: NAT Destination IP
            rule,                          # 11: Rule Name
            user,                          # 12: Source User
            "",                            # 13: Destination User
            app,                           # 14: Application
            "vsys1",                       # 15: Virtual System
            random.choice(zones_src),      # 16: Source Zone
            random.choice(zones_dst),      # 17: Destination Zone
            "ethernet1/1",                 # 18: Ingress Interface
            "ethernet1/2",                 # 19: Egress Interface
            "default",                     # 20: Log Action
            "",                            # 21: FUTURE_USE
            str(session_id),               # 22: Session ID
            "1",                           # 23: Repeat Count
            str(src_port),                 # 24: Source Port
            str(dst_port),                 # 25: Destination Port
            str(src_port),                 # 26: NAT Source Port
            str(dst_port),                 # 27: NAT Destination Port
            "0x400000",                    # 28: Flags
            proto,                         # 29: Protocol
            action,                        # 30: Action
            str(total_bytes),              # 31: Bytes
            str(bytes_sent),               # 32: Bytes Sent
            str(bytes_rcvd),               # 33: Bytes Rcvd
            str(total_pkts),               # 34: Packets
            start_ts,                      # 35: Start Time
            str(elapsed),                  # 36: Elapsed Time
            category,                      # 37: Category
            "0",                           # 38: FUTURE_USE
            str(seq_num),                  # 39: Sequence Number
            "0x0",                         # 40: Action Flags
            "192.168.0.0-192.168.255.255", # 41: Source Location
            "US",                          # 42: Destination Location
            "0",                           # 43: FUTURE_USE
            str(pkts_sent),                # 44: pkts_sent
            str(pkts_rcvd),                # 45: pkts_received
            end_reason,                    # 46: Session End Reason
            "0",                           # 47: Device Group Hierarchy Level 1
            "0",                           # 48: Device Group Hierarchy Level 2
            "0",                           # 49: Device Group Hierarchy Level 3
            "0",                           # 50: Device Group Hierarchy Level 4
            "vsys1",                       # 51: Virtual System Name
            "PA-5220-FW01",                # 52: Device Name
            "from-policy",                 # 53: Action Source
            "",                            # 54: Source VM UUID
            "",                            # 55: Destination VM UUID
            "0",                           # 56: Tunnel ID/IMSI
            "0",                           # 57: Monitor Tag/IMEI
            "0",                           # 58: Parent Session ID
            "",                            # 59: Parent Start Time
            "N/A",                         # 60: Tunnel Type
            "0",                           # 61: SCTP Association ID
            "0",                           # 62: SCTP Chunks
            "0",                           # 63: SCTP Chunks Sent
            "0",                           # 64: SCTP Chunks Rcvd
        ]
        lines.append(",".join(fields))

    with open(os.path.join(OUT_DIR, "paloalto.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Wrote {len(lines)} lines to {OUT_DIR}/paloalto.log")

# -------------------------------------------------------------
# 4. Suricata EVE-JSON
# -------------------------------------------------------------
def generate_suricata(count=260):
    signatures = [
        (2010935, "ET SCAN Potential SSH Scan OUTBOUND", "Attempted Information Leak", 2, "TCP", 22),
        (2000419, "ET POLICY Suspicious inbound to Oracle SQL port 1521", "Potential Corporate Privacy Violation", 2, "TCP", 1521),
        (2013028, "ET POLICY Cryptocoin Miner Stratum Protocol TCP", "A Network Trojan was detected", 1, "TCP", 3333),
        (2024897, "ET EXPLOIT Apache Log4j RCE CVE-2021-44228", "Attempted Administrator Privilege Gain", 1, "TCP", 8080),
        (2027757, "ET EXPLOIT Spring Framework RCE CVE-2022-22965", "Attempted Administrator Privilege Gain", 1, "TCP", 80),
        (2014726, "ET DOS Possible NTP DDoS Inbound Amplification", "Attempted Denial of Service", 2, "UDP", 123),
        (2018581, "ET DNS Query for .onion domain", "Potentially Bad Traffic", 2, "UDP", 53),
        (2001219, "ET SCAN Nmap Scripting Engine User-Agent Detected", "Web Application Attack", 3, "TCP", 80),
    ]

    domains = ["api.github.com", "pool.supportxmr.com", "update.microsoft.com", "c2.malicious-domain.cc", "cloudflare.com", "google.com"]
    src_ips = [f"10.0.0.{random.randint(10, 200)}" for _ in range(30)]
    dst_ips = [f"203.0.113.{random.randint(1, 240)}" for _ in range(25)] + \
              [f"198.51.100.{random.randint(1, 240)}" for _ in range(25)]

    start_time = datetime(2026, 9, 21, 14, 0, 0)
    lines = []

    for i in range(count):
        cur_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 1), microseconds=random.randint(1000, 999000))
        ts_str = cur_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-2] + "+0000"
        flow_id = 1400000000000000 + i * 4719 + random.randint(1, 1000)
        
        event_kind = i % 3
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        src_port = random.randint(10240, 65530)
        
        if event_kind == 0:
            # Alert
            sig_id, sig_name, category, severity, proto, dst_port = random.choice(signatures)
            record = {
                "timestamp": ts_str,
                "flow_id": flow_id,
                "in_iface": "eth0",
                "event_type": "alert",
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "proto": proto,
                "tx_id": 0,
                "alert": {
                    "action": random.choice(["allowed", "blocked"]),
                    "gid": 1,
                    "signature_id": sig_id,
                    "rev": random.randint(1, 5),
                    "signature": sig_name,
                    "category": category,
                    "severity": severity,
                },
                "app_proto": "http" if dst_port in [80, 8080] else ("dns" if dst_port == 53 else "tls")
            }
        elif event_kind == 1:
            # Flow
            dst_port = random.choice([443, 80, 53, 22, 123, 8080])
            proto = "UDP" if dst_port in [53, 123] else "TCP"
            pkts_to_server = random.randint(2, 50)
            pkts_to_client = random.randint(2, 80)
            bytes_to_server = pkts_to_server * random.randint(60, 1400)
            bytes_to_client = pkts_to_client * random.randint(60, 1400)
            start_ts = (cur_time - timedelta(seconds=random.randint(1, 60))).strftime("%Y-%m-%dT%H:%M:%S.000000+0000")
            
            record = {
                "timestamp": ts_str,
                "flow_id": flow_id,
                "in_iface": "eth0",
                "event_type": "flow",
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "proto": proto,
                "app_proto": "dns" if dst_port == 53 else ("http" if dst_port in [80, 8080] else "tls"),
                "flow": {
                    "pkts_toserver": pkts_to_server,
                    "pkts_toclient": pkts_to_client,
                    "bytes_toserver": bytes_to_server,
                    "bytes_toclient": bytes_to_client,
                    "start": start_ts,
                    "end": ts_str,
                    "age": random.randint(1, 120),
                    "state": random.choice(["closed", "established"]),
                    "reason": random.choice(["shutdown", "timeout"])
                }
            }
        else:
            # DNS
            domain = random.choice(domains)
            record = {
                "timestamp": ts_str,
                "flow_id": flow_id,
                "in_iface": "eth0",
                "event_type": "dns",
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": random.choice(["1.1.1.1", "8.8.8.8", "9.9.9.9"]),
                "dest_port": 53,
                "proto": "UDP",
                "app_proto": "dns",
                "dns": {
                    "type": random.choice(["query", "answer"]),
                    "id": random.randint(1000, 65535),
                    "rrname": domain,
                    "rrtype": random.choice(["A", "AAAA", "CNAME", "MX"]),
                    "tx_id": 0
                }
            }
            
        lines.append(json.dumps(record))

    with open(os.path.join(OUT_DIR, "suricata.json"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Wrote {len(lines)} lines to {OUT_DIR}/suricata.json")

# -------------------------------------------------------------
# 5. pfSense filterlog
# -------------------------------------------------------------
def generate_pfsense(count=260):
    intfs = ["igb0", "igb1", "em0", "vtnet0", "wan", "lan"]
    actions = ["pass", "block"]
    directions = ["in", "out"]
    tcp_flags = ["S", "A", "FA", "PA", "RA", "R", "F"]
    
    src_ips = [f"192.168.1.{random.randint(10, 200)}" for _ in range(30)]
    dst_ips = [f"203.0.113.{random.randint(1, 240)}" for _ in range(25)] + \
              [f"198.51.100.{random.randint(1, 240)}" for _ in range(25)]
              
    start_time = datetime(2026, 9, 21, 14, 0, 0)
    lines = []

    for i in range(count):
        cur_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 1))
        ts_syslog = cur_time.strftime("%b %d %H:%M:%S")
        pid = 20000 + (i % 50)
        
        rule_num = i + 1
        tracker = 1000000000 + random.randint(100, 999)
        intf = random.choice(intfs)
        action = random.choice(actions)
        direction = random.choice(directions)
        ttl = random.choice([64, 128, 255])
        sub_id = random.randint(1000, 65000)
        
        proto_choice = i % 3
        if proto_choice == 0:
            # TCP
            proto_id = 6
            proto_name = "tcp"
            length = random.choice([52, 60, 64, 1500])
            src_ip = random.choice(src_ips)
            dst_ip = random.choice(dst_ips)
            src_port = random.randint(10240, 65530)
            dst_port = random.choice([80, 443, 22, 3389, 8080, 8443])
            data_len = max(0, length - 52)
            flags = random.choice(tcp_flags)
            seq = random.randint(100000000, 4000000000)
            win = 65535
            line = (
                f"{ts_syslog} pfSense filterlog[{pid}]: {rule_num},16777216,,{tracker},{intf},"
                f"match,{action},{direction},4,0x0,,{ttl},{sub_id},0,DF,{proto_id},{proto_name},"
                f"{length},{src_ip},{dst_ip},{src_port},{dst_port},{data_len},{flags},{seq},,{win},,mss;sackOK;TS"
            )
        elif proto_choice == 1:
            # UDP
            proto_id = 17
            proto_name = "udp"
            data_len = random.randint(20, 512)
            length = data_len + 28
            src_ip = random.choice(src_ips)
            dst_ip = random.choice(dst_ips)
            src_port = random.randint(10240, 65530)
            dst_port = random.choice([53, 123, 161, 500, 4500])
            line = (
                f"{ts_syslog} pfSense filterlog[{pid}]: {rule_num},16777216,,{tracker},{intf},"
                f"match,{action},{direction},4,0x0,,{ttl},{sub_id},0,none,{proto_id},{proto_name},"
                f"{length},{src_ip},{dst_ip},{src_port},{dst_port},{data_len}"
            )
        else:
            # ICMP
            proto_id = 1
            proto_name = "icmp"
            length = 84
            data_len = 56
            src_ip = random.choice(src_ips)
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "198.51.100.1"])
            line = (
                f"{ts_syslog} pfSense filterlog[{pid}]: {rule_num},16777216,,{tracker},{intf},"
                f"match,{action},{direction},4,0x0,,{ttl},{sub_id},0,none,{proto_id},{proto_name},"
                f"{length},{src_ip},{dst_ip},request,0,0"
            )
            
        lines.append(line)

    with open(os.path.join(OUT_DIR, "pfsense.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Wrote {len(lines)} lines to {OUT_DIR}/pfsense.log")

# -------------------------------------------------------------
# 6. Kaggle Internet Firewall Data
# -------------------------------------------------------------
def generate_kaggle_firewall(record_count=2000):
    zip_path = "/tmp/firewall.zip"
    out_path = os.path.join(OUT_DIR, "kaggle_firewall.csv")
    
    if os.path.exists(zip_path):
        with zipfile.ZipFile(zip_path, 'r') as zf:
            with zf.open("log2.csv") as f:
                lines = []
                for idx, raw_line in enumerate(f):
                    lines.append(raw_line.decode('utf-8').strip())
                    if idx >= record_count: # 1 header + record_count rows
                        break
        with open(out_path, "w") as f_out:
            f_out.write("\n".join(lines) + "\n")
        print(f"[+] Extracted {len(lines)-1} genuine Kaggle records to {out_path}")
    else:
        # Fallback generator if zip not found
        header = "Source Port,Destination Port,NAT Source Port,NAT Destination Port,Action,Bytes,Bytes Sent,Bytes Received,Packets,Elapsed Time (sec),pkts_sent,pkts_received"
        actions = ["allow", "drop", "deny", "reset-both"]
        rows = [header]
        for _ in range(record_count):
            sp = random.randint(1024, 65535)
            dp = random.choice([80, 443, 53, 3389, 22, 8080, 445])
            nsp = sp if random.random() > 0.3 else random.randint(1024, 65535)
            ndp = dp
            act = random.choice(actions)
            elapsed = random.randint(0, 300)
            ps = random.randint(1, 50)
            pr = random.randint(0, 50) if act == "allow" else 0
            bs = ps * random.randint(40, 1400)
            br = pr * random.randint(40, 1400)
            tot_bytes = bs + br
            tot_pkts = ps + pr
            rows.append(f"{sp},{dp},{nsp},{ndp},{act},{tot_bytes},{bs},{br},{tot_pkts},{elapsed},{ps},{pr}")
        with open(out_path, "w") as f_out:
            f_out.write("\n".join(rows) + "\n")
        print(f"[+] Generated {len(rows)-1} Kaggle records to {out_path}")

if __name__ == "__main__":
    generate_cisco_asa()
    generate_fortigate()
    generate_paloalto()
    generate_suricata()
    generate_pfsense()
    generate_kaggle_firewall()
