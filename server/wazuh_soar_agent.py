import re
import time
import json
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

AUTH_LOG = Path("/var/log/auth.log")
ACCESS_LOG = Path("/var/log/nginx/access.log")
ALERTS_FILE = Path("/reports/wazuh_alerts.json")
REPORT_FILE = Path("/reports/soc_incident_report.txt")
NFT_EXPORT = Path("/reports/firewall_blocklist.nft")

BRUTE_FORCE_THRESHOLD = 5

SSH_FAIL_REGEX = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
WEB_REGEX = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[0-9.]+"\s+(?P<status>\d+)'
)

failed_ssh = defaultdict(list)
blocked_ips = set()
alerts = []

def block_ip_in_kernel(ip: str):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        subprocess.run(
            ["nft", "add", "element", "inet", "wazuh_active_response", "attacker_blacklist", f"{{ {ip} }}"],
            check=False
        )
        print(f"    |-- [SOAR ACTIVE RESPONSE] Kernel nftables drop applied: {ip} BLOCKED!", flush=True)
        export_reports()

def record_alert(rule_id: str, level: int, desc: str, mitre_id: str, ip: str, raw_log: str, block_now: bool = True):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": rule_id, "level": level, "description": desc, "mitre": {"id": [mitre_id]}},
        "agent": {"id": "001", "name": "prod-server", "ip": "172.28.10.10"},
        "data": {"srcip": ip},
        "full_log": raw_log,
    }
    alerts.append(alert)
    ALERTS_FILE.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"\n[!] WAZUH SIEM ALERT [Rule {rule_id}] -> {desc} [MITRE {mitre_id}]", flush=True)
    print(f"    |-- Source IP : {ip} | Node: prod-server (172.28.10.10)", flush=True)
    if block_now:
        block_ip_in_kernel(ip)
    else:
        export_reports()

def export_reports():
    ruleset = subprocess.run(["nft", "list", "table", "inet", "wazuh_active_response"], capture_output=True, text=True).stdout
    NFT_EXPORT.write_text(ruleset, encoding="utf-8")

    lines = [
        "======================================================================",
        "      WAZUH SIEM & KERNEL SOAR LAB - LIVE INCIDENT REPORT             ",
        "======================================================================",
        "Protected Node    : prod-server (172.28.10.10)",
        f"Total Alerts Fired: {len(alerts)}",
        f"Blocked Hosts     : {', '.join(sorted(blocked_ips)) if blocked_ips else 'None'}",
        "----------------------------------------------------------------------",
        "TRIGGERED WAZUH ALERTS:",
    ]
    for a in alerts:
        r = a["rule"]
        lines.append(f"  [Rule {r['id']} | Level {r['level']:2d} | MITRE {r['mitre']['id'][0]}] {r['description']} (Src: {a['data']['srcip']})")
    lines.append("----------------------------------------------------------------------")
    lines.append("ACTIVE KERNEL NFTABLES RULESET:")
    lines.append(ruleset.strip())
    lines.append("======================================================================")
    REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

def monitor():
    print("======================================================================", flush=True)
    print("   WAZUH SOAR AGENT ONLINE ON prod-server (172.28.10.10)              ", flush=True)
    print("   Monitoring /var/log/auth.log (SSH) & /var/log/nginx/access.log     ", flush=True)
    print("======================================================================", flush=True)

    with open(AUTH_LOG, "r", encoding="utf-8", errors="ignore") as fa, open(ACCESS_LOG, "r", encoding="utf-8", errors="ignore") as fw:
        while True:
            line_a = fa.readline()
            if line_a:
                m = SSH_FAIL_REGEX.search(line_a)
                if m:
                    ip, user = m.group("ip"), m.group("user")
                    failed_ssh[ip].append(user)
                    cnt = len(failed_ssh[ip])
                    print(f"[SSH AUTH] Failed login #{cnt}/{BRUTE_FORCE_THRESHOLD} from {ip} (user: {user})", flush=True)
                    if cnt == BRUTE_FORCE_THRESHOLD:
                        record_alert("100001", 10, f"SSH Brute-Force threshold reached ({cnt} attempts)", "T1110.001", ip, line_a.strip(), block_now=True)

            line_w = fw.readline()
            if line_w:
                m = WEB_REGEX.search(line_w)
                if m:
                    ip, url = m.group("ip"), m.group("url")
                    print(f"[HTTP LOG] {ip} requested {url}", flush=True)
                    if re.search(r"(?i)(union.*select|select.*from|'\s*or\s*1=1|--)", url):
                        record_alert("100002", 12, f"SQL Injection signature detected on {url}", "T1190", ip, line_w.strip(), block_now=False)

            if not line_a and not line_w:
                time.sleep(0.1)

if __name__ == "__main__":
    monitor()
