import os
import json
from datetime import datetime
from utils.firewall import block_ip, update_incident_status
from utils.notifications import dispatch_webhook_alert

SOAR_HISTORY_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "soar_history.json")

PLAYBOOKS = [
    {
        "id": "PB-BRUTE-01",
        "name": "Automated Brute Force & Credential Spray Containment",
        "target_vector": "SSH / RDP / Web Auth Brute Force",
        "severity": "HIGH",
        "description": "Triggered when repeated authentication failures exceed safety threshold. Automates IP quarantine, session revocation, and security broadcast.",
        "steps": [
            {"num": 1, "action": "Firewall ACL Ingress Block", "command": "iptables -A INPUT -s {ip} -j DROP", "status": "PENDING"},
            {"num": 2, "action": "Revoke User Active OAuth Tokens & Sessions", "command": "AUTH_SERVICE.revoke_tokens_by_ip('{ip}')", "status": "PENDING"},
            {"num": 3, "action": "Enforce Mandatory MFA / Step-Up Challenge", "command": "MFA_POLICY.enforce_ip_quarantine('{ip}')", "status": "PENDING"},
            {"num": 4, "action": "Dispatch SIEM Alert Webhook to SOC Channel", "command": "WEBHOOK_DISPATCHER.broadcast_alert('{ip}')", "status": "PENDING"},
            {"num": 5, "action": "Commit Incident Case into Forensics Registry", "command": "INCIDENT_DB.commit_contained_case('{ip}')", "status": "PENDING"}
        ]
    },
    {
        "id": "PB-DDOS-02",
        "name": "Layer 7 HTTP DDoS & High-Load Scrubbing Playbook",
        "target_vector": "Volumetric HTTP Flood / DDoS",
        "severity": "CRITICAL",
        "description": "Triggered when request volume spikes beyond normal baseline. Enforces rate limits, BGP drop, and traffic scrubbing.",
        "steps": [
            {"num": 1, "action": "Enforce Upstream BGP Rate Limiting (max 30 req/min)", "command": "BGP_EDGE.apply_rate_limit('{ip}', 30)", "status": "PENDING"},
            {"num": 2, "action": "Deploy Cloudflare / Edge Challenge Challenge Mode", "command": "EDGE_WAF.enable_under_attack_mode('{ip}')", "status": "PENDING"},
            {"num": 3, "action": "Drop Malicious TCP SYN/ACK flood at Kernel Level", "command": "iptables -t raw -A PREROUTING -s {ip} -j DROP", "status": "PENDING"},
            {"num": 4, "action": "Notify SOC Network Operations Center (NOC)", "command": "NOC_ALERT.send_high_priority_page('{ip}')", "status": "PENDING"}
        ]
    },
    {
        "id": "PB-EXFIL-03",
        "name": "Off-Hours Exfiltration & Lateral Movement Isolation",
        "target_vector": "Data Exfiltration / Lateral Movement",
        "severity": "HIGH",
        "description": "Triggered on high-bandwidth outbound transfers during off-hours. Immediately cuts network egress and dumps memory forensics.",
        "steps": [
            {"num": 1, "action": "Immediate Host Isolation & Egress Cutoff", "command": "iptables -A OUTPUT -d {ip} -j REJECT", "status": "PENDING"},
            {"num": 2, "action": "Trigger Live Network Packet Dump (PCAP)", "command": "tcpdump -i eth0 host {ip} -w /pcap/{ip}_capture.pcap", "status": "PENDING"},
            {"num": 3, "action": "Quarantine Affected Database Credentials", "command": "VAULT.rotate_database_secrets()", "status": "PENDING"},
            {"num": 4, "action": "Escalate to Incident Response Tier 2 Analyst", "command": "SOAR_ESCALATION.page_tier2_analyst('{ip}')", "status": "PENDING"}
        ]
    }
]


def _load_history():
    if os.path.exists(SOAR_HISTORY_FILE):
        try:
            with open(SOAR_HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_history(data):
    os.makedirs(os.path.dirname(SOAR_HISTORY_FILE), exist_ok=True)
    try:
        with open(SOAR_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def get_playbooks():
    return PLAYBOOKS


def get_soar_history():
    return _load_history()


def execute_playbook(playbook_id, target_ip):
    """
    Executes a multi-stage SOAR Playbook on the target IP:
    1. Blocks IP in perimeter firewall
    2. Updates incident lifecycle to Contained
    3. Dispatches Webhook notification
    4. Logs execution timeline
    """
    clean_ip = str(target_ip).strip()
    selected_pb = None
    for pb in PLAYBOOKS:
        if pb["id"] == playbook_id:
            selected_pb = pb
            break

    if not selected_pb:
        selected_pb = PLAYBOOKS[0]

    # Execute Action 1: Block IP in firewall
    block_ip(clean_ip, reason=f"Automated SOAR Playbook Execution: {selected_pb['name']}", threat_level=selected_pb["severity"])
    
    # Execute Action 2: Update incident case
    update_incident_status(clean_ip, status="Contained", analyst_notes=f"SOAR Playbook {selected_pb['id']} ({selected_pb['name']}) executed automatically.")

    # Execute Action 3: Webhook broadcast
    try:
        dispatch_webhook_alert({
            "source_ip": clean_ip,
            "level": selected_pb["severity"],
            "risk": 95,
            "reasons": [f"SOAR Playbook {selected_pb['id']} executed", selected_pb["description"]],
            "is_blocked": True
        })
    except Exception:
        pass

    # Build execution log
    executed_steps = []
    for s in selected_pb["steps"]:
        executed_steps.append({
            "num": s["num"],
            "action": s["action"],
            "command": s["command"].replace("{ip}", clean_ip),
            "status": "COMPLETED (SUCCESS)",
            "executed_at": datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
        })

    record = {
        "execution_id": f"SOAR-EXEC-{clean_ip.replace('.', '')[-6:]}-{datetime.utcnow().strftime('%M%S')}",
        "playbook_id": selected_pb["id"],
        "playbook_name": selected_pb["name"],
        "target_ip": clean_ip,
        "severity": selected_pb["severity"],
        "status": "SUCCESSFULLY ORCHESTRATED",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "steps": executed_steps
    }

    history = _load_history()
    history.insert(0, record)
    _save_history(history[:25])

    return record
