import os
import json
from datetime import datetime

BLOCKED_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "blocked_ips.json")
INCIDENTS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "incidents.json")


def _load_json(file_path, default):
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def _save_json(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def get_blocked_ips():
    """Returns a list of all currently quarantined / blocked IPs."""
    data = _load_json(BLOCKED_FILE, [])
    return data


def is_ip_blocked(ip):
    """Checks if an IP is currently in the active firewall blocklist."""
    ip = str(ip).strip()
    blocked_list = get_blocked_ips()
    for item in blocked_list:
        if item.get("ip") == ip and item.get("status", "ACTIVE") == "ACTIVE":
            return True, item
    return False, None


def block_ip(ip, reason="Automated AI Threat Detection", threat_level="HIGH", risk_score=None, blocked_by="SentinelX SOC Engine"):
    """Adds an IP to the active firewall blocklist."""
    ip = str(ip).strip()
    if not ip:
        return False, "Invalid IP address"

    blocked_list = get_blocked_ips()
    # Check if already blocked
    for item in blocked_list:
        if item.get("ip") == ip:
            item["status"] = "ACTIVE"
            item["reason"] = reason
            item["threat_level"] = threat_level
            item["risk_score"] = risk_score
            item["updated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            _save_json(BLOCKED_FILE, blocked_list)
            return True, "IP containment rule updated"

    new_block = {
        "rule_id": f"FW-BLK-{ip.replace('.', '')[-6:]}",
        "ip": ip,
        "reason": reason,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "status": "ACTIVE",
        "blocked_by": blocked_by,
        "blocked_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "iptables_cmd": f"iptables -A INPUT -s {ip} -j DROP",
        "netsh_cmd": f'netsh advfirewall firewall add rule name="SentinelX_Block_{ip}" dir=in action=block remoteip={ip}'
    }
    blocked_list.insert(0, new_block)
    _save_json(BLOCKED_FILE, blocked_list)
    return True, "IP quarantined and blocked successfully"


def unblock_ip(ip):
    """Removes or deactivates an IP from the firewall blocklist."""
    ip = str(ip).strip()
    blocked_list = get_blocked_ips()
    updated = [item for item in blocked_list if item.get("ip") != ip]
    if len(updated) != len(blocked_list):
        _save_json(BLOCKED_FILE, updated)
        return True, "IP successfully removed from quarantine"
    return False, "IP was not found in active blocklist"


def get_firewall_rule_commands(ip):
    """Generates cross-platform CLI firewall containment scripts."""
    clean_ip = str(ip).strip()
    return {
        "linux_iptables": f"iptables -A INPUT -s {clean_ip} -j DROP",
        "linux_ufw": f"ufw deny from {clean_ip} to any",
        "windows_netsh": f'netsh advfirewall firewall add rule name="SentinelX_Block_{clean_ip}" dir=in action=block remoteip={clean_ip}',
        "windows_powershell": f'New-NetFirewallRule -DisplayName "SentinelX_Block_{clean_ip}" -Direction Inbound -Action Block -RemoteAddress {clean_ip}'
    }


def get_incidents():
    """Retrieves all tracked incident investigation cases."""
    return _load_json(INCIDENTS_FILE, [])


def update_incident_status(ip, status, analyst_notes="", threat_level="HIGH", risk_score=None):
    """Creates or updates a SOC incident investigation case."""
    ip = str(ip).strip()
    if not ip:
        return False

    incidents = get_incidents()
    for inc in incidents:
        if inc.get("ip") == ip:
            inc["status"] = status
            if analyst_notes:
                inc["analyst_notes"] = analyst_notes
            inc["updated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            _save_json(INCIDENTS_FILE, incidents)
            return True

    new_inc = {
        "case_id": f"INC-{ip.replace('.', '')[-6:]}-{datetime.utcnow().strftime('%M%S')}",
        "ip": ip,
        "status": status,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "analyst_notes": analyst_notes or "Initial incident triage created by SentinelX AI.",
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    incidents.insert(0, new_inc)
    _save_json(INCIDENTS_FILE, incidents)
    return True
