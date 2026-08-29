import json

MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110.001",
        "tactic": "Credential Access",
        "name": "Brute Force: Password Guessing",
        "description": "Adversaries may use brute force techniques to attempt authentication against network services by guessing passwords repeatedly.",
        "detection_triggers": "High Failed Login Attempts (>= 5 attempts)",
        "mitigations": [
            {"id": "M1036", "name": "Account Use Policies", "desc": "Enforce account lockouts and multi-factor authentication (MFA)."},
            {"id": "M1037", "name": "Filter Network Traffic", "desc": "Block attacking IPs using edge firewall ACL drop rules."}
        ]
    },
    "T1498": {
        "id": "T1498.001",
        "tactic": "Impact",
        "name": "Network Denial of Service: Direct Flood",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted services.",
        "detection_triggers": "High Request Volume (>= 300 req/min) & High Bandwidth Load",
        "mitigations": [
            {"id": "M1037", "name": "Filter Network Traffic", "desc": "Enforce upstream BGP rate limiting and syn flood throttling."},
            {"id": "M1030", "name": "Network Segmentation", "desc": "Isolate high-load traffic to DDoS mitigation scrubbing pools."}
        ]
    },
    "T1048": {
        "id": "T1048.003",
        "tactic": "Exfiltration",
        "name": "Exfiltration Over Unencrypted Network Protocol",
        "description": "Adversaries may steal data by transferring it over network protocols outside of normal operating schedules.",
        "detection_triggers": "Off-Hours Activity (Unusual Hour = 1) + High Network Throughput",
        "mitigations": [
            {"id": "M1031", "name": "Network Intrusion Prevention", "desc": "Enforce deep packet inspection and off-hours outbound data transfer limits."},
            {"id": "M1041", "name": "Data Loss Prevention (DLP)", "desc": "Block unauthorized bulk database dumps."}
        ]
    },
    "T1046": {
        "id": "T1046",
        "tactic": "Discovery",
        "name": "Network Service Discovery: Port Scanning",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify exploitable open ports.",
        "detection_triggers": "Multiple rapid port touches across short time windows",
        "mitigations": [
            {"id": "M1030", "name": "Network Segmentation", "desc": "Close unused listening ports and filter perimeter scanning probes."},
            {"id": "M1037", "name": "Filter Network Traffic", "desc": "Deploy Honeypot deception tokens to trap automated port scans."}
        ]
    },
    "T1078": {
        "id": "T1078",
        "tactic": "Defense Evasion / Initial Access",
        "name": "Valid Accounts: Darknet / Tor Ingress Abuse",
        "description": "Adversaries may obtain and abuse credentials or Tor darknet anonymizers to evade location-based access controls.",
        "detection_triggers": "Tor Exit Relay detected via OSINT threat feeds",
        "mitigations": [
            {"id": "M1026", "name": "Privileged Account Management", "desc": "Prohibit direct logins from known Tor and anonymous VPN exit nodes."},
            {"id": "M1036", "name": "Account Use Policies", "desc": "Mandate step-up biometric / FIDO2 MFA authentication."}
        ]
    }
}


def map_threat_to_mitre(incident_data):
    """
    Evaluates incident metrics and returns mapped MITRE ATT&CK Tactics & Techniques.
    """
    mapped = []
    failed = incident_data.get("failed_attempts", 0)
    reqs = incident_data.get("request_count", 0)
    unusual = incident_data.get("unusual_hour", 0)
    net = incident_data.get("network_activity", 0)
    geo = incident_data.get("geo", {})

    if failed >= 5:
        mapped.append(MITRE_TECHNIQUES["T1110"])
    if reqs >= 250 or net >= 600:
        mapped.append(MITRE_TECHNIQUES["T1498"])
    if (str(unusual) in ["1", 1] and net >= 400):
        mapped.append(MITRE_TECHNIQUES["T1048"])
    if (reqs >= 150 and failed <= 4):
        mapped.append(MITRE_TECHNIQUES["T1046"])
    if geo.get("is_tor"):
        mapped.append(MITRE_TECHNIQUES["T1078"])

    if not mapped:
        mapped.append(MITRE_TECHNIQUES["T1046"])

    return mapped


def get_full_mitre_matrix():
    """Returns the complete structured MITRE ATT&CK Matrix registry."""
    return list(MITRE_TECHNIQUES.values())
