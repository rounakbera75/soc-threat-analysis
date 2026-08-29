import os
import json
import urllib.request
from datetime import datetime

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "webhook_config.json")


def get_webhook_config():
    default_config = {
        "webhook_url": "",
        "enabled": False,
        "min_severity": "HIGH",
        "alerts_sent": 0,
        "history": []
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default_config


def save_webhook_config(url, enabled=True, min_severity="HIGH"):
    config = get_webhook_config()
    config["webhook_url"] = str(url).strip()
    config["enabled"] = bool(enabled)
    config["min_severity"] = str(min_severity)
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def dispatch_webhook_alert(incident_data):
    """
    Sends rich incident notifications to Discord, Slack, or generic SIEM webhooks.
    Includes rich embed with threat level, IP, geolocation, attack signatures, and remediation.
    """
    config = get_webhook_config()
    url = config.get("webhook_url", "").strip()

    ip = incident_data.get("source_ip", "Unknown IP")
    level = incident_data.get("level", "HIGH")
    risk = incident_data.get("risk", 100)
    geo = incident_data.get("geo", {})
    country = geo.get("country", "Unknown")
    flag = geo.get("flag", "🌐")
    reasons = incident_data.get("reasons", ["Anomalous security activity"])

    # Build rich notification payload
    color = 15548997 if level == "HIGH" else (16098851 if level == "MEDIUM" else 1091599) # Hex colors in decimal

    discord_payload = {
        "username": "SentinelX SOC Sentinel",
        "avatar_url": "https://img.icons8.com/color/96/shield.png",
        "content": f"🚨 **[SOC CRITICAL INCIDENT ALERT]** Threat detected on endpoint `{ip}`",
        "embeds": [
            {
                "title": f"🛡️ SentinelX AI Threat Assessment: {level} SEVERITY",
                "description": f"Anomalous cyber threat activity identified by Dual AI Engine (Isolation Forest ML + Heuristics).",
                "color": color,
                "fields": [
                    {"name": "🎯 Target IP", "value": f"`{ip}`", "inline": True},
                    {"name": "🌍 Geolocation", "value": f"{flag} {country} ({geo.get('city', 'Unknown')})", "inline": True},
                    {"name": "📊 Risk Score", "value": f"**{risk} / 100**", "inline": True},
                    {"name": "🤖 ML Anomaly Model", "value": f"{incident_data.get('ml_verdict', 'ANOMALY')} ({incident_data.get('ml_confidence', 85)}%)", "inline": True},
                    {"name": "📡 ISP / Network", "value": f"{geo.get('isp', 'Unknown ISP')}", "inline": True},
                    {"name": "🛡️ Quarantine Status", "value": "QUARANTINED" if incident_data.get("is_blocked") else "ACTIVE", "inline": True},
                    {"name": "⚠ Attack Signatures", "value": "\n".join([f"• {r}" for r in reasons[:3]]) or "None", "inline": False},
                    {"name": "🛠 Containment Command", "value": f"`iptables -A INPUT -s {ip} -j DROP`", "inline": False}
                ],
                "footer": {"text": "SentinelX Cyber Security Operations Center • Automated Telemetry Alert"},
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }

    delivery_status = "SUCCESS"
    delivery_note = "Webhook dispatched successfully"

    if url and (url.startswith("http://") or url.startswith("https://")):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(discord_payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "SentinelX-SOC-Webhook/2.0"}
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                pass
        except Exception as e:
            delivery_status = "FAILED"
            delivery_note = f"HTTP Dispatch Error: {str(e)}"
    else:
        delivery_status = "SIMULATED"
        delivery_note = "No external webhook URL configured; simulated in internal SOC alert queue."

    # Record history
    history_entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "ip": ip,
        "level": level,
        "risk": risk,
        "delivery_status": delivery_status,
        "delivery_note": delivery_note
    }

    config["alerts_sent"] = config.get("alerts_sent", 0) + 1
    config["history"] = [history_entry] + config.get("history", [])[:15]
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception:
        pass

    return (delivery_status == "SUCCESS" or delivery_status == "SIMULATED", delivery_note)


def test_webhook_url(url):
    """Sends an immediate verification ping to confirm external webhook connectivity."""
    clean_url = str(url).strip()
    if not clean_url or not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        return False, "Invalid Webhook URL format. Must start with http:// or https://"

    test_payload = {
        "username": "SentinelX SOC Sentinel",
        "content": "✅ **SentinelX Webhook Verification**: SIEM notification pipeline is operational and connected!"
    }
    try:
        req = urllib.request.Request(
            clean_url,
            data=json.dumps(test_payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SentinelX-SOC-Webhook/2.0"}
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            return True, f"Webhook test ping delivered successfully (HTTP {resp.status})!"
    except Exception as e:
        return False, f"Failed to deliver test ping: {str(e)}"
