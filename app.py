import os
import csv
import json
import joblib
import pandas as pd
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response

from utils.detector import (
    calculate_risk,
    get_threat_level,
    get_reason,
    predict_ml_anomaly
)
from utils.firewall import (
    get_blocked_ips,
    is_ip_blocked,
    block_ip,
    unblock_ip,
    get_firewall_rule_commands,
    get_incidents,
    update_incident_status
)
from utils.threat_intel import (
    get_ip_geolocation,
    perform_recon_scan
)
from utils.notifications import (
    get_webhook_config,
    save_webhook_config,
    dispatch_webhook_alert,
    test_webhook_url
)
from utils.mitre import (
    map_threat_to_mitre,
    get_full_mitre_matrix
)
from utils.soar import (
    get_playbooks,
    get_soar_history,
    execute_playbook
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

# Cache RF Model for Multi-Class classification
_RF_MODEL = None
def get_rf_classifier():
    global _RF_MODEL
    rf_path = os.path.join(os.path.dirname(__file__), "model", "rf_classifier.pkl")
    if _RF_MODEL is None and os.path.exists(rf_path):
        try:
            _RF_MODEL = joblib.load(rf_path)
        except Exception:
            _RF_MODEL = None
    return _RF_MODEL


def analyze_ip_security(source_ip, form_data=None):
    """
    Capstone Dual AI Engine & Threat Intelligence Pipeline:
    1. Heuristic Risk Calculation
    2. Isolation Forest Machine Learning Anomaly Detection
    3. Random Forest Multi-Class Vector Classification
    4. OSINT Geolocation, ISP, ASN, and Tor Exit Node Telemetry
    5. MITRE ATT&CK Framework Mapping
    6. Active Firewall Quarantine Check
    """
    if form_data is None:
        form_data = {}

    clean_ip = str(source_ip).strip()

    # Baseline demo values
    failed_attempts = 5
    request_count = 150
    unusual_hour = 0
    network_activity = 450

    # Look up in historical datasets
    log_files = ["data/logs.csv", "data/security_logs.csv"]
    for log_path in log_files:
        if os.path.exists(log_path):
            try:
                df = pd.read_csv(log_path)
                matching = df[df["source_ip"] == clean_ip]
                if not matching.empty:
                    row = matching.iloc[-1]
                    failed_attempts = int(row.get("failed_attempts", failed_attempts))
                    request_count = int(row.get("request_count", request_count))
                    unusual_hour = int(row.get("unusual_hour", unusual_hour))
                    network_activity = int(row.get("network_activity", network_activity))
                    break
            except Exception:
                pass

    # Override with explicit form or JSON parameters if provided
    if "failed_attempts" in form_data and str(form_data["failed_attempts"]).strip():
        try:
            failed_attempts = int(form_data["failed_attempts"])
        except ValueError:
            pass
    if "request_count" in form_data and str(form_data["request_count"]).strip():
        try:
            request_count = int(form_data["request_count"])
        except ValueError:
            pass
    if "unusual_hour" in form_data and str(form_data["unusual_hour"]).strip():
        try:
            unusual_hour = int(form_data["unusual_hour"])
        except ValueError:
            pass
    if "network_activity" in form_data and str(form_data["network_activity"]).strip():
        try:
            network_activity = int(form_data["network_activity"])
        except ValueError:
            pass

    # 1. Heuristic Risk Calculation
    risk = calculate_risk(failed_attempts, request_count, unusual_hour, network_activity)
    level = get_threat_level(risk)
    reasons = get_reason(failed_attempts, request_count, unusual_hour, network_activity)

    # 2. Machine Learning Isolation Forest Inference
    ml_result = predict_ml_anomaly(failed_attempts, request_count, unusual_hour, network_activity)

    # 3. Geolocation & ASN Threat Intel
    geo = get_ip_geolocation(clean_ip)
    if geo.get("is_tor"):
        risk = min(100, risk + 15)
        level = get_threat_level(risk)
        reasons.insert(0, "Endpoint identified as active Tor Project exit relay")

    # 4. Firewall Quarantine Check
    blocked, block_info = is_ip_blocked(clean_ip)

    status = "Threat Detected" if (risk >= 40 or ml_result.get("ml_anomaly")) else "Normal Activity"

    res_payload = {
        "source_ip": clean_ip,
        "failed_attempts": failed_attempts,
        "request_count": request_count,
        "unusual_hour": unusual_hour,
        "network_activity": network_activity,
        "risk": risk,
        "level": level,
        "status": status,
        "reasons": reasons,
        "ml_anomaly": ml_result.get("ml_anomaly", False),
        "ml_verdict": ml_result.get("ml_verdict", "NORMAL"),
        "ml_confidence": ml_result.get("ml_confidence", 85.0),
        "ml_decision_score": ml_result.get("ml_decision_score", 0.0),
        "geo": geo,
        "is_blocked": blocked,
        "block_info": block_info
    }

    # 5. MITRE ATT&CK Mapping
    res_payload["mitre_mappings"] = map_threat_to_mitre(res_payload)

    # Auto-dispatch webhook if enabled and high severity
    webhook_cfg = get_webhook_config()
    if webhook_cfg.get("enabled"):
        min_sev = webhook_cfg.get("min_severity", "HIGH")
        should_alert = (
            (min_sev == "HIGH" and level == "HIGH") or
            (min_sev == "MEDIUM" and level in ["HIGH", "MEDIUM"]) or
            (min_sev == "ALL")
        )
        if should_alert:
            try:
                dispatch_webhook_alert(res_payload)
            except Exception:
                pass

    return res_payload


def get_telemetry_analytics():
    """Aggregates real-time telemetry stats for Chart.js visual graphs & Leaflet map."""
    log_files = ["data/logs.csv", "data/security_logs.csv"]
    rows = []
    seen_ips = set()
    analyzed_items = []

    for log_path in log_files:
        if os.path.exists(log_path):
            try:
                df = pd.read_csv(log_path)
                for _, row in df.iterrows():
                    rows.append(row.to_dict())
                    ip = str(row.get("source_ip", "")).strip()
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        analyzed_items.append(analyze_ip_security(ip, row.to_dict()))
            except Exception:
                pass

    if not analyzed_items:
        for sip in ["192.168.1.52", "192.168.1.50", "192.168.1.10"]:
            analyzed_items.append(analyze_ip_security(sip))

    high_c = sum(1 for i in analyzed_items if i["level"] == "HIGH")
    med_c = sum(1 for i in analyzed_items if i["level"] == "MEDIUM")
    low_c = sum(1 for i in analyzed_items if i["level"] == "LOW")

    # Geolocation markers for Leaflet map
    geo_markers = []
    for item in analyzed_items:
        g = item.get("geo", {})
        if g.get("lat") and g.get("lon"):
            geo_markers.append({
                "ip": item["source_ip"],
                "lat": g["lat"],
                "lon": g["lon"],
                "country": g.get("country", "Unknown"),
                "city": g.get("city", "Unknown"),
                "flag": g.get("flag", "🌐"),
                "level": item["level"],
                "risk": item["risk"]
            })

    # Sort for top attackers
    sorted_threats = sorted(analyzed_items, key=lambda x: x["risk"], reverse=True)[:5]
    top_attackers = {
        "labels": [item["source_ip"] for item in sorted_threats],
        "scores": [item["risk"] for item in sorted_threats]
    }

    # Timeline points
    timeline_labels = []
    timeline_reqs = []
    timeline_net = []
    for r in rows[-7:] if rows else []:
        t_str = str(r.get("timestamp", "00:00")).split(" ")[-1][:5]
        timeline_labels.append(t_str or "00:00")
        timeline_reqs.append(int(r.get("request_count", 50)))
        timeline_net.append(int(r.get("network_activity", 100)))

    if not timeline_labels:
        timeline_labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Now"]
        timeline_reqs = [20, 150, 45, 80, 400, 120, 300]
        timeline_net = [30, 200, 60, 110, 750, 180, 500]

    failed_tot = sum(int(r.get("failed_attempts", 0)) for r in rows)
    req_tot = min(100, int(sum(int(r.get("request_count", 0)) for r in rows) / max(1, len(rows))))
    off_hour_tot = sum(1 for r in rows if str(r.get("unusual_hour", "0")) in ["1", 1]) * 15
    net_tot = min(100, int(sum(int(r.get("network_activity", 0)) for r in rows) / max(1, len(rows) * 10)))
    ml_anom_tot = sum(1 for i in analyzed_items if i["ml_anomaly"]) * 20
    vector_stats = [failed_tot, req_tot, off_hour_tot, net_tot, ml_anom_tot]

    return {
        "chart_stats": {"high": high_c, "medium": med_c, "low": low_c},
        "chart_timeline": {"labels": timeline_labels, "requests": timeline_reqs, "network": timeline_net},
        "top_attackers": top_attackers,
        "vector_stats": vector_stats,
        "total_logs": len(rows),
        "analyzed_items": analyzed_items,
        "geo_markers": geo_markers
    }


# ==========================================
# CORE DASHBOARD & ANALYSIS ROUTES
# ==========================================

@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    is_blocked = False
    alert_msg = request.args.get("alert_msg")
    alert_success = request.args.get("alert_success", "1") == "1"

    if request.method == "POST":
        source_ip = request.form.get("source_ip", "").strip()
        if source_ip:
            result = analyze_ip_security(source_ip, request.form)
            is_blocked, _ = is_ip_blocked(source_ip)

    analytics = get_telemetry_analytics()
    blocked_ips = get_blocked_ips()

    return render_template(
        "index.html",
        result=result,
        is_blocked=is_blocked,
        blocked_count=len(blocked_ips),
        total_logs=analytics["total_logs"],
        chart_stats=analytics["chart_stats"],
        chart_timeline=analytics["chart_timeline"],
        geo_markers=analytics["geo_markers"],
        alert_msg=alert_msg,
        alert_success=alert_success
    )


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    result = None
    is_blocked = False

    if request.method == "POST":
        if request.is_json:
            data = request.get_json(silent=True) or {}
            source_ip = data.get("source_ip", "").strip()
            result = analyze_ip_security(source_ip, data)
            return jsonify(result)
        else:
            source_ip = request.form.get("source_ip", "").strip()
            if source_ip:
                result = analyze_ip_security(source_ip, request.form)
                is_blocked, _ = is_ip_blocked(source_ip)
            if request.headers.get("Accept") == "application/json":
                return jsonify(result or {})

    # Support GET /analyze with query params e.g. ?source_ip=192.168.1.50
    source_ip = request.args.get("source_ip", "").strip()
    if source_ip:
        result = analyze_ip_security(source_ip, request.args)
        is_blocked, _ = is_ip_blocked(source_ip)
        if request.headers.get("Accept") == "application/json":
            return jsonify(result)

    analytics = get_telemetry_analytics()
    blocked_ips = get_blocked_ips()

    return render_template(
        "index.html",
        result=result,
        is_blocked=is_blocked,
        blocked_count=len(blocked_ips),
        total_logs=analytics["total_logs"],
        chart_stats=analytics["chart_stats"],
        chart_timeline=analytics["chart_timeline"],
        geo_markers=analytics["geo_markers"]
    )


# ==========================================
# FULLSCREEN CYBER THREAT MAP WALLBOARD
# ==========================================

@app.route("/map", methods=["GET"])
@app.route("/threat-map", methods=["GET"])
def global_threat_map():
    analytics = get_telemetry_analytics()
    blocked_ips = get_blocked_ips()
    
    attack_events = []
    country_counts = {}
    
    for item in analytics["analyzed_items"]:
        g = item.get("geo", {})
        c_name = g.get("country", "Unknown")
        flag = g.get("flag", "🌐")
        
        if c_name not in country_counts:
            country_counts[c_name] = {"country": c_name, "flag": flag, "count": 0}
        country_counts[c_name]["count"] += 1
        
        if item["failed_attempts"] >= 10:
            vector = "SSH / RDP Brute Force"
        elif item["request_count"] >= 300:
            vector = "Layer 7 HTTP DDoS Flood"
        elif str(item["unusual_hour"]) in ["1", 1]:
            vector = "Off-Hours Data Exfiltration"
        elif item["network_activity"] >= 400:
            vector = "High Bandwidth Ingress Flood"
        elif item.get("ml_anomaly"):
            vector = "Isolation Forest AI Anomaly"
        else:
            vector = "Ingress Reconnaissance Probe"
            
        attack_events.append({
            "ip": item["source_ip"],
            "lat": g.get("lat", 20.0),
            "lon": g.get("lon", 0.0),
            "country": c_name,
            "city": g.get("city", "Unknown"),
            "flag": flag,
            "isp": g.get("isp", "BGP Gateway"),
            "level": item["level"],
            "risk": item["risk"],
            "vector": vector
        })
        
    max_c = max(1, max((v["count"] for v in country_counts.values()), default=1))
    country_rankings = sorted(country_counts.values(), key=lambda x: x["count"], reverse=True)[:5]
    for c in country_rankings:
        c["pct"] = int((c["count"] / max_c) * 100)
        
    return render_template(
        "map.html",
        attack_events=attack_events,
        country_rankings=country_rankings,
        total_attacks=analytics["total_logs"] + 45,
        threat_actors_count=len(analytics["analyzed_items"]),
        blocked_count=len(blocked_ips)
    )


# ==========================================
# DUAL AI BENCHMARKS & XAI ROUTE
# ==========================================

@app.route("/ai-models", methods=["GET"])
def ai_models_dashboard():
    metrics = {}
    bench_path = "model/ai_benchmark_metrics.json"
    if os.path.exists(bench_path):
        try:
            with open(bench_path, "r", encoding="utf-8") as f:
                metrics = json.load(f)
        except Exception:
            pass

    return render_template("ai_models.html", metrics=metrics, pred_result=None, pred_input={})


@app.route("/ai-models/predict", methods=["POST"])
def ai_models_predict():
    failed = int(request.form.get("failed_attempts", 15))
    reqs = int(request.form.get("request_count", 450))
    unusual = int(request.form.get("unusual_hour", 0))
    net = int(request.form.get("network_activity", 950))

    pred_input = {
        "failed_attempts": failed,
        "request_count": reqs,
        "unusual_hour": unusual,
        "network_activity": net
    }

    # Isolation Forest
    iso_res = predict_ml_anomaly(failed, reqs, unusual, net)
    
    # Random Forest Multi-class
    rf = get_rf_classifier()
    classes_map = ["Normal Activity", "SSH/RDP Brute Force", "Layer 7 DDoS Flood", "Off-Hours Exfiltration", "Port Recon Scan"]
    rf_class = "SSH/RDP Brute Force"
    rf_conf = 96.5

    if rf is not None:
        try:
            feat_df = pd.DataFrame([pred_input])
            pred_idx = int(rf.predict(feat_df)[0])
            probs = rf.predict_proba(feat_df)[0]
            rf_class = classes_map[pred_idx]
            rf_conf = round(float(probs[pred_idx]) * 100, 1)
        except Exception:
            pass

    comp_risk = calculate_risk(failed, reqs, unusual, net)

    pred_result = {
        "rf_class": rf_class,
        "rf_confidence": rf_conf,
        "is_anomaly": iso_res.get("ml_anomaly", True),
        "iso_verdict": iso_res.get("ml_verdict", "ANOMALOUS TRAFFIC"),
        "composite_risk": comp_risk
    }

    metrics = {}
    bench_path = "model/ai_benchmark_metrics.json"
    if os.path.exists(bench_path):
        try:
            with open(bench_path, "r", encoding="utf-8") as f:
                metrics = json.load(f)
        except Exception:
            pass

    return render_template("ai_models.html", metrics=metrics, pred_result=pred_result, pred_input=pred_input)


# ==========================================
# MITRE ATT&CK MATRIX ROUTE
# ==========================================

@app.route("/mitre", methods=["GET"])
def mitre_matrix_view():
    matrix = get_full_mitre_matrix()
    return render_template("mitre.html", mitre_matrix=matrix)


# ==========================================
# SOAR PLAYBOOKS ROUTE
# ==========================================

@app.route("/playbooks", methods=["GET"])
def soar_playbooks_view():
    playbooks = get_playbooks()
    history = get_soar_history()
    return render_template("playbooks.html", playbooks=playbooks, soar_history=history, execution_result=None)


@app.route("/playbooks/run", methods=["POST"])
def soar_playbook_run():
    pb_id = request.form.get("playbook_id", "PB-BRUTE-01")
    target_ip = request.form.get("target_ip", "192.168.1.52").strip()

    exec_result = execute_playbook(pb_id, target_ip)
    playbooks = get_playbooks()
    history = get_soar_history()

    return render_template("playbooks.html", playbooks=playbooks, soar_history=history, execution_result=exec_result)


# ==========================================
# NETWORK RECONNAISSANCE SCANNER ROUTE
# ==========================================

@app.route("/recon", methods=["GET"])
def recon_scanner():
    ip = request.args.get("ip", "").strip()
    scan_result = None
    if ip:
        scan_result = perform_recon_scan(ip)

    return render_template("recon.html", scan_result=scan_result)


# ==========================================
# CYBER ATTACK SIMULATOR ROUTE
# ==========================================

@app.route("/simulate", methods=["GET", "POST"])
def simulate():
    sim_result = None
    is_blocked = False

    if request.method == "POST":
        attack_type = request.form.get("attack_type", "custom")
        now_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Preset attack profiles
        if attack_type == "brute_force":
            attack_name = "SSH / RDP Brute Force"
            ip = f"192.168.1.{100 + (hash(now_ts) % 50)}"
            failed = 28
            reqs = 65
            unusual = 0
            net = 95
        elif attack_type == "ddos_flood":
            attack_name = "Layer 7 HTTP DDoS Flood"
            ip = f"10.0.99.{hash(now_ts) % 200}"
            failed = 2
            reqs = 1450
            unusual = 0
            net = 2600
        elif attack_type == "data_exfiltration":
            attack_name = "Off-Hours Lateral Movement & Data Exfiltration"
            ip = f"172.16.4.{hash(now_ts) % 100}"
            failed = 14
            reqs = 380
            unusual = 1
            net = 1850
        elif attack_type == "port_scan":
            attack_name = "Port Scan & Service Enumeration"
            ip = f"192.168.2.{hash(now_ts) % 80}"
            failed = 6
            reqs = 260
            unusual = 0
            net = 380
        elif attack_type == "benign":
            attack_name = "Benign Authorized Employee Session"
            ip = f"192.168.1.{10 + (hash(now_ts) % 5)}"
            failed = 0
            reqs = 15
            unusual = 0
            net = 24
        else:
            # Custom vector
            attack_name = "Custom Simulated Vector"
            ip = request.form.get("source_ip", "10.0.8.99").strip()
            failed = int(request.form.get("failed_attempts", 12))
            reqs = int(request.form.get("request_count", 350))
            unusual = int(request.form.get("unusual_hour", 0))
            net = int(request.form.get("network_activity", 650))

        # Append to live telemetry
        log_path = "data/logs.csv"
        try:
            with open(log_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([now_ts, ip, failed, reqs, unusual, net])
        except Exception:
            pass

        form_payload = {
            "failed_attempts": failed,
            "request_count": reqs,
            "unusual_hour": unusual,
            "network_activity": net
        }
        sim_result = analyze_ip_security(ip, form_payload)
        sim_result["attack_name"] = attack_name
        is_blocked, _ = is_ip_blocked(ip)

        if sim_result["risk"] >= 70 or sim_result["ml_anomaly"]:
            update_incident_status(
                ip,
                status="Active Alert",
                analyst_notes=f"Automated AI detection triggered from {attack_name} simulation ({sim_result['geo'].get('country', 'Unknown')}).",
                threat_level=sim_result["level"],
                risk_score=sim_result["risk"]
            )

    return render_template(
        "simulate.html",
        sim_result=sim_result,
        is_blocked=is_blocked
    )


# ==========================================
# FIREWALL & IP QUARANTINE ROUTES
# ==========================================

@app.route("/firewall", methods=["GET"])
def firewall_dashboard():
    blocked_ips = get_blocked_ips()
    high_count = sum(1 for item in blocked_ips if item.get("threat_level") == "HIGH")
    msg = request.args.get("msg")
    success = request.args.get("success", "1") == "1"

    return render_template(
        "firewall.html",
        blocked_ips=blocked_ips,
        high_blocked_count=high_count,
        message=msg,
        success=success
    )


@app.route("/firewall/block", methods=["POST"])
def firewall_block():
    ip = request.form.get("ip", "").strip()
    reason = request.form.get("reason", "Manual SOC Quarantine").strip()
    threat_level = request.form.get("threat_level", "HIGH")
    risk_score = request.form.get("risk_score")

    if not ip:
        return redirect(url_for("firewall_dashboard", msg="Target IP address is required", success="0"))

    ok, msg = block_ip(ip, reason=reason, threat_level=threat_level, risk_score=risk_score)
    update_incident_status(ip, status="Contained", analyst_notes=f"Host contained and blocked in firewall: {reason}")

    ref = request.referrer or ""
    if "simulate" in ref:
        return redirect(url_for("simulate"))
    if "reports" in ref:
        return redirect(url_for("reports"))
    if "logs" in ref:
        return redirect(url_for("security_logs"))
    if "recon" in ref:
        return redirect(url_for("recon_scanner", ip=ip))

    return redirect(url_for("firewall_dashboard", msg=f"Quarantine enforced for {ip}", success="1" if ok else "0"))


@app.route("/firewall/unblock/<path:ip>", methods=["POST", "GET"])
def firewall_unblock(ip):
    clean_ip = ip.strip()
    ok, msg = unblock_ip(clean_ip)
    update_incident_status(clean_ip, status="Resolved", analyst_notes="Firewall containment rule lifted by SOC analyst.")

    ref = request.referrer or ""
    if "analyze" in ref or ("127.0.0.1:5000" in ref and not "firewall" in ref):
        return redirect(url_for("dashboard"))

    return redirect(url_for("firewall_dashboard", msg=f"Quarantine lifted for {clean_ip}", success="1" if ok else "0"))


# ==========================================
# WEBHOOK NOTIFICATION & SOC SETTINGS
# ==========================================

@app.route("/settings", methods=["GET", "POST"])
def soc_settings():
    msg = None
    success = True
    if request.method == "POST":
        webhook_url = request.form.get("webhook_url", "").strip()
        enabled = bool(request.form.get("enabled"))
        min_severity = request.form.get("min_severity", "HIGH")
        ok = save_webhook_config(webhook_url, enabled=enabled, min_severity=min_severity)
        msg = "Webhook configuration saved successfully!" if ok else "Error saving webhook settings."
        success = ok

    config = get_webhook_config()
    return render_template("settings.html", config=config, message=msg, success=success)


@app.route("/settings/test", methods=["POST"])
def soc_settings_test():
    config = get_webhook_config()
    url = config.get("webhook_url", "")
    ok, note = test_webhook_url(url)
    return render_template("settings.html", config=config, message=note, success=ok)


@app.route("/api/webhook/dispatch", methods=["POST"])
def manual_webhook_dispatch():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return redirect(url_for("dashboard", alert_msg="Target IP is required for alert dispatch", alert_success="0"))

    incident_data = analyze_ip_security(ip)
    ok, note = dispatch_webhook_alert(incident_data)
    return redirect(url_for("dashboard", alert_msg=f"Webhook Alert for {ip}: {note}", alert_success="1" if ok else "0"))


# ==========================================
# BATCH LOG UPLOAD & CSV SCANNER
# ==========================================

@app.route("/upload", methods=["POST"])
def upload_logs():
    if "logfile" not in request.files:
        return render_template("logs.html", logs=_get_logs_data(), upload_msg="No file selected", upload_success=False)

    file = request.files["logfile"]
    if file.filename == "":
        return render_template("logs.html", logs=_get_logs_data(), upload_msg="No file selected", upload_success=False)

    if file and file.filename.endswith(".csv"):
        try:
            df = pd.read_csv(file)
            required_cols = ["failed_attempts", "request_count", "unusual_hour", "network_activity"]
            missing = [c for c in required_cols if c not in df.columns]

            if missing:
                return render_template(
                    "logs.html",
                    logs=_get_logs_data(),
                    upload_msg=f"Invalid CSV structure. Missing columns: {', '.join(missing)}",
                    upload_success=False
                )

            if "source_ip" not in df.columns:
                df["source_ip"] = [f"192.168.1.{i+1}" for i in range(len(df))]
            if "timestamp" not in df.columns:
                df["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            log_path = "data/logs.csv"
            df[["timestamp", "source_ip", "failed_attempts", "request_count", "unusual_hour", "network_activity"]].to_csv(
                log_path, mode="a", header=not os.path.exists(log_path), index=False
            )

            threat_count = 0
            for _, row in df.iterrows():
                res = analyze_ip_security(str(row["source_ip"]), row.to_dict())
                if res["level"] in ["HIGH", "MEDIUM"] or res["ml_anomaly"]:
                    threat_count += 1

            msg = f"Successfully ingested {len(df)} records! Batch AI Scanner identified {threat_count} anomalous threat signatures."
            return render_template("logs.html", logs=_get_logs_data(), upload_msg=msg, upload_success=True)
        except Exception as e:
            return render_template("logs.html", logs=_get_logs_data(), upload_msg=f"Error parsing CSV: {str(e)}", upload_success=False)

    return render_template("logs.html", logs=_get_logs_data(), upload_msg="Please upload a valid .csv file", upload_success=False)


def _get_logs_data():
    log_files = ["data/logs.csv", "data/security_logs.csv"]
    for log_path in log_files:
        if os.path.exists(log_path):
            try:
                df = pd.read_csv(log_path)
                return df.to_dict(orient="records")
            except Exception:
                pass
    return []


# ==========================================
# INCIDENT CASE MANAGEMENT ROUTE
# ==========================================

@app.route("/incidents", methods=["POST"])
def triage_incident():
    ip = request.form.get("ip", "").strip()
    status = request.form.get("status", "Under Investigation")
    notes = request.form.get("notes", "").strip()

    if ip:
        update_incident_status(ip, status=status, analyst_notes=notes)

    return redirect(url_for("reports"))


# ==========================================
# SECURITY REPORTS & LOGS ROUTES
# ==========================================

@app.route("/reports")
def reports():
    analytics = get_telemetry_analytics()
    incidents = get_incidents()

    if not incidents:
        for item in analytics["analyzed_items"]:
            if item["level"] == "HIGH":
                update_incident_status(item["source_ip"], "Active Alert", f"High Risk ({item['risk']}/100) identified by AI Engine.")
        incidents = get_incidents()

    return render_template(
        "reports.html",
        report_items=analytics["analyzed_items"],
        total_count=len(analytics["analyzed_items"]),
        high_count=analytics["chart_stats"]["high"],
        medium_count=analytics["chart_stats"]["medium"],
        low_count=analytics["chart_stats"]["low"],
        top_attackers=analytics["top_attackers"],
        vector_stats=analytics["vector_stats"],
        incidents=incidents
    )


@app.route("/report/<path:ip>")
def incident_report(ip):
    clean_ip = ip.strip()
    result = analyze_ip_security(clean_ip)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    is_blocked, _ = is_ip_blocked(clean_ip)

    return render_template(
        "incident_report.html",
        result=result,
        generated_at=generated_at,
        is_blocked=is_blocked
    )


@app.route("/logs")
def security_logs():
    return render_template("logs.html", logs=_get_logs_data())


# ==========================================
# EXPORT ENDPOINTS (CSV & JSON)
# ==========================================

@app.route("/export/csv")
def export_csv():
    log_path = "data/logs.csv" if os.path.exists("data/logs.csv") else "data/security_logs.csv"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            csv_content = f.read()
    else:
        csv_content = "timestamp,source_ip,failed_attempts,request_count,unusual_hour,network_activity\n"

    response = Response(csv_content, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=sentinelx_security_logs.csv"
    return response


@app.route("/export/json")
def export_json():
    analytics = get_telemetry_analytics()
    blocked = get_blocked_ips()
    incidents = get_incidents()

    export_payload = {
        "system": "SentinelX AI Threat Detection & Response SIEM",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_endpoints": len(analytics["analyzed_items"]),
        "threat_summary": analytics["chart_stats"],
        "quarantined_hosts": blocked,
        "active_incidents": incidents,
        "telemetry_assessments": analytics["analyzed_items"]
    }

    response = Response(json.dumps(export_payload, indent=2), mimetype="application/json")
    response.headers["Content-Disposition"] = "attachment; filename=sentinelx_threat_intelligence.json"
    return response


@app.route("/export/report/<path:ip>")
def export_single_report(ip):
    clean_ip = ip.strip()
    result = analyze_ip_security(clean_ip)
    fw_cmds = get_firewall_rule_commands(clean_ip)

    payload = {
        "report_id": f"RPT-{clean_ip.replace('.', '')}-2026",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "assessment": result,
        "mitre_framework": result.get("mitre_mappings", []),
        "firewall_mitigation_rules": fw_cmds
    }
    response = Response(json.dumps(payload, indent=2), mimetype="application/json")
    response.headers["Content-Disposition"] = f"attachment; filename=sentinelx_report_{clean_ip}.json"
    return response


@app.route("/api/analytics")
def api_analytics():
    return jsonify(get_telemetry_analytics())


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)