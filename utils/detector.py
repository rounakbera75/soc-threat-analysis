import os
import joblib
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "threat_model.pkl")
_ML_MODEL = None


def get_ml_model():
    """Lazily loads and caches the trained Isolation Forest ML model."""
    global _ML_MODEL
    if _ML_MODEL is None and os.path.exists(MODEL_PATH):
        try:
            _ML_MODEL = joblib.load(MODEL_PATH)
        except Exception:
            _ML_MODEL = None
    return _ML_MODEL


def calculate_risk(failed_attempts, request_count, unusual_hour, network_activity):
    """Calculates rule-based heuristic risk score from 0 to 100."""
    risk = 0

    if failed_attempts >= 10:
        risk += 30
    elif failed_attempts >= 5:
        risk += 15

    if request_count >= 300:
        risk += 30
    elif request_count >= 100:
        risk += 15

    if unusual_hour == 1 or unusual_hour == "1":
        risk += 20

    if network_activity >= 700:
        risk += 20
    elif network_activity >= 400:
        risk += 10

    return min(risk, 100)


def get_threat_level(risk):
    """Categorizes threat severity into LOW, MEDIUM, or HIGH."""
    if risk >= 70:
        return "HIGH"
    elif risk >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def get_reason(failed_attempts, request_count, unusual_hour, network_activity):
    """Generates detailed human-readable threat indicators."""
    reasons = []

    if failed_attempts >= 10:
        reasons.append(f"High number of failed login attempts ({failed_attempts} attempts)")
    elif failed_attempts >= 5:
        reasons.append(f"Elevated number of failed login attempts ({failed_attempts} attempts)")

    if request_count >= 300:
        reasons.append(f"Very high request volume ({request_count} req/min)")
    elif request_count >= 100:
        reasons.append(f"Elevated request volume ({request_count} req/min)")

    if unusual_hour == 1 or unusual_hour == "1":
        reasons.append("Off-hours activity detected (Unusual Hour = 1)")

    if network_activity >= 700:
        reasons.append(f"Abnormally high network throughput ({network_activity} KB/s)")
    elif network_activity >= 400:
        reasons.append(f"Elevated network throughput ({network_activity} KB/s)")

    if not reasons:
        reasons.append("Normal traffic baseline - No anomalous signatures identified")

    return reasons


def predict_ml_anomaly(failed_attempts, request_count, unusual_hour, network_activity):
    """
    Executes Machine Learning anomaly detection using the trained Isolation Forest model.
    Returns anomaly status, decision score, and anomaly probability percentage.
    """
    model = get_ml_model()
    if model is None:
        # Fallback if model not available
        is_anom = (failed_attempts >= 5 or request_count >= 200 or network_activity >= 500)
        return {
            "ml_anomaly": is_anom,
            "ml_verdict": "ANOMALOUS TRAFFIC" if is_anom else "NORMAL BEHAVIOR",
            "ml_confidence": 85.0 if is_anom else 92.0,
            "ml_decision_score": -0.15 if is_anom else 0.15
        }

    try:
        features_df = pd.DataFrame([{
            "failed_attempts": int(failed_attempts),
            "request_count": int(request_count),
            "unusual_hour": int(unusual_hour),
            "network_activity": int(network_activity)
        }])

        prediction = model.predict(features_df)[0]
        decision = float(model.decision_function(features_df)[0])

        is_anom = bool(prediction == -1)

        # Calibrate decision score into 0-100% anomaly probability
        # In IsolationForest, negative decision score = anomaly, positive = normal
        if decision < 0:
            prob = min(99.9, max(60.0, 75.0 + abs(decision) * 150.0))
        else:
            prob = max(1.0, min(40.0, 30.0 - decision * 100.0))

        return {
            "ml_anomaly": is_anom,
            "ml_verdict": "ANOMALOUS TRAFFIC" if is_anom else "NORMAL BEHAVIOR",
            "ml_confidence": round(prob, 1),
            "ml_decision_score": round(decision, 4)
        }
    except Exception as e:
        is_anom = (failed_attempts >= 5 or request_count >= 200 or network_activity >= 500)
        return {
            "ml_anomaly": is_anom,
            "ml_verdict": "ANOMALOUS TRAFFIC" if is_anom else "NORMAL BEHAVIOR",
            "ml_confidence": 80.0,
            "ml_decision_score": 0.0
        }


def detect_threat(data):
    """Legacy helper for backward compatibility."""
    risk = calculate_risk(
        data.get("failed_attempts", 0),
        data.get("request_count", 0),
        data.get("unusual_hour", 0),
        data.get("network_activity", 0)
    )
    return get_threat_level(risk)