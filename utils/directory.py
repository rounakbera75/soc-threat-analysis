def calculate_risk(failed_attempts, request_count, unusual_hour, network_activity):
    risk = 0

    if failed_attempts >= 10:
        risk += 30
    elif failed_attempts >= 5:
        risk += 15

    if request_count >= 300:
        risk += 30
    elif request_count >= 100:
        risk += 15

    if unusual_hour == 1:
        risk += 20

    if network_activity >= 700:
        risk += 20
    elif network_activity >= 400:
        risk += 10

    return min(risk, 100)


def get_threat_level(risk):
    if risk >= 70:
        return "HIGH"
    elif risk >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def get_reason(failed_attempts, request_count, unusual_hour, network_activity):
    reasons = []

    if failed_attempts >= 10:
        reasons.append("High number of failed login attempts")

    if request_count >= 300:
        reasons.append("Very high request volume")

    if unusual_hour == 1:
        reasons.append("Activity detected during unusual hours")

    if network_activity >= 700:
        reasons.append("Abnormally high network activity")

    if not reasons:
        reasons.append("No significant suspicious activity detected")

    return reasons


def detect_threat(data):
    risk = calculate_risk(
        data.get("failed_attempts", 0),
        data.get("request_count", 0),
        data.get("unusual_hour", 0),
        data.get("network_activity", 0)
    )

    return get_threat_level(risk)