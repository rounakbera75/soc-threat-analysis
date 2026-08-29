import os
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

# Create larger synthetic training dataset for multi-class cyber threat classification
data_rows = [
    # Normal Baseline (Label: 0)
    [0, 10, 0, 20, 0], [1, 15, 0, 25, 0], [0, 12, 0, 18, 0], [1, 20, 0, 30, 0],
    [0, 8, 0, 15, 0], [2, 18, 0, 28, 0], [0, 25, 0, 35, 0], [1, 14, 0, 22, 0],
    [0, 30, 0, 40, 0], [1, 16, 0, 26, 0], [0, 5, 0, 10, 0], [2, 22, 0, 32, 0],
    # Brute Force SSH/RDP (Label: 1)
    [15, 60, 0, 80, 1], [25, 75, 0, 95, 1], [30, 50, 0, 70, 1], [20, 85, 0, 90, 1],
    [18, 65, 0, 85, 1], [35, 90, 0, 100, 1], [28, 70, 0, 88, 1], [22, 80, 0, 92, 1],
    # Layer 7 DDoS Flood (Label: 2)
    [1, 1200, 0, 2500, 2], [2, 1500, 0, 3000, 2], [0, 1800, 0, 3500, 2], [3, 1400, 0, 2800, 2],
    [1, 2000, 0, 4000, 2], [2, 1600, 0, 3200, 2], [0, 2200, 0, 4500, 2], [1, 1300, 0, 2700, 2],
    # Off-Hours Data Exfiltration (Label: 3)
    [12, 350, 1, 1800, 3], [15, 420, 1, 2100, 3], [10, 380, 1, 1950, 3], [14, 450, 1, 2300, 3],
    [8, 320, 1, 1600, 3], [16, 500, 1, 2500, 3], [11, 400, 1, 2000, 3], [13, 360, 1, 1850, 3],
    # Port Reconnaissance Scan (Label: 4)
    [5, 250, 0, 350, 4], [6, 280, 0, 380, 4], [4, 300, 0, 400, 4], [7, 260, 0, 360, 4],
    [5, 320, 0, 420, 4], [6, 240, 0, 340, 4], [8, 310, 0, 410, 4], [4, 270, 0, 370, 4]
]

columns = ["failed_attempts", "request_count", "unusual_hour", "network_activity", "threat_class"]
df = pd.DataFrame(data_rows, columns=columns)

features = ["failed_attempts", "request_count", "unusual_hour", "network_activity"]
X = df[features]
y = df["threat_class"]

os.makedirs("model", exist_ok=True)

# 1. Train Unsupervised Isolation Forest Anomaly Detector
iso_forest = IsolationForest(n_estimators=120, contamination=0.25, random_state=42)
iso_forest.fit(X)
joblib.dump(iso_forest, "model/threat_model.pkl")

# 2. Train Supervised Random Forest Threat Vector Classifier
rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
rf_classifier.fit(X, y)
joblib.dump(rf_classifier, "model/rf_classifier.pkl")

# 3. Compute Evaluation Metrics
y_pred = rf_classifier.predict(X)
acc = float(accuracy_score(y, y_pred))
prec = float(precision_score(y, y_pred, average="weighted"))
rec = float(recall_score(y, y_pred, average="weighted"))
f1 = float(f1_score(y, y_pred, average="weighted"))
cm = confusion_matrix(y, y_pred).tolist()
feat_imp = rf_classifier.feature_importances_.tolist()

metrics_payload = {
    "model_name": "SentinelX Dual AI Threat Ensemble",
    "trained_at": "2026-08-29",
    "algorithm_1": "Isolation Forest (Unsupervised Anomaly Scoring)",
    "algorithm_2": "Random Forest Classifier (Multi-Class Threat Categorization)",
    "accuracy": round(acc * 100, 1),
    "precision": round(prec * 100, 1),
    "recall": round(rec * 100, 1),
    "f1_score": round(f1 * 100, 1),
    "confusion_matrix": cm,
    "classes": ["Normal Activity", "SSH/RDP Brute Force", "Layer 7 DDoS Flood", "Off-Hours Exfiltration", "Port Recon Scan"],
    "feature_names": features,
    "feature_importances": [round(val * 100, 1) for val in feat_imp]
}

with open("model/ai_benchmark_metrics.json", "w", encoding="utf-8") as f:
    json.dump(metrics_payload, f, indent=2)

print("====================================================")
print("SentinelX Capstone AI Ensemble Trained Successfully!")
print(f"Accuracy: {acc*100}% | Precision: {prec*100}% | F1: {f1*100}%")
print("Saved models: model/threat_model.pkl & model/rf_classifier.pkl")
print("====================================================")
