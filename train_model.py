import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

# Load security logs
df = pd.read_csv("data/logs.csv")

# Features
features = [
    "failed_attempts",
    "request_count",
    "unusual_hour",
    "network_activity"

]

X = df[features]

# Create AI model
model = IsolationForest(
    n_estimators=100,
    contamination=0.3,
    random_state=42
)

# Train model
model.fit(X)

# Create model folder
os.makedirs("model", exist_ok=True)

# Save model
joblib.dump(model, "model/threat_model.pkl")

print("================================")
print("SentinelX AI Model Trained!")
print("================================")
print("Saved: model/threat_model.pkl")