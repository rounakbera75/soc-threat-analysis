"""
SentinelX AI Model Training Launcher
Delegates to train_models.py to train both Isolation Forest and Random Forest models
and generate benchmark evaluation metrics.
"""
import subprocess
import sys
import os

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_script = os.path.join(script_dir, "train_models.py")
    result = subprocess.run([sys.executable, target_script], check=True)
    sys.exit(result.returncode)