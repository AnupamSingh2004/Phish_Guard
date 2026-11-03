"""Central configuration: paths, seeds and decision thresholds."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"
LOG_DIR = ROOT / "logs"
SAMPLES_DIR = ROOT / "samples"

SEED = 42
N_URLS = 8000          # total synthetic URLs (50/50)
N_EMAILS = 2400        # total synthetic emails (50/50)

# Risk bands (0-100). >= BLOCK_AT is classified "phishing".
WARN_AT = 30
BLOCK_AT = 50

# Hybrid URL score = ML_WEIGHT * ML probability + (1-ML_WEIGHT) * rule score
ML_WEIGHT = 0.70
