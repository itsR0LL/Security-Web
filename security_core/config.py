from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SECURITY_DATA_DIR", PROJECT_ROOT / "security_data"))
DB_PATH = Path(os.environ.get("SECURITY_DB_PATH", DATA_DIR / "security_studio.sqlite3"))

DEFAULT_MONITORED_HOST = os.environ.get("SECURITY_MONITORED_HOST", "r0l1dehome.asia")
DEFAULT_REFRESH_INTERVAL_HOURS = 6
DEFAULT_HIGH_RISK_THRESHOLD = "high"
DEFAULT_RAW_RETENTION_DAYS = 90
AGGREGATE_RETENTION_LABEL = "长期保留"

RISK_ORDER = ["info", "low", "medium", "high", "critical"]

CHENGDU_DESTINATION = {
    "city": "成都",
    "latitude": 30.5728,
    "longitude": 104.0668,
}

DEFAULT_ALLOWED_ORIGINS = (
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3001",
    "http://localhost:3001",
)

WORKER_LOG_EXPORT_URL = os.environ.get("SECURITY_WORKER_LOG_EXPORT_URL", "").strip()
WORKER_LOG_EXPORT_TOKEN = os.environ.get("SECURITY_WORKER_LOG_EXPORT_TOKEN", "").strip()
