"""Proxy settings, read from environment variables."""

import os

# Where the real (SQLi-vulnerable) application is listening.
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:5000").rstrip("/")

# Where the proxy itself listens.
PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))

# "block" enforces; "monitor" only logs and forwards everything.
BLOCK_MODE = os.environ.get("BLOCK_MODE", "block").lower()

# Seconds to wait for the backend before a 502.
BACKEND_TIMEOUT = float(os.environ.get("BACKEND_TIMEOUT", "10"))

# ---- Reputation / throttling -------------------------------------------------
# Score added per request, by verdict.
SUSPICIOUS_SCORE = float(os.environ.get("SUSPICIOUS_SCORE", "3"))
MALICIOUS_SCORE = float(os.environ.get("MALICIOUS_SCORE", "10"))

# Seconds for an idle IP's score to halve.
SCORE_HALF_LIFE = float(os.environ.get("SCORE_HALF_LIFE", "120"))

# Above THROTTLE_THRESHOLD: tarpit. Above BAN_THRESHOLD: 429.
THROTTLE_THRESHOLD = float(os.environ.get("THROTTLE_THRESHOLD", "10"))
BAN_THRESHOLD = float(os.environ.get("BAN_THRESHOLD", "25"))

# Tarpit delay cap, and the Retry-After sent when banned (seconds).
MAX_THROTTLE_DELAY = float(os.environ.get("MAX_THROTTLE_DELAY", "5"))
BAN_COOLDOWN = float(os.environ.get("BAN_COOLDOWN", "30"))

# Below this a decayed score counts as zero.
DROP_BELOW = float(os.environ.get("DROP_BELOW", "0.1"))

# Table size: soft-prune trigger, hard-prune trigger, hard-prune target.
SOFT_PRUNE_AT = int(os.environ.get("SOFT_PRUNE_AT", "10000"))
HARD_PRUNE_AT = int(os.environ.get("HARD_PRUNE_AT", "12000"))
HARD_PRUNE_TARGET = int(os.environ.get("HARD_PRUNE_TARGET", "7500"))


# ---- Schema Enforcing --------------------------------------------------------
# Validate known fields of incoming requests against expected shape
SCHEMA_CONSTRAINT = False
