"""Proxy settings, read from environment variables."""

import os

# Where the real (SQLi-vulnerable) application is listening.
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:5000").rstrip("/")

# Where the proxy itself listens.
PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))

# "block"   -> requests with findings get a 403 and never reach the backend
# "monitor" -> findings are only logged, the request is forwarded anyway
BLOCK_MODE = os.environ.get("BLOCK_MODE", "block").lower()

# Seconds to wait for the backend before giving up with a 502.
BACKEND_TIMEOUT = float(os.environ.get("BACKEND_TIMEOUT", "10"))

# ---- Reputation / throttling -------------------------------------------------
# How much a single request adds to the client's suspicion score, by verdict.
SUSPICIOUS_SCORE = float(os.environ.get("SUSPICIOUS_SCORE", "3"))
MALICIOUS_SCORE = float(os.environ.get("MALICIOUS_SCORE", "10"))

# Score half-life: a quiet IP's score halves every this many seconds, so it
# recovers on its own.
SCORE_HALF_LIFE = float(os.environ.get("SCORE_HALF_LIFE", "120"))

# Tiered thresholds. Above THROTTLE_THRESHOLD requests are tarpitted (delayed);
# above BAN_THRESHOLD they are rejected with 429 + Retry-After.
THROTTLE_THRESHOLD = float(os.environ.get("THROTTLE_THRESHOLD", "10"))
BAN_THRESHOLD = float(os.environ.get("BAN_THRESHOLD", "25"))

# Cap on the tarpit delay (seconds) and the Retry-After sent when banned.
MAX_THROTTLE_DELAY = float(os.environ.get("MAX_THROTTLE_DELAY", "5"))
BAN_COOLDOWN = float(os.environ.get("BAN_COOLDOWN", "30"))
