"""Per-IP suspicion scores with time decay, and the tiered throttle decision.

Each client IP has a score that goes up when the detector flags its requests
and decays on its own over time (half-life), so an IP that stops probing
recovers. The score maps to a tiered action:

    score <= throttle_at              -> "pass"   (forward normally)
    throttle_at < score <= ban_at     -> "delay"  (tarpit: sleep, growing with score)
    score > ban_at                    -> "ban"    (reject with 429 + Retry-After)
"""

import threading
import time

PASS = "pass"
DELAY = "delay"
BAN = "ban"

# Below this a decayed score is treated as zero and the entry can be dropped.
_FORGET_BELOW = 0.1
# Prune the table when it grows past this many IPs.
_PRUNE_AT = 10_000


class Reputation:
    def __init__(self, half_life, throttle_at, ban_at, max_delay, ban_cooldown,
                 clock=time.monotonic):
        self.half_life = half_life          # seconds for a score to halve
        self.throttle_at = throttle_at      # score above which we tarpit
        self.ban_at = ban_at                # score above which we 429
        self.max_delay = max_delay          # cap on the tarpit delay, seconds
        self.ban_cooldown = ban_cooldown    # Retry-After when banned, seconds
        self._clock = clock
        self._scores = {}                   # ip -> (score, last_seen)
        self._lock = threading.Lock()

    def _decayed(self, ip, now):
        """Current score of `ip` after applying decay (does not store)."""
        entry = self._scores.get(ip)
        if entry is None:
            return 0.0
        score, last_seen = entry
        if score <= 0:
            return 0.0
        return score * (0.5 ** ((now - last_seen) / self.half_life))

    def _prune(self, now):
        dead = [ip for ip in self._scores if self._decayed(ip, now) < _FORGET_BELOW]
        for ip in dead:
            del self._scores[ip]

    def penalise(self, ip, amount):
        """Add `amount` to the decayed score of `ip` and return the new score."""
        now = self._clock()
        with self._lock:
            score = self._decayed(ip, now) + amount
            self._scores[ip] = (score, now)
            if len(self._scores) > _PRUNE_AT:
                self._prune(now)
            return score

    def score(self, ip):
        """Current decayed score of `ip`, without changing it."""
        with self._lock:
            return self._decayed(ip, self._clock())

    def classify(self, score):
        """Map a score to (action, delay_or_retry_after_seconds)."""
        if score > self.ban_at:
            return BAN, self.ban_cooldown
        if score > self.throttle_at:
            span = self.ban_at - self.throttle_at
            fraction = (score - self.throttle_at) / span if span > 0 else 1.0
            return DELAY, min(self.max_delay, self.max_delay * fraction)
        return PASS, 0.0

    def assess(self, ip, amount):
        """Penalise `ip` by `amount`, then classify. Returns (score, action, seconds)."""
        score = self.penalise(ip, amount)
        action, seconds = self.classify(score)
        return score, action, seconds

    def reset(self):
        with self._lock:
            self._scores.clear()
