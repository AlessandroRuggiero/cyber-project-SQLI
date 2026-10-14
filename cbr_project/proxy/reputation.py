"""Per-IP suspicion scores with time decay, mapped to a tiered pass/delay/ban action."""

import threading
import time
from collections.abc import Callable
from typing import Literal

Action = Literal["pass", "delay", "ban"]
ScoreEntry = tuple[float, float]  # (score, last_seen)

PASS: Action = "pass"
DELAY: Action = "delay"
BAN: Action = "ban"

# https://registry.khronos.org/OpenGL-Refpages/es3/html/smoothstep.xhtml
smoothstep = lambda edge0, edge1, x: (lambda t: t * t * (3.0 - 2.0 * t))(
    max(0.0, min(1.0, (x - edge0) / (edge1 - edge0)))
)


class ReputationTable:
    def __init__(
        self,
        half_life: float,
        throttle_at: float,
        ban_at: float,
        max_delay: float,
        ban_cooldown: float,
        drop_below: float = 0.1,
        soft_prune_at: int = 10_000,
        hard_prune_at: int = 12_000,
        hard_prune_target: int = 7500,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.half_life = half_life
        self.throttle_at = throttle_at
        self.ban_at = ban_at
        self.max_delay = max_delay
        self.ban_cooldown = ban_cooldown
        self.drop_below = drop_below  # below this a decayed score is dropped
        self.soft_prune_at = soft_prune_at  # past this, drop dead IPs
        self.hard_prune_at = hard_prune_at  # past this, evict low scores too
        self.hard_prune_target = hard_prune_target  # ...down to this many
        self._clock = clock
        self._scores: dict[str, ScoreEntry] = dict()
        self._lock = threading.Lock()

    def _decay(self, entry: ScoreEntry, now: float) -> float:
        """Compute the decayed score of an already-looked-up entry at time `now`."""
        score, last_seen = entry
        if score <= 0:
            return 0.0
        return score * (0.5 ** ((now - last_seen) / self.half_life))

    def _decayed(self, ip: str, now: float) -> float:
        """Compute the decayed score of `ip` at time `now`."""
        entry = self._scores.get(ip)
        return self._decay(entry, now) if entry is not None else 0.0

    def _prune(self, now: float) -> None:
        """Drop dead IPs; past hard_prune_at, evict the lowest scores too."""
        scores = {ip: self._decay(entry, now) for ip, entry in self._scores.items()}
        alive = {ip: s for ip, s in scores.items() if s >= self.drop_below}

        if len(alive) > self.hard_prune_at:
            keep = sorted(alive, key=alive.get, reverse=True)[: self.hard_prune_target]
            alive = {ip: alive[ip] for ip in keep}

        self._scores = {ip: self._scores[ip] for ip in alive}

    def penalise(self, ip: str, amount: float) -> float:
        """Add `amount` to the decayed score of `ip` and return the new score."""
        now = self._clock()
        with self._lock:
            score = self._decayed(ip, now) + amount
            self._scores[ip] = (score, now)  # Update the score and last_seen timestamp
            if len(self._scores) > self.soft_prune_at:
                self._prune(now)
            return score

    def score(self, ip: str) -> float:
        """Current decayed score of `ip`"""
        with self._lock:
            return self._decayed(ip, self._clock())

    def classify(self, score: float) -> tuple[Action, float]:
        """Map a score to (action, delay_or_retry_after_seconds)."""
        if score > self.ban_at:
            return BAN, self.ban_cooldown
        if score > self.throttle_at:
            span = self.ban_at - self.throttle_at
            fraction = (score - self.throttle_at) / span if span > 0 else 1.0
            return DELAY, self.max_delay * smoothstep(0.0, 1.0, fraction)
        return PASS, 0.0

    def assess(self, ip: str, amount: float) -> tuple[float, Action, float]:
        """Penalise `ip` by `amount`, then classify."""
        score = self.penalise(ip, amount)
        action, seconds = self.classify(score)
        return score, action, seconds

    def reset(self) -> None:
        with self._lock:
            self._scores.clear()
