import httpx
import pytest
from fastapi.testclient import TestClient

import app as proxy_app
import config
import detector
import reputation
from detector import Severity

BACKEND = "http://backend.test:5000"


class FakeClient:
    """Stand-in for the shared httpx.AsyncClient: records calls, returns a set response."""

    def __init__(self):
        self.calls = []
        self.response = httpx.Response(200, content=b"ok")
        self.error = None

    async def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if self.error is not None:
            raise self.error
        return self.response


@pytest.fixture
def backend(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(config, "BACKEND_URL", BACKEND)
    monkeypatch.setattr(proxy_app, "client", fake)
    return fake


@pytest.fixture
def client():
    # No `with`, so the lifespan does not run and our fake client stays in place.
    return TestClient(proxy_app.app)


@pytest.fixture(autouse=True)
def reset_reputation():
    """Scores are process-wide and every test client shares one IP, so clear
    the table around each test to keep them independent."""
    proxy_app.rep.reset()
    yield
    proxy_app.rep.reset()


def test_forwards_method_path_query_and_body(backend, client):
    resp = client.post("/login?next=%2Fcart", data={"email": "alice", "password": "pw"})

    assert resp.status_code == 200
    assert resp.content == b"ok"
    call = backend.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == BACKEND + "/login?next=%2Fcart"
    assert call["content"] == b"email=alice&password=pw"
    assert call["follow_redirects"] is False


def test_forwards_cookies_and_strips_hop_by_hop_headers(backend, client):
    client.get("/cart", headers={"Connection": "keep-alive", "X-Custom": "1"},
               cookies={"session": "abc"})

    headers = backend.calls[0]["headers"]
    assert headers["cookie"] == "session=abc"
    assert headers["x-custom"] == "1"
    assert "connection" not in headers
    assert "host" not in headers
    assert "x-forwarded-for" in headers


def test_relays_response_headers(backend, client):
    backend.response = httpx.Response(
        302,
        content=b"",
        headers=[
            ("location", BACKEND + "/index"),
            ("set-cookie", "a=1; Path=/"),
            ("set-cookie", "b=2; Path=/"),
            ("transfer-encoding", "chunked"),
        ],
    )

    resp = client.get("/logout", follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers["location"] == "http://testserver/index"
    assert resp.headers.get_list("set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert "transfer-encoding" not in resp.headers


def test_relative_location_is_untouched(backend, client):
    backend.response = httpx.Response(302, headers=[("location", "/login")], content=b"")
    resp = client.get("/cart", follow_redirects=False)
    assert resp.headers["location"] == "/login"


def test_backend_down_returns_502(backend, client):
    backend.error = httpx.ConnectError("refused")
    assert client.get("/").status_code == 502


def test_extract_inputs_covers_all_locations():
    inputs = detector.extract_inputs(
        path="/restaurant",
        query=[("id", "1"), ("q", "x")],
        json_data={"user": {"name": "bob"}, "ids": [1, 2]},
        cookies=[("c", "v")],
        headers={"User-Agent": "ua"},
    )
    assert ("path", "", "/restaurant") in inputs
    assert ("query", "id", "1") in inputs
    assert ("query", "q", "x") in inputs
    assert ("json", "user.name", "bob") in inputs
    assert ("json", "ids[1]", "2") in inputs
    assert ("cookie", "c", "v") in inputs
    assert ("header", "User-Agent", "ua") in inputs


@pytest.fixture
def flag_marker(monkeypatch):
    """Fake detector: flags any value containing MARKER as malicious."""
    monkeypatch.setattr(
        detector, "check_value",
        lambda v: (Severity.MALICIOUS, "marker") if "MARKER" in v else (Severity.CLEAN, ""),
    )


def test_block_mode_blocks_flagged_request(backend, client, flag_marker, monkeypatch):
    monkeypatch.setattr(config, "BLOCK_MODE", "block")

    resp = client.post("/login", data={"email": "x", "password": "MARKER"})

    assert resp.status_code == 403
    assert backend.calls == []


def test_monitor_mode_forwards_flagged_request(backend, client, flag_marker, monkeypatch):
    monkeypatch.setattr(config, "BLOCK_MODE", "monitor")

    resp = client.post("/login", data={"email": "x", "password": "MARKER"})

    assert resp.status_code == 200
    assert len(backend.calls) == 1
    assert backend.calls[0]["content"] == b"email=x&password=MARKER"


def test_tautology_is_blocked(backend, client):
    resp = client.post("/login", data={"email": "a", "password": "1' OR '1' = '1"})
    assert resp.status_code == 403
    assert backend.calls == []


def test_plain_request_passes(backend, client):
    resp = client.post("/login", data={"email": "alice@example.com", "password": "hunter2"})
    assert resp.status_code == 200


def test_suspicious_value_is_forwarded(backend, client):
    resp = client.get("/search?q=select")
    assert resp.status_code == 200
    assert len(backend.calls) == 1
    assert detector.check_value("select")[0] == Severity.SUSPICIOUS
    assert detector.check_value("1' OR '1'='1")[0] == Severity.MALICIOUS
    assert detector.check_value("alice@example.com")[0] == Severity.CLEAN


# ---- reputation / throttling -------------------------------------------------

def test_score_decays_by_half_life():
    now = {"t": 1000.0}
    rep = reputation.Reputation(half_life=60, throttle_at=10, ban_at=25,
                                max_delay=5, ban_cooldown=30, clock=lambda: now["t"])
    rep.penalise("1.2.3.4", 8.0)
    assert rep.score("1.2.3.4") == 8.0
    now["t"] += 60
    assert abs(rep.score("1.2.3.4") - 4.0) < 1e-9
    now["t"] += 120
    assert abs(rep.score("1.2.3.4") - 1.0) < 1e-9


def test_classify_tiers():
    rep = reputation.Reputation(half_life=60, throttle_at=10, ban_at=20,
                                max_delay=4, ban_cooldown=30)
    assert rep.classify(5) == (reputation.PASS, 0.0)
    action, delay = rep.classify(15)
    assert action == reputation.DELAY and abs(delay - 2.0) < 1e-9
    assert rep.classify(100) == (reputation.BAN, 30)


def test_blocked_malicious_still_scores(backend, client, flag_marker, monkeypatch):
    monkeypatch.setattr(config, "BLOCK_MODE", "block")
    before = proxy_app.rep.score("testclient")
    client.post("/login", data={"email": "x", "password": "MARKER"})
    assert proxy_app.rep.score("testclient") > before


def test_suspicious_traffic_is_tarpitted_then_banned(backend, client, monkeypatch):
    monkeypatch.setattr(config, "BLOCK_MODE", "block")
    monkeypatch.setattr(
        detector, "check_value",
        lambda v: (Severity.SUSPICIOUS, "probe") if "PROBE" in v else (Severity.CLEAN, ""),
    )
    monkeypatch.setitem(proxy_app.SCORE_DELTA, Severity.SUSPICIOUS, 3.0)
    monkeypatch.setattr(proxy_app.rep, "throttle_at", 4)
    monkeypatch.setattr(proxy_app.rep, "ban_at", 8)

    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(proxy_app.asyncio, "sleep", fake_sleep)

    codes = [client.get("/x?q=PROBE").status_code for _ in range(3)]

    assert codes == [200, 200, 429]        # pass, tarpit (still forwarded), ban
    assert len(sleeps) == 1 and sleeps[0] > 0
    assert len(backend.calls) == 2         # the banned request never reached the backend


def test_ban_response_has_retry_after(backend, client, monkeypatch):
    monkeypatch.setattr(config, "BLOCK_MODE", "block")
    monkeypatch.setattr(detector, "check_value", lambda v: (Severity.SUSPICIOUS, "p"))
    monkeypatch.setattr(proxy_app.rep, "throttle_at", 0)
    monkeypatch.setattr(proxy_app.rep, "ban_at", 0)
    monkeypatch.setattr(proxy_app.rep, "ban_cooldown", 30)

    resp = client.get("/anything")
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "30"
