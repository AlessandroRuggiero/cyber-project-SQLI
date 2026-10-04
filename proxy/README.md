# SQLi filtering proxy

An async reverse proxy written in Python with FastAPI and httpx, served by uvicorn. It sits in front of the vulnerable app in `../cbr_project` and inspects every request for SQL injection before forwarding it. It is async so the reputation tarpit can delay a request with `await asyncio.sleep` — which frees the event loop instead of tying up a thread.

```
browser ──► proxy (:8080) ──► cbr_project (:5000)
              │
              ├─ detector.inspect() ─► clean / suspicious / malicious
              └─ reputation (per IP) ─► forward · tarpit · ban (429)
```

## Layout

| File | Purpose |
|---|---|
| `app.py` | Catch-all async reverse proxy (FastAPI + httpx). It forwards method, path, query, body, headers and cookies, and relays the response (including `Set-Cookie` and redirects). |
| `detector.py` | Detection framework. `extract_inputs()` collects the user-controlled values, `inspect()` + `verdict()` combine per-value results into clean / suspicious / malicious, and `check_value()` delegates to the detectors. |
| `detectors/` | One detector per file, each a `check_value(value)` returning `(Severity, reason)` — a clean value is `(Severity.CLEAN, "")`, never `None`. The bundled ones are all `example_*` templates to copy and replace: `example_obvious_injection.py` and `example_time_based.py` → `Severity.MALICIOUS`; `example_sql_tokens.py` and `example_metadata.py` → `Severity.SUSPICIOUS`. `__init__.py` defines the `Severity` enum (`CLEAN < SUSPICIOUS < MALICIOUS`) and runs them all, keeping the highest. Add a rule by dropping in a module and listing it in `DETECTORS`. |
| `reputation.py` | Per-IP suspicion scores with time decay, and the tiered throttle decision (pass / tarpit / ban). |
| `config.py` | Settings, read from environment variables. |
| `echo_backend.py` | Stand-in backend for developing filters. It logs every request that reaches it and echoes it back as JSON. |
| `tests/` | pytest suite. The backend is mocked, so the tests need no running app. |
| `http/` | `.http` payload files to fire at a running proxy: `attacks.http` (blocked), `benign.http` (must all pass), `mixed.http` (ambiguous — forwarded but scored suspicious). `run_http.py` sends them from the CLI. |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BACKEND_URL` | `http://127.0.0.1:5000` | The real app |
| `PROXY_HOST` / `PROXY_PORT` | `127.0.0.1` / `8080` | Where the proxy listens |
| `BLOCK_MODE` | `block` | `block` enforces (403 / tarpit / 429). `monitor` only logs the verdict and what it would have done, and forwards everything. |
| `BACKEND_TIMEOUT` | `10` | Seconds to wait for the backend before returning a 502 |
| `SUSPICIOUS_SCORE` / `MALICIOUS_SCORE` | `3` / `10` | How much a suspicious / malicious request adds to the client's score |
| `SCORE_HALF_LIFE` | `120` | Seconds for an idle IP's score to halve (how fast it recovers) |
| `THROTTLE_THRESHOLD` / `BAN_THRESHOLD` | `10` / `25` | Score above which requests are tarpitted / rejected with 429 |
| `MAX_THROTTLE_DELAY` | `5` | Cap on the tarpit delay, in seconds |
| `BAN_COOLDOWN` | `30` | `Retry-After` sent while an IP is banned, in seconds |

## Running

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest

# terminal 1: the vulnerable backend
cd ../cbr_project && python main.py

# terminal 2: the proxy (uvicorn; `python app.py` is equivalent)
uvicorn app:app --host 127.0.0.1 --port 8080
```

`python app.py` runs the same uvicorn server. Then browse http://127.0.0.1:8080. The backend on :5000 should not be reachable from outside, or the proxy can simply be bypassed.

## Developing filters with the echo backend

`echo_backend.py` listens on :5000 like the real app, so the proxy needs no config change. Run it **instead of** `cbr_project` while working on rules:

```bash
# terminal 1
python echo_backend.py

# terminal 2
python app.py
```

Anything the filter lets through is printed in terminal 1 as `REACHED BACKEND: ...` and echoed back as JSON. Blocked requests never reach it, and the proxy answers with a 403. It has no database, so nothing on disk changes, and it accepts any path and method:

```bash
curl -s -d "email=x&password=1' OR '1' = '1" http://127.0.0.1:8080/login
curl -s "http://127.0.0.1:8080/anything?id=1%20UNION%20SELECT%20password%20FROM%20users"
curl -s -H 'Content-Type: application/json' -d '{"id": "1; DROP TABLE users--"}' http://127.0.0.1:8080/api
```

Use `ECHO_PORT` to run it on another port, together with `BACKEND_URL` on the proxy.

## Reputation and throttling

Detection is not all-or-nothing. `check_value()` returns a **severity** per value, and `inspect()`/`verdict()` reduce a request to one of three verdicts:

| Verdict | Request | Score |
|---|---|---|
| clean | forwarded | unchanged |
| suspicious (e.g. a stray `'`, a bare `--`) | forwarded | `+SUSPICIOUS_SCORE` |
| malicious (e.g. `' OR '1'='1`, `UNION SELECT`) | **blocked (403)** | `+MALICIOUS_SCORE` |

Scores are kept **per client IP** and decay with a half-life, so an IP that stops probing recovers on its own. The current score drives a tiered response:

```
score ≤ THROTTLE_THRESHOLD              → forward normally
THROTTLE_THRESHOLD < score ≤ BAN_THRESHOLD → tarpit: sleep before forwarding,
                                             the delay growing with the score
score > BAN_THRESHOLD                    → reject with 429 + Retry-After
```

So an IP that sends obvious attacks is blocked *and* loses reputation; once its score is high enough, even its clean-looking requests get tarpitted and then banned — the throttle attaches to the IP, not the single request. Blocking a malicious request always wins over throttling (it returns 403 regardless of score).

The detectors are all `example_*` modules — deliberately crude plain-string checks (no regex) meant as templates to copy, not a finished WAF: `example_obvious_injection.py` (tautology / UNION / stacked write / quote-comment) and `example_time_based.py` (SLEEP / pg_sleep / WAITFOR DELAY) → MALICIOUS; `example_sql_tokens.py` (comment marker / lone keyword) and `example_metadata.py` (information_schema / sqlite_master / @@version …) → SUSPICIOUS. They miss obfuscated payloads (e.g. `/**/` in place of spaces) and occasionally over-flag. Tightening or replacing them, and the `*_SCORE` / `*_THRESHOLD` / `SCORE_HALF_LIFE` / cooldown settings above, is the work. In `monitor` mode the verdict and the action it *would* take are logged, but nothing is blocked or delayed.

## Payload files (`http/`)

Two `.http` files to exercise a running proxy:

- `attacks.http` — SQL injection in forms, query strings, JSON, a header and a cookie. Every request should be **blocked** (403, or 429 once the score piles up).
- `benign.http` — legitimate requests, including values that merely look like SQL (`O'Brien`, `coffee or tea`, a password with `'`, `-` and `=`). Every request must **pass**. This is the false-positive guard.
- `mixed.http` — ambiguous requests (a lone SQL keyword, a `--` or `/* */` in otherwise normal text). Each is **forwarded** but rated *suspicious*, so firing the file raises the client's score and the tarpit progressively kicks in. The proxy log shows `suspicious` → `THROTTLED`.

Open them in VS Code with the "REST Client" extension (or JetBrains' HTTP client) and click *Send Request*, or run them from the CLI:

```bash
python http/run_http.py http/attacks.http --expect 403
python http/run_http.py http/benign.http  --expect 2xx,3xx
python http/run_http.py http/mixed.http   --expect 2xx,3xx
```

`run_http.py` prints each request's status and flags (`!!`) any that did not match `--expect`, so tightening a rule and re-running tells you at a glance whether you caught more attacks without breaking normal traffic. Because reputation is per-IP and sticky, restart the proxy between files for a clean per-file picture (otherwise the attack scores bleed into the next run).

## Next step

Tune the detectors in `detectors/` (plain string checks, no regex). With the current crude rules, `attacks.http` is mostly blocked but a couple of obfuscated payloads only register as *suspicious*, and `mixed.http` shows how ambiguous traffic accrues reputation. Each detector's `check_value(value)` returns `(Severity.MALICIOUS, reason)`, `(Severity.SUSPICIOUS, reason)` or `(Severity.CLEAN, "")`.
