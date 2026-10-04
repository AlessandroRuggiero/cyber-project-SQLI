"""Async reverse proxy (FastAPI) that filters SQL injection in front of the app.

Each request gets a verdict from the detectors:
  * malicious  -> blocked with 403 (block mode), and the client's score jumps
  * suspicious -> forwarded, but the client's suspicion score rises a little
  * clean      -> forwarded, no score change

Scores are kept per client IP (reputation.py) and decay over time. Once an IP
is suspicious enough its requests are tarpitted (a growing `await asyncio.sleep`,
which frees the event loop instead of holding a thread) and, higher still,
rejected with 429 + Retry-After. In monitor mode nothing is blocked or delayed:
the proxy only logs the verdict and what it would have done.
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl

import httpx
from fastapi import FastAPI, Request, Response

import config
import detector
import reputation
from detector import Severity

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("proxy")

# Headers that only make sense for a single connection and must not be forwarded.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
# Recomputed for the new message, so never copied over. Content-Encoding is
# dropped because httpx already decompresses the body it hands us.
REQUEST_SKIP = HOP_BY_HOP | {"host", "content-length"}
RESPONSE_SKIP = HOP_BY_HOP | {"content-length", "content-encoding"}

# One shared client, opened at startup and reused for every forward.
client: httpx.AsyncClient = None


@asynccontextmanager
async def lifespan(_app):
    global client
    async with httpx.AsyncClient(timeout=config.BACKEND_TIMEOUT) as c:
        client = c
        yield


app = FastAPI(lifespan=lifespan)

# Per-IP suspicion scores and the tiered throttle decision.
rep = reputation.Reputation(
    half_life=config.SCORE_HALF_LIFE,
    throttle_at=config.THROTTLE_THRESHOLD,
    ban_at=config.BAN_THRESHOLD,
    max_delay=config.MAX_THROTTLE_DELAY,
    ban_cooldown=config.BAN_COOLDOWN,
)

# How much each verdict adds to the client's score.
SCORE_DELTA = {
    Severity.CLEAN: 0.0,
    Severity.SUSPICIOUS: config.SUSPICIOUS_SCORE,
    Severity.MALICIOUS: config.MALICIOUS_SCORE,
}


def _collect_inputs(request, body):
    """Decode the request into the (location, name, value) list the detectors want."""
    content_type = request.headers.get("content-type", "")
    form, json_data, raw = (), None, ""
    if "application/x-www-form-urlencoded" in content_type:
        form = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    elif "application/json" in content_type:
        try:
            json_data = json.loads(body)
        except ValueError:
            json_data = None
    else:
        raw = body.decode("utf-8", "replace")

    return detector.extract_inputs(
        path=request.url.path,
        query=request.query_params.multi_items(),
        form=form,
        json_data=json_data,
        body=raw,
        cookies=request.cookies.items(),
        headers=request.headers,
    )


def _forward_headers(request, client_ip):
    headers = {k: v for k, v in request.headers.items() if k.lower() not in REQUEST_SKIP}
    previous = request.headers.get("x-forwarded-for")
    headers["x-forwarded-for"] = f"{previous}, {client_ip}" if previous else client_ip
    headers["x-forwarded-host"] = request.headers.get("host", "")
    headers["x-forwarded-proto"] = request.url.scheme
    return headers


def _relay_response(request, upstream):
    body = upstream.content
    response = Response(content=body, status_code=upstream.status_code)
    # Rebuild headers from the upstream response, preserving duplicates
    # (several Set-Cookie) and rewriting an absolute redirect to the backend.
    raw = [(b"content-length", str(len(body)).encode())]
    base = str(request.base_url).rstrip("/")
    for name, value in upstream.headers.multi_items():
        if name.lower() in RESPONSE_SKIP:
            continue
        if name.lower() == "location" and value.startswith(config.BACKEND_URL):
            value = base + value[len(config.BACKEND_URL):]
        raw.append((name.encode("latin-1"), value.encode("latin-1")))
    response.raw_headers = raw
    return response


@app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy(path: str, request: Request):
    ip = request.client.host if request.client else "unknown"
    query = ("?" + request.url.query) if request.url.query else ""
    here = f"{request.method} {request.url.path}{query}"

    body = await request.body()
    findings = detector.inspect(_collect_inputs(request, body))
    for f in findings:
        log.warning("%s in %s %r: %r (%s)", f.severity, f.location, f.name, f.value, f.reason)

    result = detector.verdict(findings)
    score, action, seconds = rep.assess(ip, SCORE_DELTA[result])

    # Monitor mode never interferes: it only observes and scores.
    if config.BLOCK_MODE == "monitor":
        if result != Severity.CLEAN or action != reputation.PASS:
            log.info("%s -> MONITOR (%s, score %.1f, would %s)", here, result, score, action)
    else:
        if result == Severity.MALICIOUS:
            log.info("%s -> BLOCKED (score %.1f)", here, score)
            return _blocked_response()
        if action == reputation.BAN:
            log.info("%s -> BANNED (score %.1f, retry after %ds)", here, score, seconds)
            return _throttled_response(seconds)
        if action == reputation.DELAY and seconds > 0:
            log.info("%s -> THROTTLED (score %.1f, delay %.1fs)", here, score, seconds)
            await asyncio.sleep(seconds)  # frees the event loop, holds no thread

    target = config.BACKEND_URL + request.url.path + query
    try:
        upstream = await client.request(
            request.method, target,
            headers=_forward_headers(request, ip),
            content=body,
            follow_redirects=False,
        )
    except httpx.RequestError as exc:
        log.error("%s -> backend error: %s", here, exc)
        return Response("<h1>502 Bad Gateway</h1>", status_code=502, media_type="text/html")

    note = "forwarded" if result == Severity.CLEAN else f"forwarded ({result}, score {score:.1f})"
    log.info("%s -> %s (%d)", here, note, upstream.status_code)
    return _relay_response(request, upstream)


def _blocked_response():
    body = "<h1>403 Forbidden</h1><p>The request was blocked by the SQL injection filter.</p>"
    return Response(body, status_code=403, media_type="text/html")


def _throttled_response(retry_after):
    body = "<h1>429 Too Many Requests</h1><p>This client is temporarily throttled.</p>"
    return Response(body, status_code=429, media_type="text/html",
                    headers={"Retry-After": str(int(retry_after))})


if __name__ == "__main__":
    import uvicorn

    log.info("Proxying http://%s:%d -> %s (mode: %s)",
             config.PROXY_HOST, config.PROXY_PORT, config.BACKEND_URL, config.BLOCK_MODE)
    uvicorn.run(app, host=config.PROXY_HOST, port=config.PROXY_PORT)
