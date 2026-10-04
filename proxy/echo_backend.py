"""Stand-in backend for developing filters: logs every request that reaches it.

Run it instead of ../cbr_project on the same port, and the proxy needs no
changes. Anything the filter blocked never shows up here; anything it let
through is logged and echoed back as JSON, exactly as the backend received it.
"""

import logging
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("echo")

ECHO_HOST = os.environ.get("ECHO_HOST", "127.0.0.1")
ECHO_PORT = int(os.environ.get("ECHO_PORT", "5000"))

ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


@app.route("/", defaults={"path": ""}, methods=ALL_METHODS)
@app.route("/<path:path>", methods=ALL_METHODS)
def echo(path):
    form = request.form.to_dict(flat=False)
    json_body = request.get_json(silent=True)
    received = {
        "method": request.method,
        "path": request.path,
        "query": request.args.to_dict(flat=False),
        "form": form,
        "json": json_body,
        # Raw body only when it is neither a form nor JSON, to avoid logging it twice.
        "body": "" if form or json_body is not None else request.get_data(as_text=True),
        "cookies": request.cookies.to_dict(),
        "headers": dict(request.headers),
    }

    lines = [f"REACHED BACKEND: {request.method} {request.full_path.rstrip('?')}"]
    for section in ("query", "form", "json", "body", "cookies"):
        if received[section]:
            lines.append(f"  {section}: {received[section]!r}")
    log.info("\n".join(lines))

    return jsonify(received)


if __name__ == "__main__":
    app.run(host=ECHO_HOST, port=ECHO_PORT)
