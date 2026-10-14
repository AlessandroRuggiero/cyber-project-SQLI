#!/usr/bin/env python3
"""Minimal .http runner: send every request in a .http file and print the status."""

import argparse
import re
import sys
from urllib.parse import quote

import httpx


def parse(path):
    variables, requests_out = {}, []
    with open(path, encoding="utf-8") as handle:
        blocks = re.split(r"(?m)^###.*$", handle.read())

    for block in blocks:
        lines = block.splitlines()
        title, method, url, headers, body_lines, in_body = "", None, None, {}, [], False
        for line in lines:
            if not in_body and line.startswith("@"):
                name, _, value = line[1:].partition("=")
                variables[name.strip()] = value.strip()
                continue
            if method is None:
                # Take the whole target (it may contain raw spaces), dropping an
                # optional trailing "HTTP/1.1".
                m = re.match(
                    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+?)(?:\s+HTTP/[\d.]+)?\s*$",
                    line,
                )
                if m:
                    method, url = m.group(1), m.group(2)
                continue
            if not in_body:
                if line.strip() == "":
                    in_body = True
                elif ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip()] = value.strip()
            else:
                body_lines.append(line)

        if method and url:
            for name, value in variables.items():
                url = url.replace("{{%s}}" % name, value)
            # .http request lines may contain raw spaces/quotes in the query;
            # The client needs a pre-encoded URL, so encode it like a browser
            # would (% is safe so an already-encoded %27 is not double-encoded).
            url = quote(url, safe="!#$%&'()*+,/:;=?@[]~")
            body = "\n".join(body_lines).strip("\n")
            requests_out.append((title.strip(), method, url, headers, body))
    return requests_out


def matches(code, expect):
    for pattern in expect:
        if pattern.endswith("xx") and str(code).startswith(pattern[0]):
            return True
        if pattern.isdigit() and int(pattern) == code:
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--expect", default="", help="comma list, e.g. 403 or 2xx,3xx")
    args = ap.parse_args()
    expect = [p.strip() for p in args.expect.split(",") if p.strip()]

    reqs = parse(args.file)
    bad = 0
    for i, (title, method, url, headers, body) in enumerate(reqs, 1):
        try:
            resp = httpx.request(method, url, headers=headers,
                                 content=body.encode() if body else None,
                                 follow_redirects=False, timeout=10)
            code = resp.status_code
        except httpx.HTTPError as exc:
            print(f"  {i:2}. ERR  {method} {url}  ({exc})")
            bad += 1
            continue

        ok = matches(code, expect) if expect else True
        if not ok:
            bad += 1
        flag = "    " if ok else " !! "
        print(f"{flag}{i:2}. {code} {method} {url.split('://',1)[-1]}  {title}")

    total = len(reqs)
    if expect:
        print(f"\n{total - bad}/{total} matched expected {args.expect}")
        sys.exit(1 if bad else 0)
    print(f"\n{total} requests sent")


if __name__ == "__main__":
    main()
