# SQLi Cybersecurity Project

## Problem statement

The project aims to demonstrate how SQL injections can be 
exploited, detected and blocked in a vulnerable web application. 
The project features a CLI tool to automatically dump a database given a blind SQLi vulnerable endpoint (boolean based extraction) and a proxy which inspects incoming requests and blocks or delays payloads that appear malicious. 
The project therefore aims to cover both the attack and defense sides of the problem.

## AI Usage Disclosure 

AI was used to generate the whole website contained in `cbr_project/website`,
to write the Dockerfiles needed to containerize the application, and to define
the SQL database.

The student written part of the project is contained in
`cbr_project/boolean` (Bucci) and `cbr_project/proxy` (Erikers and Ruggiero).

## Reference

- [SQLite documentation](https://sqlite.org/docs.html)
- [PayloadAllTheThings SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

## Project documentation

### Website and database

The Flask backend is implemented in `cbr_project/main.py`. Its templates,
static files, schema, seed data, and database are under `cbr_project`. The
demo accounts are:

- `demo@example.com` / `demo`
- `admin@example.com` / `admin`

The training vulnerability is limited to `POST /login`. Other database
queries use parameters; new string-built SQL queries should not be added.

### SQLi filtering proxy

The proxy is in `cbr_project/proxy` and runs in front of the backend. It
examines values in paths, query parameters, request bodies, headers, and
cookies. Detector results are classified as clean, suspicious, or malicious.
In block mode, malicious requests receive `403`; suspicious traffic increases
the client's score and can be tarpitted or eventually rejected with `429`.
Monitor mode logs the verdict but forwards requests.

### Boolean SQL dumper

`cbr_project/boolean/db_dumper.py` automates SQLite extraction through a
true/false HTTP response oracle. It enumerates tables and columns, counts
rows, and uses the shared `boolean_extractor.py` to recover query results
character by character with binary search. Extracted tables are written as
UTF-8 CSV files in `dump/`. The dumper supports GET and POST targets,
custom payload templates, response-status or response-text oracles, headers,
cookies, and timeouts. Example commands are available in
`cbr_project/boolean/exploit.sh`.

## Testing documentation

### Website via docker

```bash
docker compose up --build
```

Open <http://127.0.0.1:8080>. Stop with `docker compose down`; add `-v` to
recreate the database volume. To run the backend without Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m cbr_project.init_db
flask --app cbr_project.main:main run
```

The backend is then available at <http://127.0.0.1:5000>. Test proxy payloads
and run the automated tests with:

```bash
python cbr_project/proxy/http/run_http.py cbr_project/proxy/http/attacks.http --expect 403
pytest
```

### Testing filters with echo backend

Start the echo backend and proxy in separate terminals:

```bash
python cbr_project/proxy/echo_backend.py
python cbr_project/proxy/app.py
```

Forwarded requests are printed by the echo backend; malicious requests should
be rejected by the proxy and should not appear there.

## Individual contributions

### Martin Erikers (erikers@kth.se)

TODO

### Gioele Bucci (gioeleb@kth.se)

My contribution was the boolean-based SQL injection dumper in
`cbr_project/boolean/db_dumper.py`. It automates the extraction of an SQLite
database through a true/false response oracle, without relying on the
application returning query results directly. The dumper first enumerates
user-created tables through `sqlite_master`, then retrieves each table's
column names using `pragma_table_info`. For every table it counts the rows and
extracts them one at a time.

The extraction is performed by the shared `boolean_extractor` module. It
determines the length of each query result and recovers every printable
character with binary search, minimizing the number of HTTP requests compared
with trying every possible character. The dumper combines column values with
delimiters, quotes schema-derived identifiers safely, converts SQL `NULL`
values to a visible representation, and separates the recovered output back
into rows and columns. Each table is saved as a separate UTF-8 CSV file in a
`dump` directory, with sanitized filenames.

The command-line interface supports both GET and POST injection points, custom
boolean payload templates, response-status or response-text oracles, headers,
cookies, and request timeouts. The accompanying `exploit.sh` examples
demonstrate a full database dump and an authenticated POST-based dump through
the proxy.
