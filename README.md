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

The student written part of the project is contained in `cbr_project/boolean` (Bucci) and `cbr_project/proxy` (Erikers and Ruggiero).

For more information, see [Individual contribution](#individual-contribution) and [AI-DISCLOSURE.md](AI-DISCLOSURE.md)

## Reference
- [SQLite documentation](https://www.sqlite.org/docs.html)
- [swisskyrepo/PayloadsAllTheThings - SQLite Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
- [coreruleset/coreruleset (OWASP CRS for WAFs)](https://github.com/coreruleset/coreruleset)
### Tools/Libraries
- [libinjection](https://github.com/client9/libinjection)
	- [libinjection python wrapper](https://pypi.org/project/libinjection-python/)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [regex101](https://regex101.com)

## Project documentation
### Website and database

The Flask backend is implemented in `cbr_project/main.py`. Its templates,
static files, schema, seed data, and database are under `cbr_project`. The
demo accounts are:

- `demo@example.com` / `demo`
- `admin@example.com` / `admin`

The training vulnerability is limited to `POST /login`. Other database
queries use parameters; new string-built SQL queries should not be added.

### Boolean SQL dumper

`cbr_project/boolean/db_dumper.py` automates SQLite extraction through a
true/false HTTP response oracle. It enumerates tables and columns, counts
rows, and uses the shared `boolean_extractor.py` to recover query results
character by character with binary search. Extracted tables are written as
UTF-8 CSV files in `dump/`. The dumper supports GET and POST targets,
custom payload templates, response-status or response-text oracles, headers,
cookies, and timeouts. Example commands are available in
`cbr_project/boolean/exploit.sh`.

### SQLi filtering proxy

The proxy is in `cbr_project/proxy` and runs in front of the backend. It
examines values in paths, query parameters, request bodies, headers, and
cookies. Detector results are classified as clean, suspicious, or malicious.
In block mode, malicious requests receive `403`; suspicious traffic increases
the client's score and can be tarpitted or eventually rejected with `429`.
Monitor mode logs the verdict but forwards requests.

### Filters
The filtering is done in the proxy, using the filters found in [regex_rules.py](cbr_project/proxy/detectors/regex_rules.py), [tokenizer.py](cbr_project/proxy/detectors/tokenizer.py), and [schema_constraint.py](cbr_project/proxy/schema_constraint.py).

[regex_rules.py](cbr_project/proxy/detectors/regex_rules.py) contains the regex rule-based SQLi detection. It contains one function per filtering rule, returning true if a match is found and false if not. Every rule returning true is then summed together in `apply_rules()` via different weights per rule. If the sum is greater than a certain threshold, the `Severity.SUSPICIIOUS` result is returned. If the sum passes a higher threshold, `Severity.MALICIOUS` is returned. Currently, due to the small amount of filter functions included, the weights are set to almost always trigger a "malicious" detection by themselves. However, the weights and thresholds can be adjusted to create a more fine-grained filter.

Strengths:
- Adaptable to any type of input passed on to the database
- Larger, more detailed rule sets can lead to a relatively high accuracy of identifying injection attempts

Weaknesses:
- Writing the perfect set of regexes to identify all forms of SQL injection is a very difficult problem, as one can often by accident either over or undershoot the target effect when working with complex regexes
- Without a very large set of well-tuned rules, it suffers both a large risk of evasion tactics slipping through and a large rate of false positives, balanced by the level of "paranoia" in the rules and their weights (how wide the rules are and easily they trigger a detection)

Evaluation:
The regex rules filter currently blocks all injection attempts by sqlmap except some used for probing (see testing section for the particular command used). However, bypassing it is still very doable and there is a large amount of potential false positives.
\
\
\
[schema_constraint.py](cbr_project/proxy/schema_constraint.py) contains functions each corresponding to a particular input type featured in the project backend, and `follows_schema()` which selects the correct function to validate a particular parameter in the request based on its type.

Strengths:
- Very good accuracy; generally produces no false positives or negatives as every relevant input for this filter follows a strict format and can be relatively easily targeted with regex

Weaknesses:
- Doesn't work for all types of user input; in this project the website has a `password` parameter vulnerable which is hard/inadvisable to constrain without harming account security
- As the allowed type of input widens, the regexes required to successfully filter SQLi approaches the general regex rule case

Evaluation:
The schema constraint filter seems to perfectly block attempts at protected endpoints, but does nothing when the input isn't of a particularly constrainable format.
\
\
\
[tokenizer.py](cbr_project/proxy/detectors/tokenizer.py) contains only the plumbing to implement `libinjection` detection. It works by tokenizing the input and comparing the produced set of tokens to a database of fingerprints.

Strengths:
- Few false positives as the token fingerprint approach used leads to very specific patterns to match potential injection attempts against

Weaknesses:
- Some amount of false negatives, it prioritizes accuracy over catching every attempt
- Can be defeated by padding inputs, as the fingerprints are built from up to a maximum of 5 tokens

Evaluation:
Blocks most attempts from sqlmap, notably missing a few SQLite-specific injections.


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
### Testing filters with the debug echo backend
The regex and libinjection filters are toggled by commenting or uncommenting their lines in `cbr_project/proxy/detectors/__init__.py:48-68`, and the input validation/schema constraint filter can be toggled with the boolean at `cbr_project/proxy/config.py:45`.
The `BLOCK-MODE` environment variable can be set to either `block` to block misbehaving IP addresses, `no_ban` to block individual injection attempts while not banning the clients, or `monitor` to just print received requests and what would have happened with the `block` mode.

1. Make sure you have a virtual environment with the required dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-libinjection.txt      # if the libinjection detector is wanted
```
- `libinjection` can be omitted if including it isn't of interest, just make sure it's also commented out in the code

2. Launch proxy with echo backend
```bash
# proxy
BLOCK_MODE=no_ban uvicorn cbr_project.proxy.app:app --host 127.0.0.1 --port 8090
# echo pseudo-backend
python -m cbr_project.proxy.echo_backend
```
- Both commands should be run in different terminals
- `BLOCK-MODE=no_ban` is useful here to allow sqlmap to brute force rapidly while still showing if requests were passed on or blocked

3. Run tools such as curl or sqlmap to test, echo backend terminal will print any requests successfully passing the proxy
```bash
curl -s -d "email=x&password=1' OR '1' = '1 AND 321=123" http://127.0.0.1:8090/login

sqlmap -u 'http://127.0.0.1:8090/login' -p password \
          --dbms=sqlite --level=5 --risk=3 \
          --threads=1 --timeout=5 --batch \
          --flush-session --fresh-queries --no-logging \
          -v --ignore-code=403 --code=200 \
          --data="email=a@b.se&name=John Doe&password=12345&id=1"
```
- This particular sqlmap command tries SQL injection on the `password` field sent to the login endpoint, suitable for testing the non input validation-based filters (email, name and id  are protected by the input validation constraint, resulting in sqlmap not being able to do much of anything)
- Edit the `-p` switch to change targeted field, or omit it to target all available fields.

## Individual contribution
### Martin Erikers (`erikers@kth.se`)
Main contributions: [regex_rules.py](cbr_project/proxy/detectors/regex_rules.py), [tokenizer.py](cbr_project/proxy/detectors/tokenizer.py), [util.py](cbr_project/proxy/detectors/util.py), [schema_constraint.py](cbr_project/proxy/schema_constraint.py)

The main focus of my personal contribution is the filters used in the proxy to filter out incoming attempts at SQL injection. 

The first step working on the filters was researching existing options, and trying to figure out what was reasonable to build for the project. For this reason, I selected a general regex-based filter, an input validation filter (here called "schema constraint" despite not directly interacting with the database schema), and also included an existing tokenizing heuristic-based detector ([libinjection](https://github.com/libinjection/libinjection)) for comparison.

I started by implementing a transformation function with the purpose of matching the operations done on the query by SQLite to make sure the string I was writing rules against looked the same as it does to the SQLite parser. 

The regex-based filter was then implemented by, at first, looking up the most common injection approaches and writing basic regexes that would catch them. Following this, I used [sqlmap](https://github.com/sqlmapproject/sqlmap) as an "adversary", running it against my regexes between every update to figure out what I needed to catch next, or if I caused a regression by accident. I also looked briefly to the [OWASP core rule set](https://github.com/coreruleset/coreruleset) for inspiration, but the rules defined there generally are too fine-grained to use here as they're designed to be incredibly specific and complemented by a whole corpus of other incredibly specific rules. 
I did not have great prior familiarity of regex beyond knowing the basic syntax and having written simple regexes for other purposes before this, so [regex101](https://regex101.com) was useful for helping me iterate on my patterns via trial and error. As I worked on the regexes I both added strings that should match and false positives that should be avoided to the test bench, which meant I could instantly see whenever the pattern improved or worsened and could quickly iterate.

The input validation/schema constraint filter was implemented by, based on the vulnerable endpoints in the backend, writing regexes attempting to constrain the input as much as possible while not affecting the intended input space. This required less work, as the regexes used were simple compared to the ones in the general regex filter.

The tokenizing detector used is a third-party library, and as such only needed a small amount plumbing for integration into the proxy.


### Gioele Bucci (`gioeleb@kth.se`)

I have developed a CLI tool that automatically dumps each table of a database
as a separate `.csv` file by extracting data from an endpoint vulnerable to
boolean-based SQL injection, automating the process of dumping an SQLite database.
The dumper first enumerates user-created tables through `sqlite_master`, then
retrieves each table's column names using `pragma_table_info`. For every table
it counts the rows and extracts them one at a time.

The extraction is performed by the shared `boolean_extractor` module. It
determines the length of each query result and recovers every printable
character with binary search, minimizing the number of HTTP requests compared
with trying every possible character sequentially. The dumper combines column values with delimiters, quotes schema-derived identifiers safely, converts SQL `NULL`
values to a visible representation, and separates the recovered output back
into rows and columns. Each table is saved as a separate UTF-8 CSV file in a
`dump` directory, with sanitized filenames.

The command-line interface supports both GET and POST injection points, custom
boolean payload templates, response-status or response-text oracles, headers,
cookies, and request timeouts. 
The accompanying `exploit.sh` examples demonstrate a full database dump and an authenticated POST-based dump. The extraction logic is also easily expandable to support time-based extraction: the blind extraction concept remains the same, while
the response oracle can be adapted to measure delays instead of evaluating
true-or-false responses.

The video at [cbr_project/boolean/demo_boolean.mp4](https://github.com/AlessandroRuggiero/cyber-project-SQLI/blob/main/cbr_project/boolean/demo_boolean.mp4) showcases the Boolean SQL dumper in use against the project's website.
