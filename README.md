# Cyber-project-SQLI
## Problem statement
(problem statement)
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
### Filtering
The filtering is done in the proxy, using the filters found in [regex_rules.py](cbr_project/proxy/detectors/regex_rules.py), [tokenizer.py](cbr_project/proxy/detectors/tokenizer.py), and [schema_constraint.py](cbr_project/proxy/schema_constraint.py).

[regex_rules.py](cbr_project/proxy/detectors/regex_rules.py) contains the regex rule-based SQLi detection. It contains one function per filtering rule, returning true if a match is found and false if not. Every rule returning true is then summed together in `apply_rules()` via different weights per rule. If the sum is greater than a certain threshold, the `Severity.SUSPICIIOUS` result is returned. If the sum passes a higher threshold, `Severity.MALICIOUS` is returned. Currently, due to the small amount of filter functions included, the weights are set to almost always trigger a "malicious" detection by themselves. However, the weights and thresholds can be adjusted to create a more fine-grained filter.
Strengths:
- Adaptable to any type of input passed on to the database
- Larger, more detailed rule sets can lead to a relatively high accuracy of identifying injection attempts
Weaknesses:
- Writing the perfect set of regexes to identify all forms of SQL injection is a very difficult problem, as one can often by accident either over or undershoot the target effect when working with complex regexes
- Without a very large set of well-tuned rules, it suffers both a large risk of evasion tactics slipping through and a large rate of false positives, balanced by the level of "paranoia" in the rules and their weights (how wide the rules are and easily they trigger a detection)
Evaluation:
This filter currently blocks all injection attempts by sqlmap except some used for probing (see testing section for the particular command used). However, bypassing it is still very doable and there is a large amount of potential false positives.

[schema_constraint.py](cbr_project/proxy/schema_constraint.py) contains functions each corresponding to a particular input type featured in the project backend, and `follows_schema()` which selects the correct function to validate a particular parameter in the request based on its type.
Strengths:
- Very good accuracy; generally produces no false positives or negatives as every relevant input for this filter follows a strict format and can be relatively easily targeted with regex
Weaknesses:
- Doesn't work for all types of user input; in this project the website has a `password` parameter vulnerable which is hard/inadvisable to constrain without harming account security
- As the allowed type of input widens, the regexes required to successfully filter SQLi approaches the general regex rule case
Evaluation:
Seems to perfectly block attempts at protected endpoints, but does nothing when the input isn't of a particularly constrained format.

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
(how to run the full site)
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
- `BLOCK-MODE=no_ban` is useful here to allow sqlmap to brute force rapidly while still communicating if requests were passed on or blocked

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
### Martin Erikers (erikers@kth.se)
The main focus of my personal contribution is the filters used in the proxy to filter out incoming attempts at SQL injection. 

The first step working on the filters was researching existing options, and trying to figure out what was reasonable to build for the project. For this reason, I selected a general regex-based filter, an input validation filter (here called "schema constraint" despite not directly interacting with the database schema), and also included an existing tokenizing heuristic-based detector ([libinjection](https://github.com/libinjection/libinjection)) for comparison.

I started by implementing a transformation function with the purpose of matching the operations done on the query by SQLite to make sure the string I was writing rules against looked the same as it does to the SQLite parser. 

The regex-based filter was then implemented by, at first, looking up the most common injection approaches and writing basic regexes that would catch them. Following this, I used [sqlmap](https://github.com/sqlmapproject/sqlmap) as an "adversary", running it against my regexes between every update to figure out what I needed to catch next, or if I caused a regression by accident. I also looked briefly to the [OWASP core rule set](https://github.com/coreruleset/coreruleset) for inspiration, but the rules defined there generally are too fine-grained to use here as they're designed to be incredibly specific and complemented by a whole corpus of other incredibly specific rules. 
I did not have great prior familiarity of regex beyond knowing the basic syntax and having written simple regexes for other purposes before this, so [regex101](https://regex101.com) was useful for helping me iterate on my patterns via trial and error. As I worked on the regexes I both added strings that should match and false positives that should be avoided to the test bench, which meant I could instantly see whenever the pattern improved or worsened and could quickly iterate.

The input validation/schema constraint filter was implemented by, based on the vulnerable endpoints in the backend, writing regexes attempting to constrain the input as much as possible while not affecting the intended input space. This required less work, as the regexes used were simple compared to the ones in the general regex filter.

The tokenizing detector used is a third-party library, and as such only needed a small amount plumbing for integration into the proxy.


### etc
