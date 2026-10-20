# Cyber-project-SQLI
## Problem statement
(problem statement)
## Reference
- [SQLite documentation](https://www.sqlite.org/docs.html)
- [swisskyrepo/PayloadsAllTheThings - SQLite Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
- [coreruleset/coreruleset (OWASP CRS for WAFs)](https://github.com/coreruleset/coreruleset)
### Tools/Libraries
- [libinjection](https://github.com/client9/libinjection)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [regex101](https://regex101.com)
## Project documentation
(main documentation, divided into domains)
### Filtering
The main filtering is done in `regex_rules.py` and `tokenizer.py` in the `cbr_project/proxy/detectors/` directory, and in `schema_constraint.py` in the `cbr_project/proxy/` directory.

`regex_rules.py` contains the regex rule-based SQLi detection. It contains one function per filtering rule returning true if a match is found and false if not, which are all summed together in `apply_rules()` via different weights per rule. If the sum is greater than a certain limit, the `Severity.SUSPICIIOUS` result is returned. If the sum passes a higher threshold, `Severity.MALICIOUS` is returned. Currently, due to the small amount of filter functions included, the weights are set to almost always trigger a "malicious" response by themselves. However, the weights and thresholds can be adjusted to create a more fine-grained filter.
Strengths:
- Adaptable to any type of input passed on to the database
- Larger, more detailed rule sets can lead to a relatively high accuracy of identifying injection attempts
Weaknesses:
- Writing the perfect set of regexes to identify all forms of SQL injection is a very difficult problem; one can often by accident either over- or undershoot the intended effect when working on complex regexes
- Without a very large set of well-tuned rules, it suffers both a large risk of evasion tactics slipping through and a large rate of false positives, balanced by the level of paranoia in the rules and their weights

`schema_constraint.py` contains functions each corresponding to a particular input class featured in the project site, and `follows_schema()` which selects the correct function to validate a particular parameter in the request based on its name.
Strengths:
- Very good accuracy; generally no false positives or negatives as every relevant input for this filter follows a strict format
Weaknesses:
- Doesn't work for all types of user input; in this project the website has a `password` parameter vulnerable which is hard/inadvisable to constrain without harming account security
- As the input allowed gets broader, the regexes required to match them approaches the general regex rule case

`tokenizer.py` contains only the plumbing to implement `libinjection` detection.
Strengths:
- Few false positives; the token fingerprint approach used results in tightly defined patterns for finding injection attempts (there are still examples though)LÄNK
Weaknesses:
- A fair amount of false negatives
- Can be defeated by padding inputs, as the fingerprints are based on up to max 5 tokens

## Testing documentation
### Website via docker
(how to run the full site)
### Testing filters with the debug echo backend
1. Create virtual environment and install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-libinjection.txt      # if libinjection filter is wanted
```
- `libinjection` can be omitted if testing it isn't of interest; might however need to comment out a couple lines of code TODO ELABORATE

2. Launch proxy with echo backend
```bash
# proxy
BLOCK_MODE=no_ban uvicorn cbr_project.proxy.app:app --host 127.0.0.1 --port 8090
# echo pseudo-backend
python -m cbr_project.proxy.echo_backend
```
- each command should be run in a different terminal
- `BLOCK-MODE=no_ban` disables the rate-limiting/banning functionality to enable faster brute force testing, while still making sure the proxy properly blocks requests that should be filtered

3. Run sqlmap to test
```bash
sqlmap -u 'http://127.0.0.1:8090/login' -p password \
          --dbms=sqlite --level=5 --risk=3 \
          --threads=1 --timeout=5 --batch \
          --flush-session --fresh-queries --no-logging \
          -v --ignore-code=403 --code=200 \
          --data="email=a@b.se&name=John Doe&password=12345&id=1"
```
- This particular command tries SQL injection on the `password` field sent to the login endpoint, suitable for testing the non input validation-based filters (email, name and id in this (fictional) endpoint are protected with input validation, resulting in sqlmap not being able to do much of anything)
- Edit the `-p` switch to change targeted field; omit it to target all available fields.

## Individual contribution
### Martin Erikers (erikers@kth.se)
Like the other group members, I helped plan and decide what the project should be about, including the scope and limitations. The main focus of my personal contribution is the filters used in the proxy to filter out incoming attempts at SQL injection. The first step towards this was researching existing options, and trying to figure out what was reasonable to build for the project. For this reason, I selected a general regex-based filter, an input validation filter (called "schema constraint" despite not directly interacting with the database schema), and also included an existing tokenizing heuristic-based detector ([libinjection](https://github.com/libinjection/libinjection)) for comparison.

I started by implementing utility functions with the purpose of simulating initial operations done on the query by SQLite; to make sure the string I was writing rules against looked the same as it does to the SQLite parser. 
- The regex-based filter was then implemented by, at first, looking up the most common injection approaches and writing basic regexes that would catch them. Following this, I used [sqlmap](https://github.com/sqlmapproject/sqlmap) as an "adversary", running it against my filter between every update to figure out what I needed to catch next, or if I caused a regression by accident. I also looked briefly to the [OWASP core rule set](https://github.com/coreruleset/coreruleset) for inspiration, but realized implementing even a fraction of it was out of scope for the project. 
  I do not have great prior familiarity of regex beyond knowing the basic syntax and having written simple regexes for other purposes before this, so [regex101](https://regex101.com) was useful for helping me iterate on my patterns via trial and error. As I worked on the regexes I both added strings that should match and false positives that should be avoided to the test bench, which meant I could instantly see whenever the pattern improved or worsened and could quickly iterate.
- The input validation/schema constraint filter was implemented by, based on the vulnerable endpoints in the backend, writing regexes attempting to constrain the input as much as possible while not affecting the intended input space. This required less work, as the regexes used were simple compared to the ones found in the general regex filter.
- The tokenizing detector used is a third-party library, and as such only needed the plumbing for integration into the proxy.


### etc
