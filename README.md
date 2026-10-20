# Cyber-project-SQLI
## Problem statement
(problem statement)
## Reference
- [SQLite documentation](https://www.sqlite.org/docs.html)
### Tools/Libraries
- [libinjection](https://github.com/client9/libinjection)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [regex101](https://regex101.com)
## Project documentation
(main documentation, divided into domains)
## Testing documentation
### Website via docker
(how to run the full site)
### Testing filters with echo backend
(how to run the proxy w echo backend)
## Individual contribution
### Martin Erikers (erikers@kth.se)
Like the other group members, I helped plan and decide what the project should be about, including the scope and limitations. The main focus of my personal contribution is the filters used in the proxy to filter out incoming attempts at SQL injection. The first step towards this was researching existing options, and trying to figure out what was reasonable to build for the project. For this reason, I selected a general regex-based filter, an input validation filter (called "schema constraint" despite not directly interacting with the database schema), and also included an existing tokenizing heuristic-based detector ([libinjection](https://github.com/libinjection/libinjection)) for comparison.

I started by implementing utility functions with the purpose of simulating initial operations done on the query by SQLite; to make sure the string I was writing rules against looked the same as it does to the SQLite parser. 
- The regex-based filter was then implemented by, at first, looking up the most common injection approaches and writing basic regexes that would catch them. Following this, I used [sqlmap](https://github.com/sqlmapproject/sqlmap) as an "adversary", running it against my filter between every update to figure out what I needed to catch next, or if I caused a regression by accident. I also used -filter rule list thingy- for inspiration. I do not have great prior familiarity of regex beyond knowing the basic syntax and having written simple regexes for other purposes before this, so [regex101](https://regex101.com) was useful for helping me iterate on my patterns via trial and error. As I worked on the regexes I both added strings that should match and false positives that should be avoided to the integrated test bench, which meant I could instantly see whenever the pattern improved or worsened and quickly iterate.
- The input validation filter was implemented by, based on the vulnerable endpoints in the backend, writing regexes to try to constrain the input as much as possible while not affecting the intended input space. This required less work, as the regexes used were simple compared to the ones found in the general regex filter.
- The tokenizing detector is a third-party library, and as such only needs importing and integrating into the proxy.


### etc
