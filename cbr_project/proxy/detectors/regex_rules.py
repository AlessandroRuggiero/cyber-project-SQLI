"""
A detector containing more rules and looped normalization in addition to the naive keyword list
Scoped to sqlite specifically, currently blocks all attempts by sqlmap at --level=5 --risk=3
Sources:
    https://www.sqlite.org/datatype3.html
    https://www.sqlite.org/lang_expr.html
    (more pages in official documentation, was very useful)
Regexes built with:
    https://regex101.com
"""

import re

from . import Severity, util


# matches sqlite statements that can be used to obfuscate other values
def sqlite_char_etc(input: str) -> bool:
    return (
        re.search(
            r"(char|hex|unhex|substr|substring|quote|unicode|printf|format|replace)\((\S+,?)+[)$]?",
            input,
        )
        is not None
    )


# counts usage of special characters, should probably not be used to block by itself
def special_character_count(input: str) -> bool:
    suspicion_sum = 0
    suspicion_sum = suspicion_sum + input.count(";") * 2
    suspicion_sum = suspicion_sum + input.count("'") * 2
    suspicion_sum = suspicion_sum + input.count("(")
    suspicion_sum = suspicion_sum + input.count(")")
    suspicion_sum = suspicion_sum + input.count("<")
    suspicion_sum = suspicion_sum + input.count(">")

    return suspicion_sum > 10


# matches "and" or "or" followed by a tautology, x =/like/is x
def tautology(input: str) -> bool:
    return re.search(r"\b(?:and|or)\b\s*([\S']{1,40})\s*\b(=|like|is)\b\s*\1", input) is not None


# matches "and", "or", "having", followed by a comparison
def boolean_comparison(input: str) -> bool:
    return (
        re.search(
            r"\b(?:and|or(\s+not)*|having)\b[\s\(]*\S+\s*((not)*\s+like|=|<|>|<>|!=|>=|<=)\s*\S+",
            input,
        )
        is not None
    )


# matches union select or variant
def union_select(input: str) -> bool:
    return re.search(r"\b(union\b( all\b)? select)\b", input) is not None


# matches case when statement
def case_when(input: str) -> bool:
    return re.search(r"(case)\b[\s\S](when)", input) is not None


# matches extension load, should probably always block this one
def load_extension(input: str) -> bool:
    return re.search(r"\bload_extension\s*\(", input) is not None


# matches "in boolean mode"
def in_boolean_mode(input: str) -> bool:
    return re.search(r"\b(in\b\s+boolean\b\s+mode)\b", input) is not None


def apply_rules(input: str) -> tuple[Severity, str]:
    suspicion: int = 0
    severity = Severity.CLEAN
    message: str = ""

    input, removed_comments, removed_whitespace = util.normalize(input)
    if removed_comments > 0:
        suspicion = suspicion + 5
        message += "contains sqlite comments "
    if removed_whitespace > 10:  # idk how much this matters
        suspicion = suspicion + 1

    if special_character_count(input):
        suspicion = suspicion + 2
        message += "contains a large amount of special characters "

    if sqlite_char_etc(input):
        suspicion = suspicion + 5
        message += "contains injected sqlite char() "

    if tautology(input):
        suspicion = suspicion + 5
        message += "contains sql tautology "

    if boolean_comparison(input):
        suspicion = suspicion + 5
        message += "contains boolean comparison "

    if case_when(input):
        suspicion = suspicion + 5
        message += "contains case when statement "

    if union_select(input):
        suspicion = suspicion + 5
        message += "contains union select statement variant "

    if load_extension(input):
        suspicion = suspicion + 100
        message += "tries to load extension "

    if in_boolean_mode(input):
        suspicion = suspicion + 5
        message += "contains in boolean mode statement "

    if suspicion >= 5:
        severity = Severity.MALICIOUS
    elif suspicion >= 2:
        severity = Severity.SUSPICIOUS
    return (severity, message)


def check_value(value: str) -> tuple[Severity, str]:
    return apply_rules(value)
