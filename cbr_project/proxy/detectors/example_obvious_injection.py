"""EXAMPLE detector: obvious SQL injection (tautology, UNION, stacked write, quote+comment) -> MALICIOUS."""

from . import Severity, words

_WRITES = ("drop", "delete", "insert", "update")


def _lstrip_quote(text):
    """Drop one leading single quote (the optional quote in ' OR '1)."""
    return text[1:] if text.startswith("'") else text


def _quote_then_comment(value):
    """A single quote followed (after any spaces) by -- or # — a classic bypass."""
    i = value.find("'")
    while i != -1:
        rest = value[i + 1:].lstrip()
        if rest.startswith("--") or rest.startswith("#"):
            return True
        i = value.find("'", i + 1)
    return False


def _quoted_tautology(low):
    """A quote, then OR/AND, then a digit: ' OR 1   /   ' OR '1."""
    i = low.find("'")
    while i != -1:
        rest = low[i + 1:].lstrip()
        for keyword in ("or", "and"):
            if rest.startswith(keyword):
                after = _lstrip_quote(rest[len(keyword):].lstrip())
                if after[:1].isdigit():
                    return True
        i = low.find("'", i + 1)
    return False


def _digits_equal_digits(text):
    """True if `text` starts with  <digits> = <digits>  (spaces allowed)."""
    rest = text.lstrip()
    digits = rest[:len(rest) - len(rest.lstrip("0123456789"))]
    if not digits:
        return False
    rest = rest[len(digits):].lstrip()
    if not rest.startswith("="):
        return False
    rest = rest[1:].lstrip()
    return rest[:1].isdigit()


def _bare_equality(low):
    """A standalone OR/AND followed by  N = N  — e.g. OR 1=1 (no quote needed)."""
    for keyword in ("or", "and"):
        i = low.find(keyword)
        while i != -1:
            before = low[i - 1] if i > 0 else ""
            after = low[i + len(keyword):]
            standalone = not (before.isalnum() or before == "_") and not (
                after[:1].isalnum() or after[:1] == "_")
            if standalone and _digits_equal_digits(after):
                return True
            i = low.find(keyword, i + 1)
    return False


def _union_select(low):
    """The words UNION and SELECT, adjacent."""
    token_pairs = zip(words(low), words(low)[1:])
    return any(a == "union" and b == "select" for a, b in token_pairs)


def _stacked_write(low):
    """A ';' followed (after any spaces) by DROP / DELETE / INSERT / UPDATE."""
    i = low.find(";")
    while i != -1:
        rest = low[i + 1:].lstrip()
        for keyword in _WRITES:
            if rest.startswith(keyword):
                nxt = rest[len(keyword):][:1]
                if not (nxt.isalnum() or nxt == "_"):  # whole word
                    return True
        i = low.find(";", i + 1)
    return False


def check_value(value):
    low = value.lower()
    if _quote_then_comment(value):
        return Severity.MALICIOUS, "quote then comment"
    if _quoted_tautology(low):
        return Severity.MALICIOUS, "quoted tautology"
    if _bare_equality(low):
        return Severity.MALICIOUS, "boolean equality (e.g. OR 1=1)"
    if _union_select(low):
        return Severity.MALICIOUS, "UNION SELECT"
    if _stacked_write(low):
        return Severity.MALICIOUS, "stacked write statement"
    return Severity.CLEAN, ""
