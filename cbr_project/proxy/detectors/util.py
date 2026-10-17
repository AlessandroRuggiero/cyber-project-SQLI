"""
Contains a bit of shared functionality between detectors
"""

import re


# sqlite treats comments as whitespace
# https://www.sqlite.org/lang_comment.html
def remove_comments(input: str) -> tuple[str, int]:
    return re.subn(r"(\/\*[\s\S]*?\*\/)|(--.+\n?)", " ", input)


# sqlite treats any whitespace the same
# todo: replace \s with actual sqlite whitespace codepoints
def normalize_whitespace(input: str) -> tuple[str, int]:
    return re.subn(r"\s+", " ", input)


# normalization pass
# follows the transformations happening to the string as it is passed through backend to sqlite
def normalize(input: str) -> tuple[str, int, int]:
    # inputs are url-decoded etc as appropriate based on origin in proxy
    input = input.strip()  # explicitly stripped, see backend code
    # query is sent to sqlite, which then removes comments and normalizes whitespace
    input, removed_comments = remove_comments(input)
    input, removed_whitespace = normalize_whitespace(input)
    input = input.lower()  # sqlite is case-insensitive
    return input, removed_comments, removed_whitespace
