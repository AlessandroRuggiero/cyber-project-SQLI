"""
Blocks any query that doesn't fit the schema for the targeted db endpoint.
Annoyingly, it basically requires manually annotating all api routes that send a db call, and if there are vulnerable routes without a strict format, this will not help.
An assumption could be made that the frontend should prevent legitimate users from submitting invalid information, so any queries not matching are intentionally bypassing the frontend and therefore suspicious?

Unfortunately, while most db queries follow a relatively strict format, the "password" login field is vulnerable in this backend.
Other than possibly a max/min length, there probably shouldn't be any more restrictions to passwords for security reasons.
"""

import re

from cbr_project.proxy.detector import Location


# Arbitrarily chose to limit to positive integers in a reasonable span, sqlite supports larger/negative integers
def is_valid_id(value: str) -> bool:
    if value == "":
        return False
    try:
        num = int(value)
        return num > 0 and num < 2147483647
    except ValueError:
        return False


# Matches name-like strings, might work for both people and restaurants idk
# Currently rejects a whole bunch of valid names
# Annoyingly, allowing O'Brien or Tom's Diner also happens to let by the ' character; easier to mitigate than without the schema yet definitely an issue
def is_valid_name(value: str) -> bool:
    if value == "":
        return False
    return re.fullmatch(r"([A-Z][a-zA-Z]+)( [A-Z][a-zA-Z]+)*", str(value)) is not None


# Incredibly naive email matcher, but at least it'll probably not be injectable
# basically anything123@whatever.alright
def is_valid_email(value: str) -> bool:
    if value == "":
        return False
    return re.fullmatch(r"([a-zA-Z0-9]+)@([a-zA-Z]+)\.([a-zA-Z]+)", str(value)) is not None


# Clumsy implementation, could be better in so many ways
def follows_schema(inputs: list[tuple[Location, str, str]]) -> bool:
    for x in inputs:
        if x[0] == "form":
            if x[1] == "id":
                if not is_valid_id(x[2]):
                    return False
            elif x[1] == "email":
                if not is_valid_email(x[2]):
                    return False
            elif x[1] == "name":
                if not is_valid_name(x[2]):
                    return False
    return True
