"""The decoded content of a response body: what the answer-grading oracles match against.

The target answers in JSON, and a JSON serializer escapes quotes, backslashes and control
characters inside string values (some also escape non-ASCII and angle brackets). The values the
oracles look for — the injection marker, foreign canaries, an echoed payload — are decoded
strings, so they are matched against the body's decoded string values, not its raw text.

Decoding rule (refactor #2): every string value in the parsed body, in document order, with its
JSON path. Keys, numbers, booleans and null are not included. A top-level JSON string decodes to
itself. A body that does not parse as JSON (an HTML error page, plain text, malformed JSON) falls
back to the raw text, which is exactly what the oracles read before decoding existed.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Callable

# Joins decoded values into one text. A newline keeps adjacent values from running together.
SEPARATOR = "\n"
# The path of the single value a non-JSON body decodes to.
RAW_PATH = "(raw text)"

DecodedValues = tuple[tuple[str, str], ...]   # ((json path, decoded string value), ...)


def decoded_values(text: str) -> DecodedValues:
    """Every string value of the JSON body ``text`` as (path, value) in document order, or
    ``((RAW_PATH, text),)`` when ``text`` is not JSON."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):   # not JSON, or nested deeper than the parser accepts
        return ((RAW_PATH, text),)
    return _string_values(data)


# A path is built only for a value that is emitted: each stack entry carries a link
# (segment, parent link) instead of a path string, so deep nesting costs no quadratic copying.
_Link = tuple[str, "_Link"] | None


def _string_values(root: object) -> DecodedValues:
    """The string values under ``root`` with their paths, in document order. Iterative, so any
    depth the JSON parser accepts is walked without recursion."""
    out: list[tuple[str, str]] = []
    stack: list[tuple[object, _Link]] = [(root, None)]
    while stack:
        node, link = stack.pop()
        if isinstance(node, str):
            out.append((_path(link), node))
        elif isinstance(node, dict):
            stack.extend((value, (f".{key}", link)) for key, value in reversed(node.items()))
        elif isinstance(node, list):
            stack.extend((value, (f"[{i}]", link)) for i, value in reversed(list(enumerate(node))))
    return tuple(out)


def _path(link: _Link) -> str:
    segments: list[str] = []
    while link is not None:
        segment, link = link
        segments.append(segment)
    return "$" + "".join(reversed(segments))


def joined(values: DecodedValues) -> str:
    """The decoded values as one text, in document order."""
    return SEPARATOR.join(value for _, value in values)


def where(values: DecodedValues, matches: Callable[[str], bool]) -> str:
    """Where in the body a match was found, for an oracle's detail (owner decision 6): the path of
    the first decoded value that matches on its own, or a note that the match spans values (the
    oracles match the joined text, so a hit can straddle the separator)."""
    for path, value in values:
        if matches(value):
            return f"in {path}"
    return "across decoded values"


def fold(text: str) -> str:
    """Unicode compatibility normalization (NFKC) then casefolding: the form markers are matched
    in, and the form echo stripping matches in, so the two can never disagree (owner decision 3)."""
    return unicodedata.normalize("NFKC", text).casefold()
