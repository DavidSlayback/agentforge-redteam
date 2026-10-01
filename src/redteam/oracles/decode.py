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
    except (ValueError, RecursionError):   # not JSON, or nested too deep to walk
        return ((RAW_PATH, text),)
    out: list[tuple[str, str]] = []
    _walk(data, "$", out)
    return tuple(out)


def _walk(node: object, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, str):
        out.append((path, node))
    elif isinstance(node, dict):
        for key, value in node.items():
            _walk(value, f"{path}.{key}", out)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _walk(value, f"{path}[{i}]", out)


def joined(values: DecodedValues) -> str:
    """The decoded values as one text, in document order."""
    return SEPARATOR.join(value for _, value in values)


def fold(text: str) -> str:
    """Unicode compatibility normalization (NFKC) then casefolding: the form markers are matched
    in, and the form echo stripping matches in, so the two can never disagree (owner decision 3)."""
    return unicodedata.normalize("NFKC", text).casefold()
