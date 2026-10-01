"""The decoding helper: JSON string values joined in document order; non-JSON falls back."""

from __future__ import annotations

import json

from redteam.oracles.decode import RAW_PATH, SEPARATOR, decoded_values, joined


def test_string_values_are_decoded_in_document_order_with_their_paths() -> None:
    body = json.dumps({"a": 'quote " here', "b": [{"c": "line\nbreak"}, "back\\slash"], "d": "Ä"},
                      ensure_ascii=True)
    assert decoded_values(body) == (
        ("$.a", 'quote " here'), ("$.b[0].c", "line\nbreak"), ("$.b[1]", "back\\slash"), ("$.d", "Ä"),
    )


def test_keys_numbers_booleans_and_null_are_not_decoded() -> None:
    body = json.dumps({"key_only": 1, "flag": True, "none": None, "ratio": 0.5, "s": "kept"})
    assert decoded_values(body) == (("$.s", "kept"),)
    assert decoded_values("{}") == ()
    assert decoded_values("42") == ()


def test_a_top_level_json_string_decodes_to_itself() -> None:
    assert decoded_values(json.dumps('a "b"')) == (("$", 'a "b"'),)


def test_a_body_that_is_not_json_falls_back_to_the_raw_text() -> None:
    for text in ("<html><body>Bad gateway</body></html>", "plain text", '{"truncated": "x', ""):
        assert decoded_values(text) == ((RAW_PATH, text),)


def test_joined_uses_the_separator_in_document_order() -> None:
    assert joined((("$.a", "one"), ("$.b", "two"))) == f"one{SEPARATOR}two"
    assert joined(()) == ""
