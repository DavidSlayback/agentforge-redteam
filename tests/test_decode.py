"""The decoding helper: JSON string values joined in document order; non-JSON falls back."""

from __future__ import annotations

import json

from redteam.oracles.base import Observation
from redteam.oracles.decode import RAW_PATH, SEPARATOR, decoded_values, fold, joined, where


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


def test_a_top_level_json_string_decodes_to_itself() -> None:
    assert decoded_values(json.dumps('a "b"')) == (("$", 'a "b"'),)
    obs = Observation(response_text=json.dumps('line\none'), injection_marker="one", status_code=200)
    assert obs.decoded_text == "line\none"


def test_a_bare_scalar_body_is_graded_on_its_raw_text() -> None:
    # A bare number, boolean or null has no string value, but it is the whole answer: grading it
    # as no content would hide e.g. a numeric canary. It falls back to the raw text.
    for text in ("12345678901234", "true", "null", " 0.5 "):
        assert decoded_values(text) == ((RAW_PATH, text),)
    obs = Observation(response_text="12345678901234", foreign_canaries=frozenset({"12345678901234"}))
    assert obs.decoded_text == "12345678901234"


def test_a_body_that_is_not_json_falls_back_to_the_raw_text() -> None:
    for text in ("<html><body>Bad gateway</body></html>", "plain text", '{"truncated": "x', ""):
        assert decoded_values(text) == ((RAW_PATH, text),)


def test_a_deeply_nested_body_the_parser_accepts_is_decoded_without_recursion() -> None:
    depth = 5000   # parses with the C JSON parser; a recursive walk would raise RecursionError
    body = json.dumps({"a": "first"})[:-1] + ', "b": ' + "[" * depth + '"deep"' + "]" * depth + "}"
    values = decoded_values(body)
    assert values[0] == ("$.a", "first")
    assert values[1] == ("$.b" + "[0]" * depth, "deep")
    assert Observation(response_text=body).decoded_text == "first\ndeep"


def test_a_body_nested_beyond_the_parser_falls_back_to_the_raw_text() -> None:
    body = "[" * 200_000 + "]" * 200_000
    assert decoded_values(body) == ((RAW_PATH, body),)


def test_joined_uses_the_separator_in_document_order() -> None:
    assert joined((("$.a", "one"), ("$.b", "two"))) == f"one{SEPARATOR}two"
    assert joined(()) == ""


def test_where_names_the_first_matching_value_or_a_match_across_values() -> None:
    values = (("$.a", "one"), ("$.b", "two"), ("$.c", "two again"))
    assert where(values, lambda v: "two" in v) == "in $.b"
    assert where(values, lambda v: "one\ntwo" in v) == "across decoded values"


def test_fold_is_compatibility_normalization_then_casefold() -> None:
    assert fold("ZZ-Mark") == "zz-mark"
    assert fold("ＺＺ-Ｍ") == "zz-m"          # fullwidth letters
    assert fold("Straße") == "strasse"               # casefold, not lower


def test_an_observation_decodes_its_raw_body_when_the_caller_sets_nothing_else() -> None:
    obs = Observation(response_text=json.dumps({"a": 'x "y"', "b": "z"}))
    assert obs.decoded == (("$.a", 'x "y"'), ("$.b", "z"))
    assert obs.decoded_text == 'x "y"\nz'
    assert Observation(response_text="plain").decoded_text == "plain"
    assert Observation().decoded is None and Observation().decoded_text is None


def test_an_observation_keeps_decoded_values_the_caller_set() -> None:
    obs = Observation(response_text=json.dumps({"a": "echo"}), decoded=(("$.a", " "),))
    assert obs.decoded_text == " "
    assert obs.response_text == '{"a": "echo"}'
