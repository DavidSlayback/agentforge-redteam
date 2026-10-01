"""The decoding helper: JSON string values joined in document order; non-JSON falls back."""

from __future__ import annotations

import json

from redteam.oracles.base import Observation
from redteam.oracles.decode import RAW_PATH, SEPARATOR, decoded_values, fold, joined


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
