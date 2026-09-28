"""The CLI parses commands and runs the safe ones without any network or key."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.cli import build_parser, main
from redteam.store.store import Store


def test_report_runs_on_a_store(tmp_path: Path, capsys) -> None:
    db = tmp_path / "s.db"
    Store.open(db).close()  # create an empty, migrated store
    rc = main(["--store", str(db), "report"])
    assert rc == 0
    assert "Red Team — status" in capsys.readouterr().out


def test_parser_requires_a_command() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_campaign_maps_categories_to_owasp() -> None:
    args = build_parser().parse_args(
        ["campaign", "--target", "agentforge-w2", "--category", "prompt-injection", "--route", "/v1/x"]
    )
    assert args.category == ["prompt-injection"]
    assert args.route == ["/v1/x"]
    assert args.max_campaigns == 5
