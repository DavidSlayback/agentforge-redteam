"""The HTML dashboard renders from a store and escapes content."""

from __future__ import annotations

from pathlib import Path

from redteam.observability.dashboard import render_html
from redteam.store.store import Store


def test_render_html_on_empty_store(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    html = render_html(store)
    assert "<!doctype html>" in html
    assert "AgentForge Red Team" in html
    assert "OWASP coverage" in html and "Findings" in html
    store.close()


def test_render_html_shows_a_finding_and_escapes(tmp_path: Path) -> None:
    store = Store.open(tmp_path / "s.db")
    with store.transaction():
        store.insert("findings", {
            "finding_id": "F-1", "title": "t",
            "primary_category": "inj</td><script>alert(1)</script>", "severity_score": 8.1,
            "status": "new", "dedup_key": "k", "updated_at": "2026-09-28",
        })
    html = render_html(store)
    assert "F-1" in html
    assert "<script>alert(1)</script>" not in html   # rendered field is escaped, not injected
    assert "&lt;script&gt;" in html
    store.close()
