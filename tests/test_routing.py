"""Category routing policy: kind per category, and the deterministic-only (campaign-refused) set."""

from __future__ import annotations

from redteam.routing import execution_kind, is_deterministic_only


def test_execution_kind_maps_each_category() -> None:
    assert execution_kind("broken-object-authorization") == "authz"
    assert execution_kind("broken-authentication") == "authz"
    assert execution_kind("indirect-injection") == "document"
    assert execution_kind("prompt-injection") == "direct"
    assert execution_kind("something-new") == "direct"      # default is a direct turn


def test_authz_categories_are_deterministic_only() -> None:
    assert is_deterministic_only("broken-object-authorization")
    assert is_deterministic_only("broken-authentication")
    assert not is_deterministic_only("prompt-injection")
    assert not is_deterministic_only("indirect-injection")
