"""Single source of category routing policy — which execution path each attack category takes,
and which categories the model-driven campaign must refuse.

Kept free of the ``run_*`` functions (the dispatch module maps kind → function), so this module
sits *below* dispatch, campaign, and authz_probe with no import cycle. The canary-gating set
(``NEEDS_CANARY``) stays in the OWASP module — it is OWASP-strategy metadata, already single-sourced.
"""

from __future__ import annotations

# Authorization probes deliberately mismatch credentials/target; they run via the deterministic
# authz track (`redteam authz`), never the model-driven campaign.
AUTHZ_CATEGORIES = frozenset({"broken-object-authorization", "broken-authentication"})
# Indirect injection is an upload+scan document flow rather than a direct HTTP turn.
DOCUMENT_CATEGORIES = frozenset({"indirect-injection"})


def execution_kind(category: str) -> str:
    """Which execution path a category takes: ``authz``, ``document``, or ``direct``."""
    if category in AUTHZ_CATEGORIES:
        return "authz"
    if category in DOCUMENT_CATEGORIES:
        return "document"
    return "direct"


def is_deterministic_only(category: str) -> bool:
    """True for categories that must run via the deterministic authz track. The campaign refuses
    them: routing one through the model-driven path would exercise only StatusOracle and score a
    real authorization break as FAIL ('defense held') — a fake pass.
    """
    return category in AUTHZ_CATEGORIES
