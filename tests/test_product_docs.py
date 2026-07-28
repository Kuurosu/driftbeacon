from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_product_direction_documents_positioning_and_boundaries() -> None:
    text = _read("docs/product-direction.md")

    assert "Know exactly what to fix next to reduce production risk" in text
    assert "Scanner output is an input, not the product" in text
    assert "Production Health is a prioritisation and trend metric" in text
    assert "does not prove that a repository or production environment is secure" in text
    assert "Do not build an unreliable clustering algorithm" in text
    assert "Do not use private customer source code" in text
    assert "Explicitly out of scope" in text


def test_pricing_strategy_is_proposed_not_enforced() -> None:
    text = _read("docs/pricing-strategy.md")

    assert "proposed product strategy, not implemented billing behavior" in text
    assert "does not enforce paid plans" in text
    assert "£19 per month" in text
    assert "£79 per month" in text
    assert "£199 per month" in text
    assert "Plan enforcement must be centralised" in text
    assert "not paid-plan enforcement" in text


def test_roadmap_distinguishes_current_mvp_from_planned_features() -> None:
    text = _read("docs/roadmap.md")

    assert "Phase 1: Public Web Scan MVP" in text
    assert "No login, billing, private repositories or scheduled scans" in text
    assert "Billing is not implemented in the current MVP" in text
    assert "Impact simulation must reuse the real scoring model" in text
    assert "Explicitly Out Of Scope For The Current MVP" in text
    assert "multi-tenant production infrastructure" in text


def test_beta_docs_cover_launch_privacy_terms_and_tester_material() -> None:
    checklist = _read("docs/beta-launch-checklist.md")
    privacy = _read("docs/beta-data-and-privacy.md")
    terms = _read("docs/beta-acceptable-use.md")
    invitation = _read("docs/beta-tester-invitation.md")

    assert "DRIFTBEACON_BETA_ACCEPTING_SCANS=false" in checklist
    assert "keyed hash" in privacy
    assert "Report links are public to anyone with the URL" in privacy
    assert "Only submit repositories you are permitted to analyse" in terms
    assert "Would you connect private repositories for continuous monitoring?" in invitation
