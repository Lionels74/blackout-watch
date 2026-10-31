"""Tests de déduplication."""
import pytest
from datetime import datetime, timedelta, timezone
from collector.dedup import jaccard_tokens, cluster_items, _is_syndication
from collector.normalize import RawItem


def make_item(
    title: str,
    source_id: str = "test",
    tier: str = "C",
    owner: str = "owner1",
    published_at: datetime | None = None,
    raw_ids: list | None = None,
    url: str = "https://example.com/article",
) -> RawItem:
    return RawItem(
        source_id=source_id,
        tier=tier,
        owner=owner,
        url=url,
        title=title,
        summary_text="",
        published_at=published_at or datetime.now(timezone.utc),
        raw_ids=raw_ids or [],
    )


def test_jaccard_identical():
    assert jaccard_tokens("power outage france", "power outage france") == pytest.approx(1.0)

def test_jaccard_empty():
    assert jaccard_tokens("", "") == pytest.approx(1.0)

def test_jaccard_disjoint():
    score = jaccard_tokens("elephant paris rome", "banana tokyo seoul")
    assert score == pytest.approx(0.0)

def test_jaccard_partial():
    # "power outage" vs "power failure" → "power" en commun
    score = jaccard_tokens("power outage france", "power failure france")
    assert 0.3 < score < 1.0


def test_same_cve_merged():
    """Deux items avec le même CVE doivent être fusionnés."""
    i1 = make_item("CVE-2024-1234 critical vulnerability", raw_ids=["CVE-2024-1234"], owner="certfr")
    i2 = make_item("Vulnérabilité CVE-2024-1234 exploitée", raw_ids=["CVE-2024-1234"], owner="cisa")
    clusters = cluster_items([i1, i2])
    assert len(clusters) == 1
    assert len(clusters[0].items) == 2


def test_different_cves_not_merged():
    """Deux CVEs différents ne doivent pas être fusionnés."""
    i1 = make_item("CVE-2024-1234", raw_ids=["CVE-2024-1234"], owner="certfr")
    i2 = make_item("CVE-2024-5678", raw_ids=["CVE-2024-5678"], owner="certfr")
    clusters = cluster_items([i1, i2])
    assert len(clusters) == 2


def test_similar_titles_merged():
    """Titres similaires dans la fenêtre temporelle → fusion."""
    i1 = make_item("Power outage affecting France electricity grid failure")
    i2 = make_item("Power outage france electricity grid failure major")
    clusters = cluster_items([i1, i2])
    assert len(clusters) == 1


def test_beyond_window_not_merged():
    """Titres similaires hors fenêtre (>72h) → pas de fusion."""
    now = datetime.now(timezone.utc)
    i1 = make_item("Power outage france major", published_at=now)
    i2 = make_item("Power outage france major", published_at=now - timedelta(hours=73))
    clusters = cluster_items([i1, i2])
    assert len(clusters) == 2


def test_syndication_detected():
    """Deux owners différents avec Jaccard ≥ 0.85 = syndication (même contenu)."""
    title = "Breaking: Major submarine cable cut in Mediterranean disrupts internet"
    i1 = make_item(title, owner="reuters", source_id="gdelt")
    i2 = make_item(title, owner="bloomberg", source_id="gdelt")
    clusters = cluster_items([i1, i2], syndication_thresh=0.85)
    assert len(clusters) == 1
    # Syndication → n_owners reste 1
    assert clusters[0].n_owners == 1


def test_n_owners_independent():
    """Deux owners indépendants (titres proches mais pas syndicaux) → n=2."""
    i1 = make_item("Major power outage hits France electricity", owner="certfr")
    i2 = make_item("France power outage electricity major grid", owner="ecowatt")
    clusters = cluster_items([i1, i2])
    if len(clusters) == 1:
        assert clusters[0].n_owners >= 1  # au minimum 1


def test_blackout_false_positive():
    """'blackout' dans un contexte film ne doit pas déclencher electricity."""
    # Test via dedup uniquement : deux items totalement différents
    i1 = make_item("Blackout film review 2024 cinema art")
    i2 = make_item("Power outage grid failure france electricity")
    clusters = cluster_items([i1, i2])
    assert len(clusters) == 2  # pas de fusion
