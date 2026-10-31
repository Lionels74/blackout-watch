"""Tests de scoring avec cas dorés calculés à la main."""
import math
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from pathlib import Path

# Chemin vers la config
BASE_DIR = Path(__file__).parent.parent

@pytest.fixture
def scorer():
    """Crée un Scorer avec la config réelle."""
    import json
    from collector.scoring import Scorer
    settings = json.loads((BASE_DIR / "config" / "settings.json").read_text(encoding="utf-8"))
    return Scorer(settings, BASE_DIR / "config" / "zones.json", BASE_DIR / "config" / "dependencies.json")


def test_G_severity_5(scorer):
    """G = severity/5. G(5) = 1.0"""
    assert scorer.G(5) == 1.0

def test_G_severity_1(scorer):
    """G(1) = 0.2"""
    assert scorer.G(1) == pytest.approx(0.2)

def test_G_severity_3(scorer):
    """G(3) = 0.6"""
    assert scorer.G(3) == pytest.approx(0.6)


def test_K_confirmed_tier_A(scorer):
    """Cas doré : confirmed, tier A, n=1 → K = 1.0 * min(1, 1.0 + 0) = 1.0"""
    assert scorer.K("A", "confirmed", 1) == pytest.approx(1.0)

def test_K_unverified_tier_D(scorer):
    """K = 0.35 * (0.3 + 0.1*0) = 0.35 * 0.3 = 0.105"""
    assert scorer.K("D", "unverified", 1) == pytest.approx(0.105)

def test_K_denied(scorer):
    """denied → K = 0 quelle que soit la source"""
    assert scorer.K("A", "denied", 5) == pytest.approx(0.0)

def test_K_probable_tier_C_n2(scorer):
    """K = 0.7 * min(1, 0.6 + 0.1*1) = 0.7 * 0.7 = 0.49"""
    assert scorer.K("C", "probable", 2) == pytest.approx(0.49)

def test_K_n_owners_capped_at_1(scorer):
    """R_adj ne dépasse pas 1.0 même avec beaucoup d'owners."""
    k_n1 = scorer.K("A", "confirmed", 1)
    k_n100 = scorer.K("A", "confirmed", 100)
    assert k_n1 == k_n100  # R=1.0 déjà plafonné


def test_P_same_zone(scorer):
    """P = 1.0 si la zone est affectée."""
    assert scorer.P(["france"], "france") == pytest.approx(1.0)

def test_P_global_single_country(scorer):
    """Global avec 1 pays = 0.6."""
    assert scorer.P(["france"], "global", n_countries=1) == pytest.approx(0.6)

def test_P_global_two_countries(scorer):
    """Global avec ≥2 pays = 1.0."""
    assert scorer.P(["france", "germany"], "global", n_countries=2) == pytest.approx(1.0)

def test_P_quebec_to_canada(scorer):
    """Québec → Canada = 0.7."""
    assert scorer.P(["quebec"], "canada") == pytest.approx(0.7)

def test_P_canada_to_quebec(scorer):
    """Canada → Québec = 0.7."""
    assert scorer.P(["canada"], "quebec") == pytest.approx(0.7)

def test_P_default(scorer):
    """Zone non liée → 0.05."""
    assert scorer.P(["mauritius"], "france") == pytest.approx(0.05)


def test_P_hazard_global_single_non_systemic(scorer):
    """Hazard, 1 pays non systémique → P(global) = 0.15."""
    assert scorer.P(["global"], "global", n_countries=1,
                    kind="hazard", affected_countries=["VU"]) == pytest.approx(0.15)


def test_P_hazard_global_single_systemic_node(scorer):
    """Hazard touchant 1 seul nœud systémique → P(global) = 0.15 (pas 0.6)."""
    assert scorer.P(["global"], "global", n_countries=1,
                    kind="hazard", affected_countries=["DE"]) == pytest.approx(0.15)


def test_P_hazard_global_two_systemic_nodes(scorer):
    """Hazard touchant ≥2 nœuds systémiques (CN+JP) → P(global) = 0.6."""
    assert scorer.P(["global"], "global", n_countries=2,
                    kind="hazard", affected_countries=["CN", "JP"]) == pytest.approx(0.6)


def test_P_hazard_global_many_non_systemic_countries(scorer):
    """Hazard 18 pays non-systemiques sans noeud ni point de passage → P(global) = 0.15."""
    # Aucun de ces pays n'est dans interconnected_countries ni adjacent a un chokepoint
    many = ["VU", "PG", "SB", "FJ", "TO", "CM", "NG", "SD", "SS",
            "ET", "MZ", "AU", "BR", "PH", "TZ", "TH", "MX", "NE"]
    assert scorer.P(["global"], "global", n_countries=18,
                    kind="hazard", affected_countries=many) == pytest.approx(0.15)


def test_P_incident_global_unchanged(scorer):
    """Incident (non-hazard) single country → P(global) = 0.6 (comportement inchangé)."""
    assert scorer.P(["france"], "global", n_countries=1,
                    kind="incident") == pytest.approx(0.6)


def test_P_incident_global_two_countries_is_1(scorer):
    """Incident ≥2 pays → P(global) = 1.0 (comportement inchangé)."""
    assert scorer.P(["france", "germany"], "global", n_countries=2,
                    kind="incident") == pytest.approx(1.0)


def test_I_national(scorer):
    assert scorer.I("national") == pytest.approx(1.0)

def test_I_regional(scorer):
    assert scorer.I("regional") == pytest.approx(0.7)

def test_I_local(scorer):
    assert scorer.I("local") == pytest.approx(0.4)

def test_I_non_critical(scorer):
    assert scorer.I("non_critical") == pytest.approx(0.2)


def test_D_unknown(scorer):
    """Durée inconnue → D = 0.8."""
    assert scorer.D(None) == pytest.approx(0.8)

def test_D_zero(scorer):
    """D(0) = 0.6 + 0.4 * min(1, ln(1)/ln(73)) = 0.6 + 0 = 0.6"""
    assert scorer.D(0) == pytest.approx(0.6)

def test_D_72h(scorer):
    """D(72) = 0.6 + 0.4 * min(1, ln(73)/ln(73)) = 0.6 + 0.4 = 1.0"""
    assert scorer.D(72) == pytest.approx(1.0)


def test_S_no_propagation(scorer):
    assert scorer.S(["france"], []) == pytest.approx(1.0)

def test_S_multi_zone(scorer):
    assert scorer.S(["france", "canada"], []) == pytest.approx(1.2)

def test_S_cascade(scorer):
    assert scorer.S(["france", "canada"], ["electricity"]) == pytest.approx(1.4)


def test_T_no_decay(scorer):
    """Événement très récent → T ≈ 1."""
    now = datetime.now(timezone.utc)
    t = scorer.T("cyber", now, False, "confirmed")
    assert t == pytest.approx(1.0, abs=0.01)

def test_T_half_life(scorer):
    """À t = h_c (72h pour cyber), T = 2^(-1) = 0.5."""
    t72h_ago = datetime.now(timezone.utc) - timedelta(hours=72)
    t = scorer.T("cyber", t72h_ago, False, "confirmed")
    assert t == pytest.approx(0.5, abs=0.02)

def test_T_resolved_faster_decay(scorer):
    """Resolved → h_c/3 = 24h pour cyber."""
    t24h_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    t = scorer.T("cyber", t24h_ago, False, "resolved")
    assert t == pytest.approx(0.5, abs=0.02)

def test_T_ongoing_stays_1(scorer):
    """Confirmed + ongoing → T = 1.0 dans la fenêtre."""
    t5d_ago = datetime.now(timezone.utc) - timedelta(days=5)
    t = scorer.T("cyber", t5d_ago, True, "confirmed")
    assert t == pytest.approx(1.0)


def test_event_score_capped_100(scorer):
    """Le score d'un événement ne dépasse jamais 100."""
    now = datetime.now(timezone.utc)
    incident = {
        "id": "test-001",
        "severity": 5,
        "category": "electricity",
        "status": "confirmed",
        "is_ongoing": True,
        "published_at": now.isoformat(),
        "secondary_categories": ["cyber"],
        "affected": {
            "countries": ["FR"],
            "zones": ["france"],
            "infrastructure_type": "national",
        },
        "confidence": {"max_tier": "A", "n_owners": 5},
    }
    score, factors = scorer.event_score(incident, "france")
    assert 0 <= score <= 100


def test_event_score_denied_zero(scorer):
    """Un incident denied doit avoir un score très proche de 0 (K=0)."""
    now = datetime.now(timezone.utc)
    incident = {
        "id": "test-denied",
        "severity": 5,
        "category": "electricity",
        "status": "denied",
        "is_ongoing": False,
        "published_at": now.isoformat(),
        "secondary_categories": [],
        "affected": {
            "countries": ["FR"],
            "zones": ["france"],
            "infrastructure_type": "national",
        },
        "confidence": {"max_tier": "A", "n_owners": 1},
    }
    score, _ = scorer.event_score(incident, "france")
    assert score == pytest.approx(0.0)


def test_category_score_floor_unverified(scorer):
    """Si tous les événements sont unverified, le score est plafonné à 39."""
    now = datetime.now(timezone.utc)
    # Créer plusieurs incidents unverified avec des scores élevés
    incidents = []
    for i in range(5):
        incidents.append({
            "id": f"inc_{i}",
            "severity": 5,
            "category": "electricity",
            "status": "unverified",
            "is_ongoing": True,
            "published_at": now.isoformat(),
            "secondary_categories": [],
            "affected": {
                "countries": ["FR"],
                "zones": ["france"],
                "infrastructure_type": "national",
            },
            "confidence": {"max_tier": "C", "n_owners": 1},
        })

    score, caps, floors, _ = scorer.category_score(incidents, "france", "electricity")
    assert score <= 39
    assert "unverified_cap_39" in caps


def test_category_score_floor_no_authoritative(scorer):
    """Score ≥ 80 sans tier A/B → plafonné à 79."""
    now = datetime.now(timezone.utc)
    incidents = []
    for i in range(10):
        incidents.append({
            "id": f"inc_{i}",
            "severity": 5,
            "category": "electricity",
            "status": "probable",
            "is_ongoing": True,
            "published_at": now.isoformat(),
            "secondary_categories": [],
            "affected": {
                "countries": ["FR"],
                "zones": ["france"],
                "infrastructure_type": "national",
            },
            "confidence": {"max_tier": "C", "n_owners": 3},
        })

    score, caps, floors, _ = scorer.category_score(incidents, "france", "electricity")
    assert score <= 79


def test_zone_index_formula(scorer):
    """Vérification de la formule Z = max(B, 0.7 * max_c S_c)."""
    # electricity=60, tous les autres=0
    cat_scores = {
        "electricity": 60.0, "cables": 0.0, "finance": 0.0,
        "cyber": 0.0, "logistics": 0.0, "geopolitics": 0.0
    }
    z_raw, z_prime = scorer.zone_index(cat_scores, 0.0)
    # 0.7 * 60 = 42 > B (weighted average ≈ 60*25/100 = 15)
    assert z_raw == pytest.approx(42.0, abs=1.0)


def test_convergence_index_zero_below_threshold(scorer):
    """CI = 0 si les scores de catégorie sont < 20."""
    cat_scores = {
        "electricity": 10.0, "cables": 5.0, "finance": 8.0,
        "cyber": 3.0, "logistics": 12.0, "geopolitics": 0.0
    }
    ci, links = scorer.convergence_index(cat_scores, [], "france")
    assert ci == pytest.approx(0.0)


def test_level_thresholds(scorer):
    from collector.scoring import get_level
    assert get_level(0) == "NORMAL"
    assert get_level(19) == "NORMAL"
    assert get_level(20) == "VIGILANCE"
    assert get_level(39) == "VIGILANCE"
    assert get_level(40) == "PRÉALERTE"
    assert get_level(59) == "PRÉALERTE"
    assert get_level(60) == "ALERTE ÉLEVÉE"
    assert get_level(79) == "ALERTE ÉLEVÉE"
    assert get_level(80) == "CRITIQUE"
    assert get_level(100) == "CRITIQUE"


# ------------------------------------------------------------------ #
# Tests vulnerability cap                                              #
# ------------------------------------------------------------------ #

def test_vulnerability_only_category_capped_at_19(scorer):
    """100 avis de vulnérabilité tier-A confirmés → cyber plafonné à 19 (NORMAL)."""
    now = datetime.now(timezone.utc)
    incidents = []
    for i in range(100):
        incidents.append({
            "id": f"vuln_{i}",
            "kind": "vulnerability",
            "severity": 2,
            "category": "cyber",
            "status": "confirmed",
            "is_ongoing": True,
            "published_at": now.isoformat(),
            "secondary_categories": [],
            "affected": {
                "countries": ["FR"],
                "zones": ["france"],
                "infrastructure_type": "non_critical",
            },
            "confidence": {"max_tier": "A", "n_owners": 1},
        })
    score, caps, floors, _ = scorer.category_score(incidents, "france", "cyber")
    assert score <= 19
    assert "vulnerability_cap_19" in caps


def test_mixed_vulnerability_incident_no_vuln_cap(scorer):
    """Mélange vulnerability + 1 incident confirmed tier-A → pas de cap vulnerability."""
    now = datetime.now(timezone.utc)
    incidents = [
        {
            "id": "real_incident",
            "kind": "incident",
            "severity": 4,
            "category": "cyber",
            "status": "confirmed",
            "is_ongoing": True,
            "published_at": now.isoformat(),
            "secondary_categories": [],
            "affected": {"countries": ["FR"], "zones": ["france"], "infrastructure_type": "national"},
            "confidence": {"max_tier": "A", "n_owners": 3},
        }
    ]
    score, caps, _, _ = scorer.category_score(incidents, "france", "cyber")
    assert "vulnerability_cap_19" not in caps
    assert score > 0


# ------------------------------------------------------------------ #
# Tests CoI : guards F=0 et C=0                                       #
# ------------------------------------------------------------------ #

def test_coi_f0_returns_zero(scorer):
    """F=0 (aucune source collectée dans les 3h) → CoI=0."""
    # zone=quebec n'a aucune source dans sources.json
    coi, Q, F, C, covered, has_src = scorer.confidence_index(
        [], "quebec", {}, []
    )
    assert F == 0.0
    assert coi == 0.0


def test_coi_c0_returns_zero(scorer):
    """Zone avec sources mais aucune catégorie couverte → CoI=0."""
    # Simuler F > 0 mais aucune catégorie trouvée
    # Impossible avec les vrais sources.json sauf zone sans catégorie couverte
    # On teste directement avec source_health vide (F=0 du coup)
    sources = [{"id": "test_src", "enabled": True, "zones_hint": ["france"],
                "default_category": "cyber"}]
    # health vide → last_success_ts absent → F=0
    coi, Q, F, C, covered, has_src = scorer.confidence_index(
        [], "france", {}, sources
    )
    assert F == 0.0
    assert coi == 0.0
    assert has_src is True


def test_coi_f0_if_all_sources_stale(scorer):
    """Sources avec last_success_ts > 3h → F=0 → CoI=0."""
    from datetime import timedelta
    sources = [{"id": "src_stale", "enabled": True, "zones_hint": ["france"],
                "default_category": "cyber"}]
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    health = {"src_stale": {"last_success_ts": old_ts, "consecutive_failures": 0}}
    coi, Q, F, C, covered, has_src = scorer.confidence_index(
        [], "france", health, sources
    )
    assert F == 0.0
    assert coi == 0.0


# ------------------------------------------------------------------ #
# Tests coverage status                                                #
# ------------------------------------------------------------------ #

def test_coverage_non_couvert_when_no_zone_sources(scorer):
    """Zone sans source → has_zone_sources=False → status=non_couvert."""
    coi, Q, F, C, covered, has_src = scorer.confidence_index(
        [], "quebec", {}, []
    )
    assert has_src is False
    assert F == 0.0


def test_coverage_status_in_compute_all(scorer):
    """compute_all : zone sans sources → coverage.status = non_couvert, index = None."""
    sources = []  # aucune source pour aucune zone
    result = scorer.compute_all([], {}, sources)
    for zone in ["france", "global", "canada", "quebec", "mauritius"]:
        z = result["zones"][zone]
        assert z["coverage"]["status"] == "non_couvert"
        assert z["index"] is None
        assert z["level"] is None


# ------------------------------------------------------------------ #
# Tests freshness (stale / stale_warning)                              #
# ------------------------------------------------------------------ #

def test_freshness_no_last_run_not_stale(scorer):
    """Pas de last_successful_run → stale=False, stale_warning=False."""
    result = scorer.compute_all([], {}, [], last_successful_run_ts=None)
    assert result["stale"] is False
    assert result["stale_warning"] is False


def test_freshness_recent_run_not_stale(scorer):
    """Run < 3h → stale=False, stale_warning=False."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    result = scorer.compute_all([], {}, [], last_successful_run_ts=ts)
    assert result["stale"] is False
    assert result["stale_warning"] is False


def test_freshness_4h_is_warning(scorer):
    """Run il y a 4h → stale_warning=True, stale=False."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat()
    result = scorer.compute_all([], {}, [], last_successful_run_ts=ts)
    assert result["stale_warning"] is True
    assert result["stale"] is False


def test_freshness_13h_is_stale(scorer):
    """Run il y a 13h → stale=True, stale_warning=False."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=13)).isoformat()
    result = scorer.compute_all([], {}, [], last_successful_run_ts=ts)
    assert result["stale"] is True
    assert result["stale_warning"] is False


# ------------------------------------------------------------------ #
# Tests hazard global cap                                              #
# ------------------------------------------------------------------ #

def _make_gdacs_hazard(idx: str, country: str, zones: list, alert: str = "Green") -> dict:
    """Fabrique un incident GDACS hazard minimal."""
    sev = {"Green": 1, "Orange": 2, "Red": 4}.get(alert, 1)
    return {
        "id": f"gdacs_{idx}",
        "kind": "hazard",
        "severity": sev,
        "category": "logistics",
        "status": "probable",
        "is_ongoing": True,
        "published_at": datetime.now(timezone.utc).isoformat(),
        "secondary_categories": ["electricity"],
        "affected": {
            "countries": [country],
            "zones": zones,
            "infrastructure_type": "non_critical",
        },
        "confidence": {"max_tier": "B", "n_owners": 1},
        "reports": [{"source_id": "gdacs"}],
        "extra": {"alert_level": alert},
    }


def test_21_green_hazards_global_normal(scorer):
    """21 hazards green/orange hors zones surveillées → global logistics ≤ 19 (NORMAL).
    Avec P=0.15 le score accumulé reste dans NORMAL sans même atteindre le cap hazard_39."""
    incidents = []
    # 10 séismes Vanuatu Green (VU → global uniquement)
    for i in range(10):
        incidents.append(_make_gdacs_hazard(f"vu_{i}", "VU", ["global"], "Green"))
    # 6 feux Sudan Green (SD → global)
    for i in range(6):
        incidents.append(_make_gdacs_hazard(f"sd_{i}", "SD", ["global"], "Green"))
    # 5 cyclones Philippines Orange (PH → global)
    for i in range(5):
        incidents.append(_make_gdacs_hazard(f"ph_{i}", "PH", ["global"], "Orange"))

    score, caps, floors, _ = scorer.category_score(incidents, "global", "logistics")
    assert score <= 19, f"score={score} doit être ≤ 19 (NORMAL) avec P=0.15"


def test_hazard_cap_39_applied_when_mass_red_hazards(scorer):
    """50 hazards Red (sans nœud systémique) → score brut > 39 → cap hazard_cap_39 appliqué."""
    incidents = []
    for i in range(50):
        incidents.append(_make_gdacs_hazard(f"ph_red_{i}", "PH", ["global"], "Red"))

    score, caps, _, _ = scorer.category_score(incidents, "global", "logistics")
    assert score <= 39, f"score={score} doit être ≤ 39 (cap hazard)"
    assert "hazard_cap_39" in caps


def test_hazard_cyclone_rouge_mauritius_floor_not_global(scorer):
    """Cyclone Red SWIndian (mauritius+global) :
    - mauritius logistics ≥ 50 (GDACS floor)
    - global logistics < 40 (P=0.15 car MU non systémique)
    """
    cyclone = _make_gdacs_hazard("swio_red", "SWIO", ["mauritius", "global"], "Red")
    # SWIO n'est pas dans systemic_nodes, n_countries=1 → P(global)=0.15

    # Test mauritius
    score_mu, _, floors_mu, _ = scorer.category_score([cyclone], "mauritius", "logistics")
    assert score_mu >= 50, f"mauritius={score_mu} doit être ≥ 50 (gdacs_red_floor)"
    assert "gdacs_red_floor_50" in floors_mu

    # Test global
    score_gl, caps_gl, _, _ = scorer.category_score([cyclone], "global", "logistics")
    assert score_gl < 40, f"global={score_gl} doit rester < 40 (P=0.15)"


def test_P_hazard_global_chokepoint_suez(scorer):
    """Hazard touchant l'Egypte (adjacente au Canal de Suez) → P(global) = 0.6."""
    assert scorer.P(["global"], "global", n_countries=1,
                    kind="hazard", affected_countries=["EG"]) == pytest.approx(0.6)


def test_P_hazard_global_chokepoint_hormuz(scorer):
    """Hazard touchant l'Iran (adjacent Ormuz) → P(global) = 0.6."""
    assert scorer.P(["global"], "global", n_countries=1,
                    kind="hazard", affected_countries=["IR"]) == pytest.approx(0.6)


def test_hazard_orange_mauritius_electricity_floor(scorer):
    """Cyclone Orange sur mauritius → electricity floor >= 30."""
    cyclone = _make_gdacs_hazard("swio_orange", "SWIO", ["mauritius", "global"], "Orange")
    score_el, _, floors_el, _ = scorer.category_score([cyclone], "mauritius", "electricity")
    assert score_el >= 30, f"mauritius electricity={score_el} doit etre >=30"
    assert "gdacs_orange_floor_30" in floors_el


def test_hazard_red_mauritius_electricity_floor(scorer):
    """Cyclone Red sur mauritius → electricity floor >= 50."""
    cyclone = _make_gdacs_hazard("swio_red2", "SWIO", ["mauritius", "global"], "Red")
    score_el, _, floors_el, _ = scorer.category_score([cyclone], "mauritius", "electricity")
    assert score_el >= 50, f"mauritius electricity={score_el} doit etre >=50"
    assert "gdacs_red_floor_50" in floors_el


def test_hazard_no_country_global_only(scorer):
    """Incident hazard zones=['global'] + countries=[] → impact minimal sur france/mauritius.
    Simule le comportement apres fix 1a : GDACS sans pays → global uniquement."""
    now = datetime.now(timezone.utc)
    inc = {
        "id": "gdacs_nozone",
        "kind": "hazard",
        "severity": 2,
        "category": "logistics",
        "status": "probable",
        "is_ongoing": True,
        "published_at": now.isoformat(),
        "secondary_categories": [],
        "affected": {
            "countries": [],
            "zones": ["global"],
            "infrastructure_type": "non_critical",
        },
        "confidence": {"max_tier": "B", "n_owners": 1},
        "reports": [{"source_id": "gdacs"}],
        "extra": {"alert_level": "Orange"},
    }
    score_fr, _, _, _ = scorer.category_score([inc], "france", "logistics")
    score_mu, _, _, _ = scorer.category_score([inc], "mauritius", "logistics")
    score_gl, _, _, _ = scorer.category_score([inc], "global", "logistics")
    assert score_fr < 5, f"france={score_fr} doit etre < 5 (P=0.05, non adjacent global)"
    assert score_mu < 5, f"mauritius={score_mu} doit etre < 5 (P=0.05, non adjacent global)"
    assert score_gl < 15, f"global={score_gl} doit etre < 15 (P=0.15 hazard sans systemic)"


def test_hazard_only_cap_removed_when_disruption_present(scorer):
    """Mélange hazard + disruption confirmé → pas de hazard_cap_39."""
    now = datetime.now(timezone.utc)
    hazard = _make_gdacs_hazard("vu_0", "VU", ["global"], "Green")
    disruption = {
        "id": "disrupt_001",
        "kind": "disruption",
        "severity": 4,
        "category": "logistics",
        "status": "confirmed",
        "is_ongoing": True,
        "published_at": now.isoformat(),
        "secondary_categories": [],
        "affected": {"countries": ["VU"], "zones": ["global"], "infrastructure_type": "national"},
        "confidence": {"max_tier": "A", "n_owners": 2},
        "reports": [{"source_id": "reuters"}],
    }
    # all_hazard = False car disruption présent → cap non appliqué
    score, caps, _, _ = scorer.category_score([hazard, disruption], "global", "logistics")
    assert "hazard_cap_39" not in caps
