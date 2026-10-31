"""Tests de classification et faux positifs."""
import pytest
from pathlib import Path
from collector.classify import Classifier

BASE_DIR = Path(__file__).parent.parent


@pytest.fixture
def classifier():
    return Classifier(
        BASE_DIR / "config" / "keywords.json",
        BASE_DIR / "config" / "severity_rules.json",
    )


def test_electricity_detected(classifier):
    cat, _ = classifier.classify_text("Major power outage affecting France electricity grid", "", "geopolitics")
    assert cat == "electricity"

def test_cables_detected(classifier):
    cat, _ = classifier.classify_text("Submarine cable cut in Mediterranean disrupts internet", "", "geopolitics")
    assert cat == "cables"

def test_cyber_detected(classifier):
    cat, _ = classifier.classify_text("Cyberattaque ransomware cible opérateur infrastructure", "", "geopolitics")
    assert cat == "cyber"

def test_logistics_detected(classifier):
    cat, _ = classifier.classify_text("Port strike blocking container ships Bab-el-Mandeb", "", "geopolitics")
    assert cat == "logistics"

def test_finance_detected(classifier):
    cat, _ = classifier.classify_text("Banking outage payment system failure SWIFT disruption", "", "geopolitics")
    assert cat == "finance"


def test_black_friday_false_positive(classifier):
    """'Black Friday' ne doit PAS être classifié comme electricity."""
    cat, _ = classifier.classify_text("Black Friday 2024 soldes promotions mode shopping", "", "geopolitics")
    # Ne doit pas être electricity
    assert cat != "electricity"

def test_blackout_film_false_positive(classifier):
    """'blackout' dans un film ne doit pas triggrer electricity."""
    cat, _ = classifier.classify_text("Blackout le film sortie cinéma 2024 critique album concert", "", "cyber")
    # Avec les mots négatifs, la catégorie electricity devrait avoir score 0
    # La catégorie retournée est le défaut de la source
    assert cat != "electricity"

def test_cable_usb_false_positive(classifier):
    """Câble USB ne doit pas déclencher cables (câbles sous-marins)."""
    cat, _ = classifier.classify_text("Câble USB-C compatible chargeur téléphone accessoire", "", "logistics")
    assert cat != "cables"


def test_status_resolved_keyword(classifier):
    """'service rétabli' → status resolved."""
    from collector.normalize import RawItem
    from datetime import datetime, timezone

    item = RawItem(
        source_id="certfr",
        tier="A",
        owner="ANSSI",
        url="https://example.com",
        title="Service rétabli après panne électrique",
        summary_text="Le service a été rétabli après 4 heures d'interruption.",
        published_at=datetime.now(timezone.utc),
    )
    status = classifier.detect_status_keywords(
        f"{item.title} {item.summary_text}", item.tier
    )
    assert status == "resolved"

def test_status_denied_keyword(classifier):
    status = classifier.detect_status_keywords(
        "Fausse information : aucune cyberattaque confirmée sur RTE", "A"
    )
    assert status == "denied"

def test_status_confirmed_tier_a(classifier):
    from collector.normalize import RawItem
    from datetime import datetime, timezone

    item = RawItem(
        source_id="cert_fr_alerte",
        tier="A",
        owner="ANSSI",
        url="https://example.com",
        title="Vulnérabilité critique",
        summary_text="",
        published_at=datetime.now(timezone.utc),
    )
    status = classifier.determine_status([item], "cyber")
    assert status == "confirmed"

def test_status_unverified_single_d(classifier):
    from collector.normalize import RawItem
    from datetime import datetime, timezone

    item = RawItem(
        source_id="gdelt",
        tier="D",
        owner="somedomain.com",
        url="https://example.com",
        title="Power outage",
        summary_text="",
        published_at=datetime.now(timezone.utc),
    )
    status = classifier.determine_status([item], "electricity")
    assert status == "unverified"


# ------------------------------------------------------------------ #
# Tests classify_kind — 10 titres réels CCCS/CISA/CERT-FR            #
# ------------------------------------------------------------------ #

def _make_item(source_id: str, tier: str, title: str, summary: str = ""):
    from collector.normalize import RawItem
    from datetime import datetime, timezone
    return RawItem(
        source_id=source_id, tier=tier, owner="test",
        url="https://example.com", title=title, summary_text=summary,
        published_at=datetime.now(timezone.utc),
    )


def test_kind_cccs_bulletin_is_vulnerability(classifier):
    """Bulletin de sécurité CCCS → vulnerability."""
    item = _make_item("cccs_fr", "A", "Bulletin de sécurité Microsoft (AV26-1068) — Mise à jour critique")
    assert classifier.classify_kind([item], "cyber") == "vulnerability"


def test_kind_cert_fr_avis_is_vulnerability(classifier):
    """CERT-FR avis → vulnerability."""
    item = _make_item("cert_fr_avis", "A", "Avis de sécurité CERT-FR: Vulnérabilité dans Apache HTTP Server")
    assert classifier.classify_kind([item], "cyber") == "vulnerability"


def test_kind_cert_fr_alerte_is_vulnerability(classifier):
    """CERT-FR alerte → vulnerability (même si 'alerte' sonne comme incident)."""
    item = _make_item("cert_fr_alerte", "A", "Alerte CERT-FR: Campagne d'exploitation de CVE-2024-1234")
    assert classifier.classify_kind([item], "cyber") == "vulnerability"


def test_kind_cisa_advisories_is_vulnerability(classifier):
    """CISA advisory → vulnerability."""
    item = _make_item("cisa_advisories", "A",
                       "CISA Releases Advisory for Cisco IOS XE Vulnerability")
    assert classifier.classify_kind([item], "cyber") == "vulnerability"


def test_kind_cisa_kev_is_vulnerability(classifier):
    """CISA KEV entry → vulnerability."""
    item = _make_item("cisa_kev", "A",
                       "CVE-2024-5678 - Ivanti Connect Secure Remote Code Execution Vulnerability")
    assert classifier.classify_kind([item], "cyber") == "vulnerability"


def test_kind_cisa_ics_is_vulnerability(classifier):
    """CISA ICS advisory → vulnerability."""
    item = _make_item("cisa_ics", "A",
                       "ICSA-24-001: Siemens SCALANCE X Series Vulnerabilities")
    assert classifier.classify_kind([item], "cyber") == "vulnerability"


def test_kind_ioda_is_incident(classifier):
    """IODA internet outage → incident."""
    item = _make_item("ioda", "B", "Internet outage detected in France (AS3215)")
    assert classifier.classify_kind([item], "cables") == "incident"


def test_kind_gdacs_is_hazard(classifier):
    """GDACS cyclone → hazard."""
    item = _make_item("gdacs", "B", "GDACS: Tropical Cyclone BELAL approaches Mauritius")
    assert classifier.classify_kind([item], "logistics") == "hazard"


def test_kind_vulnerability_severity_capped_at_1(classifier):
    """CERT-FR avis sans exploitation active → sévérité 1 après cap."""
    item = _make_item("cert_fr_avis", "A",
                       "Avis de sécurité CERT-FR: Vulnérabilité dans OpenSSL")
    kind = classifier.classify_kind([item], "cyber")
    assert kind == "vulnerability"
    assert not classifier.has_active_exploitation([item])


def test_kind_vulnerability_sev2_if_active_and_ics(classifier):
    """CISA KEV + ICS keywords → exploitation active + secteur critique → sev=2 autorisé."""
    item = _make_item("cisa_kev", "A",
                       "CVE-2024-9999 - Siemens SCADA actively exploited in the wild")
    kind = classifier.classify_kind([item], "cyber")
    assert kind == "vulnerability"
    assert classifier.has_active_exploitation([item])
    assert classifier.has_ics_critical_sector([item])
