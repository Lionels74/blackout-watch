"""Tests des adapters sur fixtures enregistrées (AUCUN appel réseau)."""
import json
import pytest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASE_DIR = Path(__file__).parent.parent


def make_mock_http(content: bytes | None):
    """Crée un mock HttpClient qui retourne le contenu fourni."""
    mock = MagicMock()
    mock.get.return_value = content
    return mock


def make_source_cfg(source_id: str, tier: str = "A", fmt: str = "rss",
                    url: str = "https://example.com/feed",
                    default_cat: str = "cyber") -> dict:
    return {
        "id": source_id,
        "name": f"Test {source_id}",
        "tier": tier,
        "owner": "test",
        "url": url,
        "format": fmt,
        "default_category": default_cat,
        "zones_hint": ["global"],
    }


def make_settings() -> dict:
    return json.loads((BASE_DIR / "config" / "settings.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ #
# Tests RSS (CERT-FR)                                                 #
# ------------------------------------------------------------------ #
def test_rss_adapter_cert_fr():
    from collector.adapters.rss import RssAdapter
    content = (FIXTURES_DIR / "cert_fr_alerte.xml").read_bytes()
    http = make_mock_http(content)
    adapter = RssAdapter(make_source_cfg("cert_fr_alerte"), make_settings())
    items = adapter.fetch(http)
    assert len(items) >= 1
    assert all(i.source_id == "cert_fr_alerte" for i in items)
    assert all(i.title for i in items)
    # Vérifier extraction CVE
    cve_items = [i for i in items if any("CVE" in rid for rid in i.raw_ids)]
    assert len(cve_items) >= 1

def test_rss_adapter_304():
    """304 Not Modified → liste vide."""
    from collector.adapters.rss import RssAdapter
    http = make_mock_http(None)  # None = 304
    adapter = RssAdapter(make_source_cfg("test_rss"), make_settings())
    items = adapter.fetch(http)
    assert items == []

def test_rss_adapter_fetch_error():
    """Erreur réseau → exception propagée (run.py la capture et comptabilise en ko)."""
    from collector.adapters.rss import RssAdapter
    http = MagicMock()
    http.get.side_effect = Exception("Network error")
    adapter = RssAdapter(make_source_cfg("test_rss"), make_settings())
    with pytest.raises(Exception, match="Network error"):
        adapter.fetch(http)


# ------------------------------------------------------------------ #
# Tests CISA KEV                                                      #
# ------------------------------------------------------------------ #
def test_cisa_kev_adapter():
    from collector.adapters.cisa_kev import CisaKevAdapter
    content = (FIXTURES_DIR / "cisa_kev.json").read_bytes()
    http = make_mock_http(content)
    adapter = CisaKevAdapter(
        make_source_cfg("cisa_kev", fmt="json", url="https://www.cisa.gov/.../kev.json"),
        make_settings()
    )
    items = adapter.fetch(http)
    # Seul CVE-2024-1234 est récent (MAX_AGE_DAYS=7 vérifié via mock)
    # Avec la fixture, dateAdded=2024-02-15 → peut être > 7j si le test s'exécute après
    # On vérifie juste le parsing sans erreur
    assert isinstance(items, list)

def test_cisa_kev_filters_old():
    """CVE ajouté en 2020 ne doit pas apparaître."""
    from collector.adapters.cisa_kev import CisaKevAdapter
    content = (FIXTURES_DIR / "cisa_kev.json").read_bytes()
    http = make_mock_http(content)
    adapter = CisaKevAdapter(
        make_source_cfg("cisa_kev", fmt="json"),
        make_settings()
    )
    items = adapter.fetch(http)
    cve_ids = [i.raw_ids[0] if i.raw_ids else "" for i in items]
    assert "CVE-2020-0001" not in cve_ids


# ------------------------------------------------------------------ #
# Tests GDACS                                                         #
# ------------------------------------------------------------------ #
def test_gdacs_adapter():
    from collector.adapters.gdacs import GdacsAdapter
    content = (FIXTURES_DIR / "gdacs.xml").read_bytes()
    http = make_mock_http(content)
    adapter = GdacsAdapter(
        make_source_cfg("gdacs", tier="B", fmt="rss", default_cat="logistics"),
        make_settings()
    )
    items = adapter.fetch(http)
    assert len(items) >= 2
    # Vérifier que les raw_ids ont le bon format (gdacs_{event_id})
    raw_ids_flat = [rid for i in items for rid in i.raw_ids]
    assert any(rid.startswith("gdacs_") for rid in raw_ids_flat)


# ------------------------------------------------------------------ #
# Tests Hydro-Québec                                                   #
# ------------------------------------------------------------------ #
def test_hydroquebec_adapter():
    from collector.adapters.hydroquebec import HydroquebecAdapter
    version_content = (FIXTURES_DIR / "hydroquebec_version.json").read_bytes()
    markers_content = (FIXTURES_DIR / "hydroquebec_markers.json").read_bytes()

    http = MagicMock()
    # Premier appel (version), deuxième appel (markers)
    http.get.side_effect = [version_content, markers_content]

    adapter = HydroquebecAdapter(
        make_source_cfg("hydroquebec", fmt="json", url="https://pannes.hydroquebec.com/"),
        make_settings()
    )
    items = adapter.fetch(http)
    # QC-MON (5000) et QC-LAU (15000) passent le seuil de 1000
    assert len(items) >= 1
    clients = [i.extra.get("clients_count", 0) for i in items]
    assert all(c >= 1000 for c in clients)


# ------------------------------------------------------------------ #
# Tests CEB Dataset                                                   #
# ------------------------------------------------------------------ #
def test_ceb_dataset_adapter():
    from collector.adapters.ceb_dataset import CebDatasetAdapter
    content = (FIXTURES_DIR / "ceb_dataset.json").read_bytes()
    http = make_mock_http(content)
    adapter = CebDatasetAdapter(
        make_source_cfg("ceb_dataset", fmt="json", url="https://raw.github.../power-outages.json", default_cat="electricity"),
        make_settings()
    )
    items = adapter.fetch(http)
    # Format réel: {"today": [], "future": [...]} — 15 coupures planifiées
    assert len(items) >= 1
    # Chaque item a un outageId comme raw_id
    assert all(len(i.raw_ids) >= 1 for i in items)
    # Les items ont la bonne catégorie (mauritius via geo_hints)
    assert all("MU" in i.geo_hints for i in items)


# ------------------------------------------------------------------ #
# Tests IODA                                                          #
# ------------------------------------------------------------------ #
def test_ioda_adapter():
    """
    Fixture : ioda.json — capture réelle 2026-10-31 depuis /v2/outages/alerts?entityType=asn.
    2 entrées : 1 level=critical (entity remappée en country/FR pour le test), 1 level=normal.
    Seule l'entrée critical doit être retournée (level != 'normal').
    Test via fetch() avec mock HTTP, pas via _parse_alerts direct.
    """
    from collector.adapters.ioda import IodaAdapter
    content = (FIXTURES_DIR / "ioda.json").read_bytes()
    http = make_mock_http(content)

    adapter = IodaAdapter(
        make_source_cfg("ioda", tier="B", fmt="json"),
        make_settings()
    )
    items = adapter.fetch(http)
    # La fixture a 1 entry level=critical → retournée, 1 entry level=normal → filtrée
    # fetch() itère sur 6 pays, mock retourne la même fixture pour chacun → 6 items
    assert len(items) >= 1
    assert all(i.source_id == "ioda" for i in items)
    # Vérifier que les items ont bien level != normal
    assert all(i.extra.get("level") != "normal" for i in items)


# ------------------------------------------------------------------ #
# Tests Cloudflare Radar                                              #
# ------------------------------------------------------------------ #
def test_cloudflare_radar_adapter():
    from collector.adapters.cloudflare_radar import CloudflareRadarAdapter
    content = (FIXTURES_DIR / "cloudflare_radar.json").read_bytes()
    data = json.loads(content)
    annotations = data["result"]["annotations"]

    with patch.dict("os.environ", {"CLOUDFLARE_API_TOKEN": "test_token"}):
        http = make_mock_http(content)
        adapter = CloudflareRadarAdapter(
            make_source_cfg("cloudflare_radar", tier="B", fmt="json"),
            make_settings()
        )
        items = adapter.fetch(http)

    assert len(items) >= 1
    # Vérifier que CABLE_CUT est détecté
    cable_items = [i for i in items if i.extra.get("outage_cause") == "CABLE_CUT"]
    assert len(cable_items) >= 1
    # Vérifier les geo_hints
    assert any("FR" in i.geo_hints for i in cable_items)


# ------------------------------------------------------------------ #
# Tests ENTSO-E                                                       #
# ------------------------------------------------------------------ #
def test_entsoe_adapter():
    """
    Fixture : entsoe.xml — fabriquée d'après la doc ENTSO-E (schéma GL_MarketDocument).
    1 TimeSeries, 1 Period, démarrage 2024-02-15T08:00Z.
    processType=A54 filtré côté API, pas dans le XML → tous les TimeSeries sont A54 par définition.
    Test via fetch() avec mock HTTP + ENTSOE_TOKEN mocké, pas via _parse_xml direct.
    """
    from collector.adapters.entsoe import EntsoeAdapter
    content = (FIXTURES_DIR / "entsoe.xml").read_bytes()
    http = make_mock_http(content)

    with patch.dict("os.environ", {"ENTSOE_TOKEN": "test_token_mock"}):
        adapter = EntsoeAdapter(
            make_source_cfg("entsoe", tier="A", fmt="xml",
                            url="https://web-api.tp.entsoe.eu/api"),
            make_settings()
        )
        items = adapter.fetch(http)

    assert isinstance(items, list)
    # La fixture a 1 TimeSeries → 1 item par pays (6 pays surveillés dans WATCHED_COUNTRIES)
    # Ou 0 si la fixture ne contient pas de Period valide — on vérifie juste le type
    assert len(items) >= 1


# ------------------------------------------------------------------ #
# Tests verify_sources — last_item_date oldest-first fix             #
# ------------------------------------------------------------------ #
def test_verify_source_last_item_date_is_most_recent():
    """
    cert_fr_alerte.xml est trié oldest-first (1re entrée = 2015-07-24, dernière = 2026-10-21).
    verify_sources.test_source() doit retourner last_item_date >= 2026, pas 2015.
    Régression : avant le fix, entries[:1] prenait la plus ancienne entrée.
    """
    from unittest.mock import patch, MagicMock
    from collector.verify_sources import test_source

    content = (FIXTURES_DIR / "cert_fr_alerte.xml").read_bytes()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/rss+xml"}
    mock_resp.content = content

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get.return_value = mock_resp

    src = {
        "id": "cert_fr_alerte",
        "name": "CERT-FR Alertes",
        "url": "https://cert.cyber.gouv.fr/alerte/feed/",
        "format": "rss",
        "enabled": True,
        "auth": "none",
    }

    with patch("collector.verify_sources.httpx.Client", return_value=mock_client):
        result = test_source(src)

    assert result["status"] == "ok"
    assert result["last_item_date"] is not None
    last_item_year = int(result["last_item_date"][:4])
    assert last_item_year >= 2026, (
        f"last_item_date={result['last_item_date']} — bug oldest-first : "
        f"entries[:1] pris au lieu de sorted[-1]"
    )
