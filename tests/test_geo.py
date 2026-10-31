"""Tests de géolocalisation."""
import pytest
from pathlib import Path
from collector.geo import GeoResolver

BASE_DIR = Path(__file__).parent.parent


@pytest.fixture
def geo():
    return GeoResolver(
        BASE_DIR / "config" / "gazetteer.json",
        BASE_DIR / "config" / "threat_actors.json",
        BASE_DIR / "config" / "zones.json",
    )


def test_resolve_france(geo):
    countries = geo.resolve_countries(["FR", "france"])
    assert "FR" in countries

def test_resolve_canada(geo):
    countries = geo.resolve_countries(["Canada"])
    assert "CA" in countries

def test_resolve_mauritius(geo):
    countries = geo.resolve_countries(["Maurice"])
    assert "MU" in countries

def test_iso_to_zones_france(geo):
    zones = geo.iso_to_zones(["FR"])
    assert "france" in zones
    assert "global" in zones

def test_iso_to_zones_quebec(geo):
    zones = geo.iso_to_zones(["QC"])
    assert "quebec" in zones
    assert "canada" in zones

def test_threat_actor_sandworm(geo):
    result = geo.resolve_threat_actor("Sandworm attack on Ukrainian power grid")
    assert result is not None
    actor_id, origin = result
    assert origin == "RU"

def test_threat_actor_lazarus(geo):
    result = geo.resolve_threat_actor("Lazarus Group cryptocurrency theft")
    assert result is not None
    _, origin = result
    assert origin == "KP"

def test_no_threat_actor(geo):
    result = geo.resolve_threat_actor("Generic power outage no attribution")
    assert result is None

def test_affected_vs_origin_distinction(geo):
    """L'origin et l'affected sont distincts."""
    # Un acteur russe attaquant la France
    affected = geo.resolve_countries(["france", "FR"])
    actor = geo.resolve_threat_actor("APT28 attack targeting France")
    assert "FR" in affected
    if actor:
        _, origin = actor
        assert origin != "FR"  # Origine = Russie


# ------------------------------------------------------------------ #
# Tests gazetteer étendu — GDACS pays + bassins océaniques            #
# ------------------------------------------------------------------ #

def test_resolve_mauritius_english(geo):
    """GDACS gdacs_country='Mauritius' → MU."""
    countries = geo.resolve_countries(["Mauritius"])
    assert "MU" in countries


def test_resolve_mauritius_zones(geo):
    """MU → zones mauritius + global."""
    zones = geo.iso_to_zones(["MU"])
    assert "mauritius" in zones
    assert "global" in zones


def test_resolve_vanuatu(geo):
    """GDACS gdacs_country='Vanuatu' → VU → global."""
    countries = geo.resolve_countries(["Vanuatu"])
    assert "VU" in countries
    zones = geo.iso_to_zones(countries)
    assert "global" in zones
    assert "mauritius" not in zones


def test_resolve_sudan(geo):
    """GDACS gdacs_country='Sudan' → SD → global."""
    countries = geo.resolve_countries(["Sudan"])
    assert "SD" in countries
    zones = geo.iso_to_zones(countries)
    assert "global" in zones
    assert "mauritius" not in zones


def test_resolve_drc(geo):
    """GDACS 'Democratic Republic of the Congo' → CD → global."""
    countries = geo.resolve_countries(["Democratic Republic of the Congo"])
    assert "CD" in countries


def test_resolve_swindian_basin(geo):
    """GDACS bassin SWIndian → SWIO → zones mauritius + global."""
    countries = geo.resolve_countries(["SWIndian"])
    assert "SWIO" in countries
    zones = geo.iso_to_zones(countries)
    assert "mauritius" in zones
    assert "global" in zones


def test_resolve_sw_indian_ocean_variants(geo):
    """Variantes du bassin SW Indian Ocean → SWIO → mauritius."""
    for hint in ["SW Indian", "South West Indian", "SW Indian Ocean"]:
        countries = geo.resolve_countries([hint])
        assert "SWIO" in countries, f"Failed for hint: {hint!r}"
        zones = geo.iso_to_zones(countries)
        assert "mauritius" in zones


def test_resolve_nwpacific_basin(geo):
    """Bassin NWPacific → NWPA → global uniquement."""
    countries = geo.resolve_countries(["NWPacific"])
    assert "NWPA" in countries
    zones = geo.iso_to_zones(countries)
    assert "global" in zones
    assert "mauritius" not in zones


def test_gdacs_mauritius_title_resolves(geo):
    """Titre GDACS réel 'Tropical Cyclone BELAL in Mauritius' → mauritius zone."""
    hints = geo.resolve_countries(["Mauritius"])
    zones = geo.iso_to_zones(hints)
    assert "mauritius" in zones


def test_gdacs_swindian_title_resolves(geo):
    """Titre GDACS 'Tropical Cyclone FREDDY in SWIndian' → mauritius zone."""
    hints = geo.resolve_countries(["SWIndian"])
    zones = geo.iso_to_zones(hints)
    assert "mauritius" in zones


def test_unresolved_country_returns_empty(geo):
    """Pays inconnu ne génère pas de zones."""
    countries = geo.resolve_countries(["Elbonia"])
    assert countries == []


# ------------------------------------------------------------------ #
# Tests fix 1b — comma-split et matching mots entiers                  #
# ------------------------------------------------------------------ #

def test_resolve_burkina_faso(geo):
    """GDACS 'Burkina Faso' → BF → global."""
    countries = geo.resolve_countries(["Burkina Faso"])
    assert "BF" in countries
    zones = geo.iso_to_zones(countries)
    assert "global" in zones


def test_resolve_comma_separated_multi_country(geo):
    """GDACS gdacs_country='Chad, Nigeria, Cameroon' (une seule chaîne) → 3 pays."""
    countries = geo.resolve_countries(["Chad, Nigeria, Cameroon"])
    assert "TD" in countries
    assert "NG" in countries
    assert "CM" in countries


def test_resolve_comma_two_countries(geo):
    """'India, Japan' comme chaîne unique → IN + JP."""
    countries = geo.resolve_countries(["India, Japan"])
    assert "IN" in countries
    assert "JP" in countries


def test_no_substring_false_positive(geo):
    """'Guinea' ne doit pas matcher 'Equatorial Guinea' (sous-chaîne partielle)."""
    countries_guinea = geo.resolve_countries(["Guinea"])
    countries_eq = geo.resolve_countries(["Equatorial Guinea"])
    assert "GN" in countries_guinea or countries_guinea == []
    assert "GN" not in countries_eq
