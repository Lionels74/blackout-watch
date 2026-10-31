"""Tests de validation des schémas JSON."""
import json
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
SCHEMA_DIR = BASE_DIR / "schemas"
DATA_DIR = BASE_DIR / "data"


def test_schema_files_exist():
    """Tous les fichiers de schéma doivent exister."""
    expected = ["incident", "scores", "history", "sources", "runs"]
    for name in expected:
        assert (SCHEMA_DIR / f"{name}.schema.json").exists(), f"Schéma manquant : {name}.schema.json"


def test_incidents_json_valid():
    """incidents.json doit être un tableau JSON valide."""
    path = DATA_DIR / "incidents.json"
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list)


def test_scores_json_valid():
    """scores.json doit être valide selon son schéma."""
    import jsonschema
    path = DATA_DIR / "scores.json"
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads((SCHEMA_DIR / "scores.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=data, schema=schema)


def test_runs_json_valid():
    """runs.json doit être valide selon son schéma."""
    import jsonschema
    path = DATA_DIR / "runs.json"
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads((SCHEMA_DIR / "runs.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=data, schema=schema)


def test_security_xss_title_sanitized():
    """Un titre avec <script> ne doit PAS être stocké tel quel."""
    from collector.normalize import strip_html, sanitize_url
    malicious = '<script>alert("xss")</script>Power outage France'
    cleaned = strip_html(malicious)
    assert "<script>" not in cleaned
    assert "alert" not in cleaned

def test_security_javascript_link_blocked():
    """Un lien javascript: retourne None."""
    from collector.normalize import sanitize_url
    assert sanitize_url("javascript:alert(1)") is None
    assert sanitize_url("JAVASCRIPT:void(0)") is None
