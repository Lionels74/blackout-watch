"""Stockage atomique des données avec validation JSON Schema."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

logger = logging.getLogger(__name__)

SCHEMA_DIR = Path(__file__).parent.parent / "schemas"
DATA_DIR = Path(__file__).parent.parent / "data"
ARCHIVE_DIR = DATA_DIR / "archive"


def _load_schema(name: str) -> dict:
    path = SCHEMA_DIR / f"{name}.schema.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def atomic_write(path: Path, data: Any, schema_name: str | None = None):
    """
    Valide le schema (si fourni) puis écrit atomiquement via fichier temporaire.
    Lève jsonschema.ValidationError si la validation échoue.
    """
    if schema_name:
        schema = _load_schema(schema_name)
        jsonschema.validate(instance=data, schema=schema)

    content = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    logger.debug("Écrit : %s (%d bytes)", path, len(content))


def save_incidents(incidents: list[dict]):
    """
    Sauvegarde incidents.json (fenêtre 90 jours) + archive YYYY-MM.json.
    """
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=90)

    # Filtrer les incidents récents
    recent = [
        inc for inc in incidents
        if _parse_dt(inc.get("updated_at", inc.get("published_at", ""))) >= cutoff
    ]
    old = [
        inc for inc in incidents
        if _parse_dt(inc.get("updated_at", inc.get("published_at", ""))) < cutoff
    ]

    # Archiver les anciens par mois
    by_month: dict[str, list] = {}
    for inc in old:
        dt = _parse_dt(inc.get("published_at", ""))
        key = dt.strftime("%Y-%m")
        by_month.setdefault(key, []).append(inc)

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    for month, month_incs in by_month.items():
        archive_path = ARCHIVE_DIR / f"{month}.json"
        existing = []
        if archive_path.exists():
            try:
                existing = json.loads(archive_path.read_text(encoding="utf-8"))
            except Exception:
                existing = []
        # Merge, éviter les doublons
        existing_ids = {inc["id"] for inc in existing}
        merged = existing + [i for i in month_incs if i["id"] not in existing_ids]
        atomic_write(archive_path, merged)

    atomic_write(DATA_DIR / "incidents.json", recent)
    logger.info("Incidents : %d récents, %d archivés", len(recent), len(old))


def save_scores(scores: dict):
    """Sauvegarde scores.json avec validation de schéma."""
    atomic_write(DATA_DIR / "scores.json", scores, "scores")


def save_history(hourly_entries: list[dict], daily_entries: list[dict]):
    """
    Sauvegarde history_hourly.json (7 jours) et history_daily.json (365 jours).
    """
    from datetime import timedelta
    now = datetime.now(timezone.utc)

    hourly_cutoff = now - timedelta(days=7)
    daily_cutoff = now - timedelta(days=365)

    recent_hourly = [
        e for e in hourly_entries
        if _parse_dt(e.get("timestamp", "")) >= hourly_cutoff
    ]
    recent_daily = [
        e for e in daily_entries
        if _parse_dt(e.get("timestamp", "")) >= daily_cutoff
    ]

    atomic_write(DATA_DIR / "history_hourly.json", {"entries": recent_hourly})
    atomic_write(DATA_DIR / "history_daily.json", {"entries": recent_daily})


def save_runs(runs: list[dict], new_run: dict):
    """Sauvegarde les 200 derniers runs dans runs.json."""
    runs.append(new_run)
    # Garder les 200 plus récents
    runs = sorted(runs, key=lambda r: r.get("started_at", ""), reverse=True)[:200]
    atomic_write(DATA_DIR / "runs.json", {"runs": runs}, "runs")
    return runs


def load_incidents() -> list[dict]:
    path = DATA_DIR / "incidents.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("Impossible de charger incidents.json : %s", e)
        return []


def load_runs() -> list[dict]:
    path = DATA_DIR / "runs.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("runs", [])
    except Exception as e:
        logger.error("Impossible de charger runs.json : %s", e)
        return []


def load_history() -> tuple[list, list]:
    hourly_path = DATA_DIR / "history_hourly.json"
    daily_path = DATA_DIR / "history_daily.json"
    hourly = []
    daily = []
    try:
        if hourly_path.exists():
            hourly = json.loads(hourly_path.read_text(encoding="utf-8")).get("entries", [])
    except Exception:
        pass
    try:
        if daily_path.exists():
            daily = json.loads(daily_path.read_text(encoding="utf-8")).get("entries", [])
    except Exception:
        pass
    return hourly, daily


def _parse_dt(dt_str: str) -> datetime:
    if not dt_str:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)
