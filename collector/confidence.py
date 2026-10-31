"""Calcul de la fraîcheur des données."""
from datetime import datetime, timezone
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


def check_freshness(scores_path: Path, settings: dict) -> tuple[bool, bool]:
    """
    Vérifie l'âge de scores.json.
    Retourne (stale_warning, stale).
    """
    warning_hours = settings.get("stale", {}).get("warning_hours", 3)
    stale_hours = settings.get("stale", {}).get("stale_hours", 12)

    if not scores_path.exists():
        return True, True

    try:
        data = json.loads(scores_path.read_text(encoding="utf-8"))
        generated_at_str = data.get("generated_at", "")
        generated_at = datetime.fromisoformat(generated_at_str.replace("Z", "+00:00"))
        age_hours = (datetime.now(timezone.utc) - generated_at).total_seconds() / 3600

        stale_warning = age_hours > warning_hours
        stale = age_hours > stale_hours
        return stale_warning, stale
    except Exception as e:
        logger.warning("Impossible de vérifier la fraîcheur : %s", e)
        return True, True
