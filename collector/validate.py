"""Validation de tous les fichiers data/ contre leurs schémas JSON."""
import json
import logging
import sys
from pathlib import Path

import jsonschema

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"
SCHEMA_DIR = Path(__file__).parent.parent / "schemas"

VALIDATIONS = [
    ("incidents.json", "incident", "array"),
    ("scores.json", "scores", "object"),
    ("history_hourly.json", None, None),
    ("history_daily.json", None, None),
    ("sources_status.json", "sources", "object"),
    ("runs.json", "runs", "object"),
]


def validate_all(exit_on_error: bool = True) -> bool:
    """
    Valide tous les fichiers data/ contre leurs schémas.
    Retourne True si tout est valide, False sinon.
    """
    all_ok = True

    for filename, schema_name, container in VALIDATIONS:
        path = DATA_DIR / filename
        if not path.exists():
            logger.warning("Fichier manquant : %s", path)
            continue

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error("JSON invalide dans %s : %s", filename, e)
            all_ok = False
            continue

        if schema_name is None:
            logger.debug("OK (pas de schéma) : %s", filename)
            continue

        schema_path = SCHEMA_DIR / f"{schema_name}.schema.json"
        if not schema_path.exists():
            logger.warning("Schéma manquant : %s", schema_path)
            continue

        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            # Pour incidents.json, valider chaque item
            if container == "array" and isinstance(data, list):
                for i, item in enumerate(data):
                    jsonschema.validate(instance=item, schema=schema)
                logger.info("OK (%d items) : %s", len(data), filename)
            else:
                jsonschema.validate(instance=data, schema=schema)
                logger.info("OK : %s", filename)
        except jsonschema.ValidationError as e:
            logger.error("Erreur de validation dans %s : %s", filename, e.message)
            all_ok = False
        except Exception as e:
            logger.error("Erreur inattendue validant %s : %s", filename, e)
            all_ok = False

    # Valider aussi les données de démo si elles existent
    demo_dir = Path(__file__).parent.parent / "demo"
    for demo_file in demo_dir.glob("*.json"):
        try:
            data = json.loads(demo_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    assert item.get("demo") is True, f"demo=true manquant dans {demo_file.name}"
            elif isinstance(data, dict):
                assert data.get("demo") is True or "zones" in data or "entries" in data
            logger.info("Demo OK : %s", demo_file.name)
        except Exception as e:
            logger.error("Demo invalide %s : %s", demo_file.name, e)
            all_ok = False

    if all_ok:
        logger.info("Validation complète : tous les fichiers sont valides")
    else:
        logger.error("Validation échouée : voir les erreurs ci-dessus")
        if exit_on_error:
            sys.exit(1)

    return all_ok


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    validate_all()
