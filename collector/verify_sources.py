"""
Vérification des sources : teste chaque URL activable et écrit sources_status.json.
Usage: python -m collector.verify_sources
"""
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import feedparser
import httpx

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"

UA = "BlackoutWatch/1.0 (+https://github.com/signalead/blackout-watch) verify_sources"


def test_source(src: dict) -> dict:
    """Teste une source et retourne son statut."""
    source_id = src["id"]
    # verify_url remplace url pour le test (ex: Hydro-Québec, IODA, GDELT ont des base_url non-testables directement)
    url = src.get("verify_url") or src.get("url", "")
    fmt = src.get("format", "rss")

    result = {
        "id": source_id,
        "name": src.get("name", ""),
        "status": "error",
        "http_status": None,
        "content_type": None,
        "parse_ok": None,
        "items_count": None,
        "last_item_date": None,
        "error_message": None,
        "latency_ms": None,
    }

    if not url:
        result["status"] = "disabled"
        result["error_message"] = "Pas d'URL"
        return result

    if src.get("excluded"):
        result["status"] = "disabled"
        result["error_message"] = src.get("exclusion_reason", "Exclu")
        return result

    t0 = time.time()
    try:
        with httpx.Client(
            timeout=20,
            follow_redirects=True,
            headers={"User-Agent": UA},
        ) as client:
            resp = client.get(url)

        latency_ms = round((time.time() - t0) * 1000)
        result["http_status"] = resp.status_code
        result["content_type"] = resp.headers.get("content-type", "")
        result["latency_ms"] = latency_ms

        if resp.status_code != 200:
            result["error_message"] = f"HTTP {resp.status_code}"
            return result

        content = resp.content

        if fmt in ("rss", "atom"):
            feed = feedparser.parse(content)
            if feed.entries:
                result["parse_ok"] = True
                result["items_count"] = len(feed.entries)
                # Date du dernier item (certains flux RSS sont triés oldest-first)
                import calendar as _cal
                def _entry_ts(e):
                    for attr in ("published_parsed", "updated_parsed"):
                        p = getattr(e, attr, None)
                        if p:
                            return _cal.timegm(p)
                    return 0
                most_recent = sorted(feed.entries, key=_entry_ts)[-1]
                for attr in ("published_parsed", "updated_parsed"):
                    parsed = getattr(most_recent, attr, None)
                    if parsed:
                        ts = _cal.timegm(parsed)
                        result["last_item_date"] = datetime.fromtimestamp(
                            ts, tz=timezone.utc
                        ).isoformat()
                        break
                result["status"] = "ok"
            else:
                result["parse_ok"] = False
                result["error_message"] = "Flux vide ou malformé"

        elif fmt == "json":
            data = json.loads(content)
            result["parse_ok"] = True
            if isinstance(data, list):
                result["items_count"] = len(data)
            elif isinstance(data, dict):
                # KEV : data.vulnerabilities
                if "vulnerabilities" in data:
                    result["items_count"] = len(data["vulnerabilities"])
                else:
                    result["items_count"] = 1
            result["status"] = "ok"

        elif fmt == "xml":
            import defusedxml.ElementTree as ET
            ET.fromstring(content)
            result["parse_ok"] = True
            result["status"] = "ok"

    except Exception as e:
        result["error_message"] = str(e)[:200]
        logger.warning("Source %s : %s", source_id, e)

    return result


def verify_all():
    """Teste toutes les sources activables et écrit sources_status.json."""
    sources_cfg = json.loads((CONFIG_DIR / "sources.json").read_text(encoding="utf-8"))["sources"]

    testable = [
        s for s in sources_cfg
        if s.get("enabled") and not s.get("excluded")
        and s.get("auth", "none") == "none"
        and s.get("url")
    ]
    # Les sources avec auth sont marquées not_tested
    auth_required = [
        s for s in sources_cfg
        if s.get("enabled") and not s.get("excluded")
        and s.get("auth", "none") != "none"
        and s.get("url")
    ]
    excluded = [s for s in sources_cfg if s.get("excluded")]

    logger.info("Test de %d sources sans auth...", len(testable))
    results = []

    for src in testable:
        logger.info("Test : %s (%s)", src["id"], src["url"])
        result = test_source(src)
        results.append(result)
        logger.info("  → %s", result["status"])
        time.sleep(1)  # politesse

    for src in auth_required:
        results.append({
            "id": src["id"],
            "name": src.get("name", ""),
            "status": "not_tested",
            "error_message": f"Authentification requise ({src.get('auth')})",
        })

    for src in excluded:
        results.append({
            "id": src["id"],
            "name": src.get("name", ""),
            "status": "disabled",
            "error_message": src.get("exclusion_reason", "Exclu"),
        })

    status_doc = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "sources": results,
    }

    output_path = DATA_DIR / "sources_status.json"
    content = json.dumps(status_doc, ensure_ascii=False, indent=2)
    tmp = output_path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(output_path)

    ok = sum(1 for r in results if r["status"] == "ok")
    ko = sum(1 for r in results if r["status"] == "error")
    not_tested = sum(1 for r in results if r["status"] == "not_tested")
    disabled = sum(1 for r in results if r["status"] == "disabled")

    logger.info("Résultats : %d OK, %d KO, %d non testées (auth), %d désactivées",
                ok, ko, not_tested, disabled)

    return status_doc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s : %(message)s")
    verify_all()
