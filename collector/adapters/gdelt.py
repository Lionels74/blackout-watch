"""Adapter GDELT DOC 2.0 - presse mondiale filtrée par mots-clés."""
import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem, sanitize_url

logger = logging.getLogger(__name__)

GDELT_DOC_URL = "https://api.gdeltproject.org/api/v2/doc/doc"


class GdeltAdapter(BaseAdapter):
    """
    Interroge l'API GDELT DOC 2.0.
    Règles strictes :
    - 1 requête / 6 secondes
    - Max 8 requêtes par run
    - Abandon propre sur 429 ou 'limit requests'
    """

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        rate_limit = self.settings.get("gdelt", {}).get("rate_limit_seconds", 6)
        max_requests = self.settings.get("gdelt", {}).get("max_requests_per_run", 8)
        trusted_press = set()

        # Charger les queries depuis keywords.json si disponible
        import json as _json
        from pathlib import Path
        kw_path = Path(__file__).parent.parent.parent / "config" / "keywords.json"
        try:
            with open(kw_path, encoding="utf-8") as f:
                kw_data = _json.load(f)
            queries = kw_data.get("gdelt_queries", {})
            trusted_press = set(kw_data.get("trusted_press", []))
        except Exception:
            queries = {}

        if not queries:
            logger.warning("GDELT : aucune query définie dans keywords.json")
            return []

        items = []
        request_count = 0
        throttled = False

        for query_name, query_str in queries.items():
            if request_count >= max_requests:
                logger.info("GDELT : limite de %d requêtes atteinte", max_requests)
                break
            if throttled:
                break

            if request_count > 0:
                time.sleep(rate_limit)

            params = {
                "mode": "artlist",
                "format": "json",
                "sort": "datedesc",
                "timespan": "2h",
                "query": query_str,
                "maxrecords": "20",
            }
            url = f"{GDELT_DOC_URL}?{urlencode(params)}"

            try:
                content = http_client.get(
                    f"{self.source_id}_{query_name}", url, run_counter, max_bytes=self.max_bytes
                )
                request_count += 1

                if content is None:
                    continue

                # Vérifier le throttling
                text = content.decode("utf-8", errors="ignore")
                if "limit requests" in text.lower() or "429" in text[:100]:
                    logger.warning("GDELT : throttle détecté, abandon du run")
                    throttled = True
                    break

                data = json.loads(content)
                articles = data.get("articles", [])

                for art in articles:
                    try:
                        item = self._parse_article(art, trusted_press, query_name)
                        if item:
                            items.append(item)
                    except Exception as e:
                        logger.warning("GDELT article ignoré : %s", e)

            except Exception as e:
                request_count += 1
                logger.warning("GDELT query %s : erreur : %s", query_name, e)
                if "429" in str(e) or "Too Many Requests" in str(e):
                    throttled = True
                    break

        if not items and throttled:
            raise RuntimeError(f"GDELT : 0 items, throttle sur {request_count} requêtes")

        logger.info("GDELT : %d items (%d requêtes)", len(items), request_count)
        return items

    def _parse_article(self, art: dict, trusted_press: set, query_name: str) -> RawItem | None:
        title = art.get("title", "")
        url = art.get("url", "")
        domain = art.get("domain", "")
        seendate = art.get("seendate", "")
        language = art.get("language", "")
        country = art.get("sourcecountry", "")

        # Valider l'URL
        safe_url = sanitize_url(url)
        if not safe_url:
            return None

        # Déterminer le tier selon le domaine
        tier = "C" if domain in trusted_press else "D"

        # Date
        try:
            if seendate:
                # Format GDELT : "20240115T120000Z"
                published_at = datetime.strptime(seendate, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            else:
                published_at = datetime.now(timezone.utc)
        except Exception:
            published_at = datetime.now(timezone.utc)

        if not title:
            return None

        # Ne stocker que le minimum requis
        summary = f"Source: {domain} ({language}). Catégorie query: {query_name}."

        geo_hints = [country] if country else []

        return make_raw_item(
            source_id=self.source_id,
            tier=tier,
            owner=domain or "gdelt",
            url=safe_url,
            title=title,
            summary=summary,
            published_at=published_at,
            geo_hints=geo_hints,
            extra={
                "domain": domain,
                "language": language,
                "source_country": country,
                "query_name": query_name,
            },
        )
