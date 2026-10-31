"""Adapter IODA Internet Outage Detection and Analysis."""
import json
import logging
from datetime import datetime, timedelta, timezone

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)

# Pays surveillés prioritairement
WATCHED_COUNTRIES = ["FR", "CA", "MU", "US", "DE", "GB"]

# Niveaux d'alerte considérés comme anomalies (API réelle : "normal" = pas d'incident)
ALERT_LEVELS = {"warning", "critical", "outage"}


class IodaAdapter(BaseAdapter):
    """
    Récupère les alertes d'outage internet depuis l'API IODA v2.
    Endpoint réel : /v2/outages/alerts (pas /v2/events qui retourne 400)
    Format réel : {"data": [{"datasource", "entity", "time", "level", "condition", ...}]}
    Documentation : https://api.ioda.inetintel.cc.gatech.edu/
    """

    BASE_URL = "https://api.ioda.inetintel.cc.gatech.edu"

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        now = datetime.now(timezone.utc)
        from_ts = int((now - timedelta(hours=24)).timestamp())
        until_ts = int(now.timestamp())

        items = []
        errors = []
        for country in WATCHED_COUNTRIES:
            try:
                url = (
                    f"{self.BASE_URL}/v2/outages/alerts"
                    f"?entityType=country&entityCode={country}"
                    f"&from={from_ts}&until={until_ts}"
                )
                content = http_client.get(
                    f"{self.source_id}_{country}", url, run_counter, max_bytes=self.max_bytes
                )
                if content is None:
                    continue

                data = json.loads(content)
                country_items = self._parse_alerts(data, country)
                items.extend(country_items)
            except Exception as e:
                logger.warning("IODA %s : erreur : %s", country, e)
                errors.append(str(e))
                continue

        if errors and not items:
            raise RuntimeError(f"IODA : toutes les requêtes ont échoué ({len(errors)} erreurs) : {errors[0]}")

        logger.info("IODA : %d items", len(items))
        return items

    def _parse_alerts(self, data: dict, country: str) -> list[RawItem]:
        """
        Parse le format réel /v2/outages/alerts :
        {"data": [{"datasource": str, "entity": {"code": str, "name": str, "type": str},
                   "time": int, "level": str, "condition": str, "value": num, ...}]}
        Seuls les items avec level != "normal" sont retournés.
        """
        alerts = data.get("data", [])
        if not isinstance(alerts, list):
            return []

        items = []
        for alert in alerts:
            try:
                level = alert.get("level", "normal")
                if level == "normal":
                    continue

                datasource = alert.get("datasource", "bgp")
                entity = alert.get("entity", {})
                entity_code = entity.get("code", country)
                entity_name = entity.get("name", "")
                entity_type = entity.get("type", "country")

                # Ignorer les entités ASN non rattachées aux zones surveillées
                if entity_type == "asn":
                    continue
                time_ts = alert.get("time")
                condition = alert.get("condition", "")
                value = alert.get("value")
                history_value = alert.get("historyValue")

                if not time_ts:
                    continue

                published_at = datetime.fromtimestamp(time_ts, tz=timezone.utc)

                # Utiliser le code entité comme hint géo si c'est un pays
                geo_code = entity_code if entity_type == "country" else country
                title = (
                    f"IODA: Internet outage alert in {geo_code} "
                    f"({datasource}, level={level})"
                )
                summary = (
                    f"Alerte IODA niveau {level} détectée en {geo_code}. "
                    f"Source: {datasource}, condition: {condition}."
                )
                if value is not None and history_value is not None:
                    summary += f" Valeur: {value} (historique: {history_value})."

                raw_id = f"ioda_{datasource}_{entity_code}_{time_ts}"

                item = make_raw_item(
                    source_id=self.source_id,
                    tier=self.tier,
                    owner=self.owner,
                    url="https://ioda.inetintel.cc.gatech.edu/",
                    title=title,
                    summary=summary,
                    published_at=published_at,
                    raw_ids=[raw_id],
                    geo_hints=[geo_code],
                    extra={
                        "datasource": datasource,
                        "level": level,
                        "condition": condition,
                        "entity_name": entity_name,
                        "entity_type": entity_type,
                    },
                )
                items.append(item)
            except Exception as e:
                logger.warning("IODA alerte ignorée : %s", e)
                continue

        return items
