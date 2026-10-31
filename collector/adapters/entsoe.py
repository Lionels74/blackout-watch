"""Adapter ENTSO-E Transparency Platform (XML)."""
import logging
import os
from datetime import datetime, timedelta, timezone

import defusedxml.ElementTree as ET

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)

# Namespace ENTSO-E
NS = {"ns": "urn:iec62325.351:tc57wg16:451-6:generationloaddocument:3:0"}

# Pays surveillés
WATCHED_COUNTRIES = {
    "FR": "10YFR-RTE------C",
    "DE": "10Y1001A1001A83F",
    "GB": "10YGB----------A",
    "ES": "10YES-REE------0",
    "IT": "10YIT-GRTN-----B",
    "BE": "10YBE----------2",
}


class EntsoeAdapter(BaseAdapter):
    """
    Lit les indisponibilités non planifiées (A54) d'ENTSO-E.
    Seul event_nature A54 (non planifié) génère des incidents.
    """

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        token = os.environ.get("ENTSOE_TOKEN", "")
        if not token:
            logger.warning("ENTSO-E : ENTSOE_TOKEN non défini, source ignorée")
            return []

        now = datetime.now(timezone.utc)
        period_start = (now - timedelta(hours=24)).strftime("%Y%m%d%H00")
        period_end = now.strftime("%Y%m%d%H00")

        items = []
        for country, area_code in WATCHED_COUNTRIES.items():
            try:
                # Unavailability of transmission infrastructure
                url = (
                    f"{self.url}"
                    f"?securityToken={token}"
                    f"&documentType=A80"
                    f"&processType=A54"
                    f"&in_Domain={area_code}"
                    f"&periodStart={period_start}"
                    f"&periodEnd={period_end}"
                )
                content = http_client.get(
                    f"{self.source_id}_{country}", url, run_counter, max_bytes=self.max_bytes
                )
                if content is None:
                    continue

                country_items = self._parse_xml(content, country)
                items.extend(country_items)

            except Exception as e:
                logger.warning("ENTSO-E %s : erreur : %s", country, e)
                continue

        logger.info("ENTSO-E : %d événements non planifiés", len(items))
        return items

    def _parse_xml(self, content: bytes, country: str) -> list[RawItem]:
        items = []
        try:
            # defusedxml pour éviter les XXE
            root = ET.fromstring(content)
        except Exception as e:
            logger.warning("ENTSO-E %s : parse XML échoué : %s", country, e)
            return []

        # Chercher les TimeSeries avec event_nature A54
        for ts in root.iter():
            if not ts.tag.endswith("TimeSeries"):
                continue
            try:
                reason = ts.find(".//{*}businessType")
                event_nature_el = ts.find(".//{*}docStatus")
                mrid = ts.find("{*}mRID")

                period = ts.find(".//{*}Period")
                if period is None:
                    continue
                start_el = period.find("{*}timeInterval/{*}start")
                if start_el is None:
                    continue

                start_str = start_el.text or ""
                try:
                    published_at = datetime.fromisoformat(
                        start_str.replace("Z", "+00:00")
                    )
                except Exception:
                    published_at = datetime.now(timezone.utc)

                asset_name = ""
                asset_el = ts.find(".//{*}name")
                if asset_el is not None:
                    asset_name = asset_el.text or ""

                mrid_val = mrid.text if mrid is not None else ""
                title = f"ENTSO-E: indisponibilité non planifiée {country}"
                if asset_name:
                    title += f" - {asset_name}"

                summary = (
                    f"Indisponibilité non planifiée (A54) détectée par ENTSO-E "
                    f"en {country}. Début: {start_str}."
                )

                item = make_raw_item(
                    source_id=self.source_id,
                    tier=self.tier,
                    owner=self.owner,
                    url="https://transparency.entsoe.eu/",
                    title=title,
                    summary=summary,
                    published_at=published_at,
                    raw_ids=[f"entsoe_{mrid_val}"] if mrid_val else [],
                    geo_hints=[country],
                    extra={
                        "event_nature": "A54",
                        "country": country,
                        "asset_name": asset_name,
                    },
                )
                items.append(item)

            except Exception as e:
                logger.warning("ENTSO-E TimeSeries ignorée : %s", e)
                continue

        return items
