"""Adapter Hydro-Québec pannes en temps réel."""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)

BISVERSION_URL = "https://pannes.hydroquebec.com/pannes/donnees/v3_0/bisversion.json"
MARKERS_URL_TPL = "https://pannes.hydroquebec.com/pannes/donnees/v3_0/bismarkers{version}.json"


class HydroquebecAdapter(BaseAdapter):
    """
    Lit les données de pannes Hydro-Québec.
    Étape 1 : récupérer la version (bisversion.json)
    Étape 2 : récupérer bismarkers{version}.json
    """

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        min_clients = self.settings.get("hydroquebec", {}).get("min_clients_threshold", 1000)

        # Étape 1 : version
        try:
            version_content = http_client.get(
                f"{self.source_id}_version", BISVERSION_URL, run_counter
            )
        except Exception as e:
            logger.error("Hydro-Québec version : %s", e)
            return []

        if version_content is None:
            return []

        try:
            version_data = json.loads(version_content)
            version = version_data.get("version") or version_data.get("v")
            if not version:
                # Parfois c'est directement la valeur string
                version = version_content.decode("utf-8").strip().strip('"')
        except Exception as e:
            logger.error("Hydro-Québec : parse version échoué : %s", e)
            return []

        # Étape 2 : données de pannes
        markers_url = MARKERS_URL_TPL.format(version=version)
        try:
            markers_content = http_client.get(
                self.source_id, markers_url, run_counter
            )
        except Exception as e:
            logger.error("Hydro-Québec markers : %s", e)
            return []

        if markers_content is None:
            return []

        try:
            markers_data = json.loads(markers_content)
        except Exception as e:
            logger.error("Hydro-Québec : parse markers échoué : %s", e)
            return []

        # Agréger par région
        markers = markers_data if isinstance(markers_data, list) else markers_data.get("markers", [])
        region_aggregates: dict[str, dict] = {}

        for marker in markers:
            try:
                nb_clients = int(marker.get("nbClients", marker.get("nb_clients", 0)))
                if nb_clients < min_clients:
                    continue

                region = str(marker.get("regionId", marker.get("region", "unknown")))
                start_str = marker.get("debutPanne", marker.get("start", ""))
                cause_code = str(marker.get("codeCause", marker.get("cause", "")))
                status = marker.get("etatPanne", marker.get("status", ""))

                if region not in region_aggregates:
                    region_aggregates[region] = {
                        "total_clients": 0,
                        "start": start_str,
                        "cause": cause_code,
                        "status": status,
                        "count": 0,
                    }
                region_aggregates[region]["total_clients"] += nb_clients
                region_aggregates[region]["count"] += 1
                # Prendre le début le plus ancien
                if start_str and start_str < region_aggregates[region]["start"]:
                    region_aggregates[region]["start"] = start_str

            except Exception as e:
                logger.warning("Hydro-Québec marker ignoré : %s", e)
                continue

        items = []
        for region, agg in region_aggregates.items():
            if agg["total_clients"] < min_clients:
                continue

            start_str = agg["start"]
            try:
                published_at = datetime.fromisoformat(
                    start_str.replace("Z", "+00:00")
                ) if start_str else datetime.now(timezone.utc)
            except Exception:
                published_at = datetime.now(timezone.utc)

            title = f"Hydro-Québec: panne région {region} ({agg['total_clients']:,} clients)"
            summary = (
                f"Panne électrique Hydro-Québec. Région: {region}. "
                f"Clients affectés: {agg['total_clients']:,}. "
                f"Cause: {agg['cause']}. Statut: {agg['status']}."
            )

            item = make_raw_item(
                source_id=self.source_id,
                tier=self.tier,
                owner=self.owner,
                url="https://pannes.hydroquebec.com/",
                title=title,
                summary=summary,
                published_at=published_at,
                raw_ids=[f"hq_{region}_{agg['start'][:10]}"] if agg["start"] else [],
                geo_hints=["QC", "CA"],
                extra={
                    "region": region,
                    "clients_count": agg["total_clients"],
                    "cause_code": agg["cause"],
                    "outage_count": agg["count"],
                },
            )
            items.append(item)

        logger.info("Hydro-Québec : %d régions avec pannes >= %d clients", len(items), min_clients)
        return items
