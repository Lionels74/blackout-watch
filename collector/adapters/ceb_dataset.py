"""Adapter CEB Maurice via dataset communautaire GitHub."""
import json
import logging
from datetime import datetime, timezone

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)


class CebDatasetAdapter(BaseAdapter):
    """
    Lit le dataset communautaire des coupures CEB Maurice.
    Coupures PLANIFIÉES uniquement. Catégorie electricity, severity 1.
    Dédoublonnage sur outageId.
    """

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        try:
            content = http_client.get(self.source_id, self.url, run_counter, max_bytes=self.max_bytes)
        except Exception as e:
            logger.error("CEB dataset : fetch échoué : %s", e)
            return []

        if content is None:
            return []

        try:
            data = json.loads(content)
        except Exception as e:
            logger.error("CEB dataset : parse JSON échoué : %s", e)
            return []

        # Format réel GitHub: {"today": [...], "future": [...]}
        # Format historique: liste directe ou {"outages": [...]} / {"data": [...]}
        if isinstance(data, list):
            outages = data
        elif "today" in data or "future" in data:
            outages = data.get("today", []) + data.get("future", [])
        else:
            outages = data.get("outages", data.get("data", []))

        items = []
        seen_ids = set()

        for outage in outages:
            try:
                outage_id = str(outage.get("outageId", outage.get("id", "")))
                if outage_id and outage_id in seen_ids:
                    continue
                if outage_id:
                    seen_ids.add(outage_id)

                # Date de début de la coupure
                # Format réel: "from"/"to"; format historique: "startDateTime"/"endDateTime"
                start_str = outage.get("from", outage.get("startDateTime", outage.get("start", "")))
                end_str = outage.get("to", outage.get("endDateTime", outage.get("end", "")))
                area = outage.get("locality", outage.get("area", outage.get("location", "Unknown")))
                reason = outage.get("reason", outage.get("cause", "Maintenance planifiée"))
                # Format réel: district (str); format historique: districts (list)
                district_raw = outage.get("district", "")
                districts = outage.get("districts", [district_raw] if district_raw else [])

                if start_str:
                    try:
                        published_at = datetime.fromisoformat(
                            start_str.replace("Z", "+00:00")
                        )
                    except Exception:
                        published_at = datetime.now(timezone.utc)
                else:
                    published_at = datetime.now(timezone.utc)

                location_str = area
                if districts:
                    location_str = f"{area} ({', '.join(districts[:3])})"

                title = f"CEB Maurice: coupure planifiée - {location_str}"
                summary = (
                    f"Coupure d'électricité planifiée par la CEB. "
                    f"Zone: {location_str}. Raison: {reason}."
                )
                if end_str:
                    summary += f" Fin prévue: {end_str}."

                item = make_raw_item(
                    source_id=self.source_id,
                    tier=self.tier,
                    owner=self.owner,
                    url="https://github.com/MrSunshyne/mauritius-dataset-electricity",
                    title=title,
                    summary=summary,
                    published_at=published_at,
                    raw_ids=[outage_id] if outage_id else [],
                    geo_hints=["MU"],
                    extra={
                        "outage_id": outage_id,
                        "area": area,
                        "reason": reason,
                        "is_planned": True,
                    },
                )
                items.append(item)

            except Exception as e:
                logger.warning("CEB dataset : entrée ignorée : %s", e)
                continue

        logger.info("CEB dataset : %d coupures planifiées", len(items))
        return items
