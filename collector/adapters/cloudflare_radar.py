"""Adapter Cloudflare Radar Outage Annotations."""
import json
import logging
import os
from datetime import datetime, timezone

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)

# Mapping outageCause → catégories
CAUSE_CATEGORY_MAP = {
    "CABLE_CUT": ("cables", None),
    "POWER_OUTAGE": ("electricity", "cables"),
    "GOVERNMENT_DIRECTED": ("geopolitics", "cables"),
    "MAINTENANCE": ("cables", None),
    "OTHER": ("cables", None),
}


class CloudflareRadarAdapter(BaseAdapter):
    """
    Récupère les annotations d'outage de Cloudflare Radar.
    Nécessite le secret CLOUDFLARE_API_TOKEN (permission Radar read).
    """

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
        if not token:
            logger.warning("Cloudflare Radar : CLOUDFLARE_API_TOKEN non défini, source ignorée")
            return []

        url = f"{self.url}?dateRange=7d&format=json"
        try:
            content = http_client.get(
                self.source_id, url, run_counter,
                extra_headers={"Authorization": f"Bearer {token}"}, max_bytes=self.max_bytes
            )
        except Exception as e:
            logger.error("Cloudflare Radar : fetch échoué : %s", e)
            return []

        if content is None:
            return []

        try:
            data = json.loads(content)
        except Exception as e:
            logger.error("Cloudflare Radar : parse JSON échoué : %s", e)
            return []

        annotations = (
            data.get("result", {}).get("annotations", [])
            or data.get("annotations", [])
        )

        items = []
        for ann in annotations:
            try:
                item = self._parse_annotation(ann)
                if item:
                    items.append(item)
            except Exception as e:
                logger.warning("Cloudflare Radar : annotation ignorée : %s", e)
                continue

        logger.info("Cloudflare Radar : %d items", len(items))
        return items

    def _parse_annotation(self, ann: dict) -> RawItem | None:
        ann_id = str(ann.get("id", ""))
        start_date = ann.get("startDate", "")
        end_date = ann.get("endDate")
        outage_cause = ann.get("outageCause", "OTHER")
        locations = ann.get("locations", [])
        description = ann.get("description", "")

        if not start_date:
            return None

        try:
            published_at = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except Exception:
            published_at = datetime.now(timezone.utc)

        # Déterminer les pays affectés
        geo_hints = []
        for loc in locations:
            if isinstance(loc, dict):
                code = loc.get("code") or loc.get("country")
                if code:
                    geo_hints.append(code)
            elif isinstance(loc, str):
                geo_hints.append(loc)

        cat, secondary = CAUSE_CATEGORY_MAP.get(outage_cause, ("cables", None))

        country_str = ", ".join(geo_hints) if geo_hints else "Unknown"
        title = f"Cloudflare Radar: {outage_cause} outage in {country_str}"
        summary = description or f"Outage annoté par Cloudflare Radar. Cause: {outage_cause}."
        if end_date:
            summary += f" Fin prévue: {end_date}."

        return make_raw_item(
            source_id=self.source_id,
            tier=self.tier,
            owner=self.owner,
            url="https://radar.cloudflare.com/",
            title=title,
            summary=summary,
            published_at=published_at,
            raw_ids=[f"cfr_{ann_id}"] if ann_id else [],
            geo_hints=geo_hints,
            extra={
                "outage_cause": outage_cause,
                "end_date": end_date,
                "annotation_id": ann_id,
                "secondary_category": secondary,
            },
        )
