"""Adapter GDACS (Global Disaster Alert and Coordination System)."""
import logging
from datetime import datetime, timezone
from typing import Optional

import feedparser

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)

# Mapping type d'événement → catégories
EVENT_CATEGORY_MAP = {
    "TC": ("logistics", "electricity"),   # Tropical Cyclone
    "FL": ("logistics", "electricity"),   # Flood
    "EQ": ("logistics", "electricity"),   # Earthquake
    "VO": ("logistics", None),            # Volcano
    "DR": ("logistics", None),            # Drought
    "WF": ("logistics", None),            # Wildfire
    "TS": ("logistics", "cables"),        # Tsunami
}


class GdacsAdapter(BaseAdapter):
    """Lit le flux RSS GDACS et génère des incidents."""

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        content = http_client.get(self.source_id, self.url, run_counter, max_bytes=self.max_bytes)
        if content is None:
            return []

        feed = feedparser.parse(content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"GDACS : flux malformé ({feed.bozo_exception})")

        items = []
        for entry in feed.entries:
            try:
                item = self._parse_entry(entry)
                if item:
                    items.append(item)
            except Exception as e:
                logger.warning("GDACS : entrée ignorée : %s", e)
                continue

        logger.info("GDACS : %d items", len(items))
        return items

    def _parse_entry(self, entry) -> Optional[RawItem]:
        title = getattr(entry, "title", "") or ""
        link = getattr(entry, "link", "") or ""
        summary = getattr(entry, "summary", "") or ""

        # Namespace GDACS dans feedparser
        event_type = getattr(entry, "gdacs_eventtype", "") or ""
        alert_level = getattr(entry, "gdacs_alertlevel", "") or ""
        event_id = getattr(entry, "gdacs_eventid", "") or ""
        country = getattr(entry, "gdacs_country", "") or ""
        severity_val = getattr(entry, "gdacs_severity", {})
        if isinstance(severity_val, dict):
            severity_text = severity_val.get("value", "")
        else:
            severity_text = str(severity_val)

        # Fallback : extraire depuis le titre
        if not event_type and not alert_level:
            for et in EVENT_CATEGORY_MAP:
                if et in title.upper():
                    event_type = et
                    break
            for level in ["Red", "Orange", "Green"]:
                if level.lower() in title.lower() or level.lower() in summary.lower():
                    alert_level = level
                    break

        if not link:
            return None

        # Date
        import time as time_mod
        published_parsed = getattr(entry, "published_parsed", None)
        if published_parsed:
            published_at = datetime.fromtimestamp(
                time_mod.mktime(published_parsed), tz=timezone.utc
            )
        else:
            published_at = datetime.now(timezone.utc)

        geo_hints = [country] if country else []

        cat, secondary = EVENT_CATEGORY_MAP.get(event_type, ("logistics", None))
        if not cat:
            cat = "logistics"

        return make_raw_item(
            source_id=self.source_id,
            tier=self.tier,
            owner=self.owner,
            url=link,
            title=title,
            summary=summary,
            published_at=published_at,
            raw_ids=[f"gdacs_{event_id}"] if event_id else [],
            geo_hints=geo_hints,
            extra={
                "event_type": event_type,
                "alert_level": alert_level,
                "event_id": event_id,
                "country": country,
                "secondary_category": secondary,
            },
        )
