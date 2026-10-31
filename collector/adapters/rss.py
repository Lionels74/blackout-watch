"""Adapter générique RSS/Atom via feedparser."""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import feedparser

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)


class RssAdapter(BaseAdapter):
    """Lit un flux RSS ou Atom et retourne des RawItems."""

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        content = http_client.get(self.source_id, self.url, run_counter, max_bytes=self.max_bytes)
        if content is None:
            # 304 Not Modified — pas de nouveaux items
            logger.debug("RSS %s : 304 Not Modified", self.source_id)
            return []

        feed = feedparser.parse(content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"RSS {self.source_id} : flux malformé ({feed.bozo_exception})")

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        items = []
        skipped_old = 0
        for entry in feed.entries:
            try:
                item = self._parse_entry(entry)
                if item:
                    if item.published_at < cutoff:
                        skipped_old += 1
                        continue
                    items.append(item)
            except Exception as e:
                logger.warning("RSS %s : entrée ignorée : %s", self.source_id, e)
                continue

        if skipped_old:
            logger.debug("RSS %s : %d entrées ignorées (> %d jours)", self.source_id, skipped_old, self.max_age_days)
        logger.info("RSS %s : %d items", self.source_id, len(items))
        return items

    def _parse_entry(self, entry) -> Optional[RawItem]:
        title = getattr(entry, "title", "") or ""
        link = getattr(entry, "link", "") or ""
        summary = getattr(entry, "summary", "") or ""
        if not summary and hasattr(entry, "content"):
            summary = entry.content[0].get("value", "") if entry.content else ""

        # Date de publication
        published_at = self._parse_date(entry)

        # Extraire les CVE du titre ou résumé
        import re
        cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        raw_ids = list(set(cve_re.findall(f"{title} {summary}")))

        # Hints géographiques depuis les tags
        geo_hints = []
        if hasattr(entry, "tags"):
            for tag in entry.tags:
                term = getattr(tag, "term", "") or ""
                if term:
                    geo_hints.append(term)

        if not link:
            return None

        return make_raw_item(
            source_id=self.source_id,
            tier=self.tier,
            owner=self.owner,
            url=link,
            title=title,
            summary=summary,
            published_at=published_at,
            raw_ids=raw_ids,
            geo_hints=geo_hints,
        )

    def _parse_date(self, entry) -> datetime:
        """Extrait la date de publication depuis une entrée feedparser."""
        for attr in ("published_parsed", "updated_parsed", "created_parsed"):
            parsed = getattr(entry, attr, None)
            if parsed:
                try:
                    import time
                    ts = time.mktime(parsed)
                    return datetime.fromtimestamp(ts, tz=timezone.utc)
                except Exception:
                    pass
        return datetime.now(timezone.utc)
