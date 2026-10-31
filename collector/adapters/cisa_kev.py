"""Adapter CISA Known Exploited Vulnerabilities (JSON)."""
import json
import logging
from datetime import datetime, timezone

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)


class CisaKevAdapter(BaseAdapter):
    """
    Lit le catalogue CISA KEV (JSON) et crée des RawItems pour les vulnérabilités
    ajoutées récemment.
    """

    # Fenêtre : on ne remonte pas à plus de 7 jours
    MAX_AGE_DAYS = 7

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        content = http_client.get(self.source_id, self.url, run_counter, max_bytes=self.max_bytes)
        if content is None:
            return []

        data = json.loads(content)

        vulns = data.get("vulnerabilities", [])
        now = datetime.now(timezone.utc)
        items = []

        for vuln in vulns:
            try:
                date_added_str = vuln.get("dateAdded", "")
                if date_added_str:
                    added_at = datetime.fromisoformat(date_added_str).replace(tzinfo=timezone.utc)
                else:
                    continue

                age_days = (now - added_at).total_seconds() / 86400
                if age_days > self.MAX_AGE_DAYS:
                    continue

                cve_id = vuln.get("cveID", "")
                product = vuln.get("product", "")
                vendor = vuln.get("vendorProject", "")
                vuln_name = vuln.get("vulnerabilityName", "")
                description = vuln.get("shortDescription", "")
                due_date = vuln.get("dueDate", "")
                known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

                title = f"{cve_id}: {vuln_name}" if cve_id else vuln_name
                summary = f"{vendor} {product}: {description}"
                if known_ransomware == "Known":
                    summary += " [Ransomware connu]"
                if due_date:
                    summary += f" (Deadline CISA: {due_date})"

                item = make_raw_item(
                    source_id=self.source_id,
                    tier=self.tier,
                    owner=self.owner,
                    url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    title=title,
                    summary=summary,
                    published_at=added_at,
                    raw_ids=[cve_id] if cve_id else [],
                    extra={
                        "cve_id": cve_id,
                        "product": product,
                        "vendor": vendor,
                        "known_ransomware": known_ransomware,
                    },
                )
                items.append(item)
            except Exception as e:
                logger.warning("CISA KEV : entrée ignorée : %s", e)
                continue

        logger.info("CISA KEV : %d items récents", len(items))
        return items
