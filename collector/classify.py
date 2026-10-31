"""Classification des événements : catégorie, sous-type, gravité, statut."""
import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Sources émettant uniquement des avis de vulnérabilité (jamais des incidents confirmés)
VULNERABILITY_SOURCES = frozenset([
    "cert_fr_alerte", "cert_fr_avis", "cert_fr_cti", "cert_fr_actualite",
    "cert_fr_scada", "cisa_advisories", "cisa_alerts", "cisa_ics", "cisa_kev",
    "cccs_fr", "cccs_en", "cert_eu", "ncsc_uk",
])

# Sources émettant des incidents/disruptions mesurés
INCIDENT_SOURCES = frozenset([
    "ioda", "cloudflare_radar", "rte_ecowatt", "entsoe",
    "hydroquebec", "ceb_dataset",
])

HAZARD_SOURCES = frozenset(["gdacs"])

# Mots-clés d'exploitation active (sev=2 si aussi secteur critique)
_ACTIVE_EXPLOIT_PATTERNS = frozenset([
    "exploited in the wild", "actively exploited", "exploitation active",
    "exploitation sauvage", "actively being exploited",
    "known exploited", "zero-day", "zero day", "0-day",
    "in the wild",
])

# Mots-clés de secteur critique/ICS (nécessaire pour sev=2 sur vulnerability)
_ICS_CRITICAL_PATTERNS = frozenset([
    "ics", "scada", "ot ", " ot,", "operational technology",
    "industrial control", "power grid", "critical infrastructure",
    "systèmes industriels", "infrastructure critique",
    "energy sector", "water sector", "water system",
])

# Mots-clés de résolution
_RESOLVED_KEYWORDS = frozenset([
    "résolu", "rétabli", "restored", "resolved", "repris", "terminé",
    "remis en service", "back online", "back to normal", "service rétabli",
    "fixed", "remediated", "mitigated",
])

# Mots-clés de démenti
_DENIED_KEYWORDS = frozenset([
    "démenti", "fausse information", "denied", "false report", "fake news",
    "inexact", "dément", "infox", "démentie", "rectification",
])

# Mots-clés de campagne coordonnée (tier A uniquement)
_COORDINATED_KEYWORDS = frozenset([
    "coordinated attack", "attaque coordonnée", "coordinated campaign",
    "campagne coordonnée", "multiple targets", "cibles multiples",
    "widespread attack", "attaque généralisée",
])

# Statuts des reports
TIER_RANK = {"A": 4, "B": 3, "C": 2, "D": 1}

# Sources autorisées à élever un statut à "confirmed" seules
CONFIRMED_TIER_B_CATEGORIES = {
    "ioda": "cables",
    "cloudflare_radar": "cables",
    "gdacs": "logistics",
    "rte_ecowatt": "electricity",
    "entsoe": "electricity",
    "hydroquebec": "electricity",
    "ceb_dataset": "electricity",
}


class Classifier:
    def __init__(self, keywords_path: Path, severity_rules_path: Path):
        with open(keywords_path, encoding="utf-8") as f:
            self._kw = json.load(f)
        with open(severity_rules_path, encoding="utf-8") as f:
            self._rules = json.load(f)

        # Précalculer les patterns de mots-clés
        self._compiled = {}
        for cat, data in self._kw.get("categories", {}).items():
            self._compiled[cat] = {
                "positive": self._compile_keywords(data.get("positive", {})),
                "negative": self._compile_keywords(data.get("negative", {})),
                "weight": data.get("weight", 1.0),
            }

    def _compile_keywords(self, kw_dict: dict) -> list[re.Pattern]:
        patterns = []
        for lang_kws in kw_dict.values():
            for kw in lang_kws:
                # Correspondance mot entier, insensible à la casse
                escaped = re.escape(kw.lower())
                patterns.append(re.compile(r"\b" + escaped + r"\b", re.IGNORECASE))
        return patterns

    def _normalize_text(self, text: str) -> str:
        """Normalise pour la comparaison de mots-clés."""
        text = text.lower()
        return "".join(
            c for c in unicodedata.normalize("NFD", text)
            if unicodedata.category(c) != "Mn"
        )

    def _score_category(self, text: str, cat: str) -> float:
        """Score de correspondance pour une catégorie."""
        data = self._compiled.get(cat, {})
        norm = self._normalize_text(text)

        # Vérifier les mots négatifs d'abord
        for pattern in data.get("negative", []):
            if pattern.search(norm):
                return 0.0

        score = 0.0
        for pattern in data.get("positive", []):
            if pattern.search(norm):
                score += 1.0

        return score * data.get("weight", 1.0)

    def classify_text(self, title: str, summary: str, source_default: str) -> tuple[str, list[str]]:
        """
        Détermine la catégorie principale et les catégories secondaires.
        Retourne (category, secondary_categories).
        """
        full_text = f"{title} {summary}"
        scores = {cat: self._score_category(full_text, cat) for cat in self._compiled}

        # Filtrer les catégories avec score > 0
        positive = {k: v for k, v in scores.items() if v > 0}

        if not positive:
            return source_default, []

        # Trier par score décroissant
        ranked = sorted(positive.items(), key=lambda x: x[1], reverse=True)
        primary = ranked[0][0]
        secondary = [cat for cat, _ in ranked[1:] if _ >= ranked[0][1] * 0.4]

        return primary, secondary[:2]  # Max 2 catégories secondaires

    def detect_status_keywords(self, text: str, tier: str) -> Optional[str]:
        """Détecte les mots-clés de résolution/démenti (comparaison sans accents)."""
        norm = self._normalize_text(text)
        for kw in _DENIED_KEYWORDS:
            if self._normalize_text(kw) in norm:
                return "denied"
        for kw in _RESOLVED_KEYWORDS:
            if self._normalize_text(kw) in norm:
                return "resolved"
        return None

    def determine_status(self, cluster_items, category: str) -> str:
        """
        Détermine le statut d'un événement selon les règles spécifiées :
        - confirmed : ≥1 tier A, OU tier B dans son domaine, OU ≥3 owners C indépendants
        - probable : 2 owners C
        - unverified : sinon
        - denied/resolved : détectés via mots-clés dans les reports
        """
        # Vérifier denied/resolved en priorité
        for item in cluster_items:
            text = f"{item.title} {item.summary_text}"
            status_kw = self.detect_status_keywords(text, item.tier)
            if status_kw in ("denied", "resolved"):
                return status_kw

        tiers = [item.tier for item in cluster_items]
        owners_c = set(item.owner for item in cluster_items if item.tier == "C")
        owners_all = set(item.owner for item in cluster_items)

        # Tier A → confirmed
        if "A" in tiers:
            return "confirmed"

        # Tier B dans son domaine → confirmed
        for item in cluster_items:
            if item.tier == "B":
                expected_cat = CONFIRMED_TIER_B_CATEGORIES.get(item.source_id)
                if expected_cat and expected_cat == category:
                    return "confirmed"

        # ≥3 owners C indépendants → confirmed
        if len(owners_c) >= 3:
            return "confirmed"

        # 2 owners C → probable
        if len(owners_c) >= 2:
            return "probable"

        # Sinon unverified
        return "unverified"

    def apply_severity_rules(self, items, category: str) -> tuple[int, str]:
        """
        Applique severity_rules.json pour obtenir la gravité.
        Retourne (severity, infrastructure_type).
        """
        best_severity = 1
        infra_type = "non_critical"
        tier_defaults = self._rules.get("default_severity_by_tier", {})
        infra_map = self._rules.get("infrastructure_importance", {})

        for item in items:
            for rule in self._rules.get("rules", []):
                conds = rule.get("conditions", {})
                if conds.get("source_id") and item.source_id != conds["source_id"]:
                    continue
                # Vérifier les conditions spécifiques via extra
                if conds.get("ecowatt_value") and item.extra.get("ecowatt_value") != conds["ecowatt_value"]:
                    continue
                if conds.get("alert_level") and item.extra.get("alert_level") != conds["alert_level"]:
                    continue
                if conds.get("event_type_in") and item.extra.get("event_type") not in conds["event_type_in"]:
                    continue
                if conds.get("event_nature") and item.extra.get("event_nature") != conds["event_nature"]:
                    continue
                if conds.get("outage_cause") and item.extra.get("outage_cause") != conds["outage_cause"]:
                    continue
                if conds.get("clients_gte") and item.extra.get("clients_count", 0) < conds["clients_gte"]:
                    continue

                sev = rule.get("severity", best_severity)
                if sev > best_severity:
                    best_severity = sev
                if rule.get("infrastructure_type"):
                    infra_type = rule["infrastructure_type"]

            # Appliquer le défaut par tier si pas de règle
            default_sev = tier_defaults.get(item.tier, 1)
            if default_sev > best_severity:
                best_severity = default_sev

        return best_severity, infra_type

    def classify_kind(self, items, category: str) -> str:
        """
        Détermine le type d'événement : vulnerability | incident | disruption | hazard.
        Les sources de vulnérabilité ont la priorité.
        """
        source_ids = {item.source_id for item in items}

        if source_ids & HAZARD_SOURCES:
            return "hazard"

        if source_ids & VULNERABILITY_SOURCES:
            return "vulnerability"

        if source_ids & INCIDENT_SOURCES:
            return "incident"

        # Keyword-based pour GDELT et autres sources génériques
        full_text = " ".join(f"{i.title} {i.summary_text}" for i in items[:3]).lower()
        disruption_kws = {"panne", "coupure", "blackout", "outage", "disruption", "interruption"}
        if any(kw in full_text for kw in disruption_kws):
            return "disruption"

        return "incident"

    def has_active_exploitation(self, items) -> bool:
        """Détecte si les items signalent une exploitation active."""
        text = " ".join(f"{i.title} {i.summary_text}" for i in items).lower()
        return any(kw in text for kw in _ACTIVE_EXPLOIT_PATTERNS)

    def has_ics_critical_sector(self, items) -> bool:
        """Détecte si les items concernent un secteur ICS/SCADA/critique."""
        text = " ".join(f"{i.title} {i.summary_text}" for i in items).lower()
        return any(kw in text for kw in _ICS_CRITICAL_PATTERNS)

    def detect_coordinated(self, items, tier: str) -> bool:
        """Campagne coordonnée uniquement si un source tier A le dit explicitement."""
        if tier != "A":
            return False
        for item in items:
            if item.tier != "A":
                continue
            text = f"{item.title} {item.summary_text}".lower()
            for kw in _COORDINATED_KEYWORDS:
                if kw in text:
                    return True
        return False
