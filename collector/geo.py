"""Géolocalisation : pays affecté et origine de la menace."""
import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Optional


logger = logging.getLogger(__name__)


class GeoResolver:
    def __init__(self, gazetteer_path: Path, threat_actors_path: Path, zones_path: Path):
        with open(gazetteer_path, encoding="utf-8") as f:
            self._gaz = json.load(f)
        with open(threat_actors_path, encoding="utf-8") as f:
            self._actors = json.load(f)
        with open(zones_path, encoding="utf-8") as f:
            self._zones_cfg = json.load(f)

        # Index inversé : nom normalisé → code ISO
        self._name_to_iso: dict[str, str] = {}
        for iso, data in self._gaz.get("countries", {}).items():
            for name in data.get("names", []):
                self._name_to_iso[self._norm(name)] = iso

        # Index secondaire : ensemble de mots → ISO (pour matching mots entiers sans sous-chaîne)
        self._words_to_iso: dict[frozenset, set[str]] = {}
        for norm_name, iso in self._name_to_iso.items():
            words = frozenset(re.findall(r'\w+', norm_name))
            if words:
                self._words_to_iso.setdefault(words, set()).add(iso)

        # Index acteurs : alias normalisé → actor_id
        self._alias_to_actor: dict[str, str] = {}
        for actor_id, data in self._actors.get("actors", {}).items():
            self._alias_to_actor[self._norm(actor_id)] = actor_id
            for alias in data.get("aliases", []):
                self._alias_to_actor[self._norm(alias)] = actor_id

    def _norm(self, text: str) -> str:
        """Normalise pour la comparaison."""
        text = text.lower()
        return "".join(
            c for c in unicodedata.normalize("NFD", text)
            if unicodedata.category(c) != "Mn"
        )

    def resolve_countries(self, hints: list[str]) -> list[str]:
        """
        Résout une liste de noms/hints en codes ISO.
        Sépare les chaînes comma-separated (ex: "Chad, Nigeria, Cameroon").
        Matching par mots entiers uniquement — pas de sous-chaîne.
        Retourne les codes ISO uniques trouvés.
        """
        found = set()
        for hint in hints:
            for part in [p.strip() for p in hint.split(",") if p.strip()]:
                norm = self._norm(part)
                if not norm:
                    continue
                # 1. Correspondance exacte
                if norm in self._name_to_iso:
                    found.add(self._name_to_iso[norm])
                    continue
                # 2. Mots entiers : frozenset de mots du hint == frozenset de mots du nom
                part_words = frozenset(re.findall(r'\w+', norm))
                if part_words and part_words in self._words_to_iso:
                    found.update(self._words_to_iso[part_words])
        return sorted(found)

    def iso_to_zones(self, iso_codes: list[str]) -> list[str]:
        """Mappe des codes ISO vers les zones BLACKOUT WATCH."""
        zones = set()
        for iso in iso_codes:
            country_data = self._gaz.get("countries", {}).get(iso, {})
            for zone in country_data.get("zones", []):
                zones.add(zone)
        return sorted(zones)

    def get_infrastructure_importance(self, iso_codes: list[str], zone: str) -> tuple[str, float]:
        """
        Détermine le type et l'importance de l'infrastructure.
        Retourne (infrastructure_type, importance_factor).
        """
        zones_cfg = self._zones_cfg.get("zones", {})

        # National si le pays est une zone principale
        for iso in iso_codes:
            country_data = self._gaz.get("countries", {}).get(iso, {})
            country_zones = country_data.get("zones", [])
            if any(z in ["france", "canada", "quebec", "mauritius"] for z in country_zones):
                if zone in country_zones:
                    return "national", 1.0
                return "regional", 0.7

        # Systémique
        for iso in iso_codes:
            if self._gaz.get("countries", {}).get(iso, {}).get("systemic"):
                return "national", 1.0

        return "non_critical", 0.2

    def resolve_threat_actor(self, text: str) -> Optional[tuple[str, str]]:
        """
        Détecte un acteur de menace dans le texte.
        Retourne (actor_id, origin_country) ou None.
        """
        norm = self._norm(text)
        for alias, actor_id in self._alias_to_actor.items():
            if alias in norm:
                actor_data = self._actors.get("actors", {}).get(actor_id, {})
                return actor_id, actor_data.get("origin_country", "")
        return None

    def get_proximity(self, affected_zones: list[str], target_zone: str) -> float:
        """
        Calcule P(z) selon les règles de zones.
        """
        if target_zone in affected_zones:
            return 1.0

        zones_cfg = self._zones_cfg.get("zones", {})
        target_cfg = zones_cfg.get(target_zone, {})
        proximity_rules = self._zones_cfg.get("proximity_rules", {})

        # Voisin interconnecté
        for zone in affected_zones:
            zone_cfg = zones_cfg.get(zone, {})
            # Vérifier les ISO codes des zones affectées vs voisins de la cible
            affected_iso = zone_cfg.get("iso_codes", [])
            target_neighbors = target_cfg.get("neighbors_interconnected", [])
            if any(iso in target_neighbors for iso in affected_iso):
                return proximity_rules.get("neighbor_interconnected", 0.5)

            # Même macro-région
            if zone_cfg.get("macro_region") == target_cfg.get("macro_region"):
                return proximity_rules.get("same_macro_region", 0.25)

        # Règle spéciale Global
        if target_zone == "global":
            return 0.6

        # Québec → Canada
        if "quebec" in affected_zones and target_zone == "canada":
            return 0.7
        if "canada" in affected_zones and target_zone == "quebec":
            return 0.7

        return proximity_rules.get("default", 0.05)

    def is_systemic_node(self, iso_codes: list[str]) -> bool:
        """Vérifie si l'événement affecte un nœud systémique."""
        systemic = self._zones_cfg.get("systemic_nodes", [])
        return any(iso in systemic for iso in iso_codes)
