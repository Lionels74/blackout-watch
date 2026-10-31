"""
Calcul des scores BLACKOUT WATCH.
Formules version 1.0 — voir docs/SCORING.md pour la documentation complète.
"""
import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Ensembles de sources importés depuis classify pour l'inférence de kind
_VULNERABILITY_SOURCES = frozenset([
    "cert_fr_alerte", "cert_fr_avis", "cert_fr_cti", "cert_fr_actualite",
    "cert_fr_scada", "cisa_advisories", "cisa_alerts", "cisa_ics", "cisa_kev",
    "cccs_fr", "cccs_en", "cert_eu", "ncsc_uk",
])
_HAZARD_SOURCES = frozenset(["gdacs"])

logger = logging.getLogger(__name__)

CATEGORIES = ["electricity", "cables", "finance", "cyber", "logistics", "geopolitics"]
ZONES = ["global", "france", "canada", "quebec", "mauritius"]
LEVELS = [
    (0, 19, "NORMAL"),
    (20, 39, "VIGILANCE"),
    (40, 59, "PRÉALERTE"),
    (60, 79, "ALERTE ÉLEVÉE"),
    (80, 100, "CRITIQUE"),
]


def _incident_kind(inc: dict) -> str:
    """Retourne le kind de l'incident, en l'inférant depuis les sources si absent."""
    kind = inc.get("kind")
    if kind:
        return kind
    source_ids = {r.get("source_id", "") for r in inc.get("reports", [])}
    if source_ids & _HAZARD_SOURCES:
        return "hazard"
    if source_ids & _VULNERABILITY_SOURCES:
        return "vulnerability"
    return "incident"


def get_level(index: float) -> str:
    for low, high, label in LEVELS:
        if low <= index <= high:
            return label
    return "CRITIQUE" if index > 80 else "NORMAL"


class Scorer:
    def __init__(self, settings: dict, zones_path: Path, deps_path: Path):
        s = settings.get("scoring", {})
        self.category_weights: dict[str, float] = s.get("category_weights", {})
        self.half_life: dict[str, float] = s.get("half_life_hours", {})
        self.max_ongoing: dict[str, int] = s.get("max_ongoing_days", {})
        self.version: str = s.get("version", "1.0")

        with open(zones_path, encoding="utf-8") as f:
            self._zones_cfg = json.load(f)
        with open(deps_path, encoding="utf-8") as f:
            self._deps = json.load(f)

        systemic_path = zones_path.parent / "systemic_nodes.json"
        if systemic_path.exists():
            with open(systemic_path, encoding="utf-8") as f:
                self._systemic_cfg = json.load(f)
        else:
            self._systemic_cfg = {
                "interconnected_countries": self._zones_cfg.get("systemic_nodes", []),
                "chokepoints": [],
            }

    # ------------------------------------------------------------------ #
    # Facteur T : décroissance temporelle                                  #
    # ------------------------------------------------------------------ #
    def T(self, category: str, published_at: datetime, is_ongoing: bool,
          status: str) -> float:
        now = datetime.now(timezone.utc)
        delta_hours = (now - published_at).total_seconds() / 3600
        h_c = self.half_life.get(category, 72)

        if status == "resolved":
            h_c = h_c / 3

        if is_ongoing and status == "confirmed":
            max_days = self.max_ongoing.get(category, 14)
            if delta_hours <= max_days * 24:
                return 1.0
            # Après max_ongoing_days, décroissance normale
        return 2 ** (-delta_hours / h_c)

    # ------------------------------------------------------------------ #
    # Facteur G : gravité normalisée                                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def G(severity: int) -> float:
        return severity / 5.0

    # ------------------------------------------------------------------ #
    # Facteur K : fiabilité × validation                                   #
    # ------------------------------------------------------------------ #
    @staticmethod
    def K(tier: str, status: str, n_owners: int) -> float:
        R_map = {"A": 1.0, "B": 0.85, "C": 0.6, "D": 0.3}
        V_map = {
            "confirmed": 1.0,
            "probable": 0.7,
            "unverified": 0.35,
            "denied": 0.0,
            "resolved": 1.0,
        }
        R = R_map.get(tier, 0.3)
        V = V_map.get(status, 0.35)
        # R_max + 0.1 × (n-1), plafonné à 1
        R_adj = min(1.0, R + 0.1 * (n_owners - 1))
        return V * R_adj

    # ------------------------------------------------------------------ #
    # Facteur P : proximité géographique                                   #
    # ------------------------------------------------------------------ #
    def P(self, affected_zones: list[str], target_zone: str,
          n_countries: int = 1, kind: str = "incident",
          affected_countries: Optional[list[str]] = None) -> float:
        # Hazard global : P réduit sauf ≥2 pays interconnectés ou touche un point de passage
        if target_zone == "global" and kind == "hazard":
            interconnected = set(self._systemic_cfg.get("interconnected_countries", []))
            chokepoints = self._systemic_cfg.get("chokepoints", [])
            n_interconnected = sum(
                1 for c in (affected_countries or []) if c in interconnected
            )
            touches_chokepoint = any(
                c in cp.get("adjacent_countries", [])
                for cp in chokepoints
                for c in (affected_countries or [])
            )
            if n_interconnected >= 2 or touches_chokepoint:
                return 0.6
            return 0.15

        if target_zone in affected_zones:
            return 1.0

        # Règle spéciale Global (non-hazard)
        if target_zone == "global":
            if n_countries >= 2:
                return 1.0
            return 0.6

        # Règle Québec ↔ Canada
        if "quebec" in affected_zones and target_zone == "canada":
            return 0.7
        if "canada" in affected_zones and target_zone == "quebec":
            return 0.7

        zones_cfg = self._zones_cfg.get("zones", {})
        target_cfg = zones_cfg.get(target_zone, {})
        prox_rules = self._zones_cfg.get("proximity_rules", {})

        for azone in affected_zones:
            az_cfg = zones_cfg.get(azone, {})
            az_iso = az_cfg.get("iso_codes", [])
            target_neighbors = target_cfg.get("neighbors_interconnected", [])
            if any(iso in target_neighbors for iso in az_iso):
                return prox_rules.get("neighbor_interconnected", 0.5)

            if az_cfg.get("macro_region") == target_cfg.get("macro_region"):
                return prox_rules.get("same_macro_region", 0.25)

        return prox_rules.get("default", 0.05)

    # ------------------------------------------------------------------ #
    # Facteur I : importance de l'infrastructure                           #
    # ------------------------------------------------------------------ #
    @staticmethod
    def I(infrastructure_type: str) -> float:
        I_map = {
            "national": 1.0,
            "regional": 0.7,
            "local": 0.4,
            "non_critical": 0.2,
        }
        return I_map.get(infrastructure_type, 0.2)

    # ------------------------------------------------------------------ #
    # Facteur D : durée                                                    #
    # ------------------------------------------------------------------ #
    @staticmethod
    def D(duration_hours: Optional[float]) -> float:
        if duration_hours is None:
            return 0.8  # inconnu
        return 0.6 + 0.4 * min(1.0, math.log(1 + duration_hours) / math.log(73))

    # ------------------------------------------------------------------ #
    # Facteur S : propagation                                              #
    # ------------------------------------------------------------------ #
    @staticmethod
    def S(affected_zones: list[str], secondary_categories: list[str]) -> float:
        if secondary_categories and len(affected_zones) > 1:
            return 1.4  # cascade intersectorielle
        if len(affected_zones) > 1:
            return 1.2  # multi-zones
        return 1.0

    # ------------------------------------------------------------------ #
    # Score d'un événement pour une zone                                   #
    # ------------------------------------------------------------------ #
    def event_score(self, incident: dict, zone: str) -> tuple[float, dict]:
        """
        E(i,z) = 100 × G × K × P(z) × I × D × S × T, plafonné à 100.
        Retourne (score, factors).
        """
        severity = incident.get("severity", 1)
        category = incident.get("category", "geopolitics")
        status = incident.get("status", "unverified")
        is_ongoing = incident.get("is_ongoing", False)
        duration = incident.get("duration_hours")
        sec_cats = incident.get("secondary_categories", [])

        affected = incident.get("affected", {})
        affected_zones = affected.get("zones", [])
        infra_type = affected.get("infrastructure_type", "non_critical")
        n_countries = len(affected.get("countries", []))

        conf = incident.get("confidence", {})
        tier = conf.get("max_tier", "D")
        n_owners = conf.get("n_owners", 1)

        # Calculer published_at
        try:
            pub_str = incident.get("published_at", "")
            pub_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
        except Exception:
            pub_at = datetime.now(timezone.utc)

        inc_kind = _incident_kind(incident)
        affected_countries_list = affected.get("countries", [])

        g = self.G(severity)
        k = self.K(tier, status, n_owners)
        p = self.P(affected_zones, zone, n_countries,
                   kind=inc_kind, affected_countries=affected_countries_list)
        i_factor = self.I(infra_type)
        d = self.D(duration)
        s = self.S(affected_zones, sec_cats)
        t = self.T(category, pub_at, is_ongoing, status)

        raw = 100 * g * k * p * i_factor * d * s * t
        score = min(100.0, raw)

        factors = {
            "G": round(g, 4), "K": round(k, 4), "P": round(p, 4),
            "I": round(i_factor, 4), "D": round(d, 4), "S": round(s, 4),
            "T": round(t, 4), "raw": round(raw, 2),
        }
        return round(score, 2), factors

    # ------------------------------------------------------------------ #
    # Score d'une catégorie                                                #
    # ------------------------------------------------------------------ #
    def category_score(
        self, incidents: list[dict], zone: str, category: str
    ) -> tuple[float, list[str], list[str], list[str]]:
        """
        S(c,z) = 100 × [1 − Π(1 − E(i,z)/100)].
        Applique ensuite les caps et planchers dans l'ordre.
        Retourne (score, caps_applied, floors_applied, contributing_incident_ids).
        """
        relevant = [
            inc for inc in incidents
            if (inc.get("category") == category or category in inc.get("secondary_categories", []))
            and inc.get("status") != "denied"
        ]

        if not relevant:
            return 0.0, [], [], []

        # Calculer les scores individuels
        event_scores = []
        for inc in relevant:
            es, _ = self.event_score(inc, zone)
            # Catégorie secondaire : facteur 0.5
            if inc.get("category") != category:
                es *= 0.5
            event_scores.append((inc["id"], es))

        # S(c,z) = 100 × [1 − Π(1 − E(i,z)/100)]
        product = 1.0
        for _, es in event_scores:
            product *= (1 - es / 100.0)
        score = 100.0 * (1.0 - product)

        caps = []
        floors = []
        contributing = [inc_id for inc_id, _ in event_scores if _ > 0]

        # a) vulnerability-only cap : jamais > 19 si tous les incidents sont kind=vulnerability
        all_vulnerability = relevant and all(
            _incident_kind(inc) == "vulnerability" for inc in relevant
        )
        if all_vulnerability and score > 19:
            score = 19.0
            caps.append("vulnerability_cap_19")

        # a2) hazard-only cap : jamais > 39 si tous sont kind=hazard
        #     (si un disruption confirmé est présent, all_hazard=False → cap non appliqué)
        all_hazard = relevant and all(_incident_kind(inc) == "hazard" for inc in relevant)
        if all_hazard and score > 39:
            score = 39.0
            caps.append("hazard_cap_39")

        # b) Score sans unverified (vulnerability traité comme unverified) < 40 → S ≤ 39
        verified_product = 1.0
        for inc, (inc_id, es) in zip(relevant, event_scores):
            is_effectively_verified = (
                inc.get("status") != "unverified"
                and _incident_kind(inc) != "vulnerability"
            )
            if is_effectively_verified:
                verified_product *= (1 - es / 100.0)
        verified_score = 100.0 * (1.0 - verified_product)
        if verified_score < 40 and score > 39:
            score = min(score, 39.0)
            caps.append("unverified_cap_39")

        # c) S ≥ 80 exige ≥1 confirmed tier A/B NON-vulnerability
        has_authoritative = any(
            _incident_kind(inc) != "vulnerability"
            and inc.get("status") == "confirmed"
            and inc.get("confidence", {}).get("max_tier") in ("A", "B")
            for inc in relevant
        )
        if score >= 80 and not has_authoritative:
            score = min(score, 79.0)
            caps.append("no_authoritative_cap_79")

        # c) Tous tier C/D avec n=1 → S ≤ 59
        all_cd_n1 = all(
            inc.get("confidence", {}).get("max_tier") in ("C", "D")
            and inc.get("confidence", {}).get("n_owners", 1) == 1
            for inc in relevant
        )
        if all_cd_n1 and score > 59:
            score = min(score, 59.0)
            caps.append("all_cd_n1_cap_59")

        # d) Planchers officiels
        for inc in relevant:
            source_id = inc.get("reports", [{}])[0].get("source_id", "") if inc.get("reports") else ""
            # Ecowatt
            ecowatt_val = inc.get("extra", {}).get("ecowatt_value")
            if source_id == "rte_ecowatt" and category == "electricity" and zone == "france":
                if ecowatt_val == 3 and score < 65:
                    score = 65.0
                    floors.append("ecowatt_3_floor_65")
                elif ecowatt_val == 2 and score < 40:
                    score = 40.0
                    floors.append("ecowatt_2_floor_40")
            # GDACS
            if source_id == "gdacs" and category in ("electricity", "logistics"):
                alert_level = inc.get("extra", {}).get("alert_level")
                affected_zones = inc.get("affected", {}).get("zones", [])
                if zone == "mauritius" and zone in affected_zones:
                    if alert_level == "Red" and score < 50:
                        score = 50.0
                        floors.append("gdacs_red_floor_50")
                    elif alert_level == "Orange" and score < 30:
                        score = 30.0
                        floors.append("gdacs_orange_floor_30")

        return round(min(score, 100.0), 2), caps, floors, contributing

    # ------------------------------------------------------------------ #
    # Index de zone                                                        #
    # ------------------------------------------------------------------ #
    def zone_index(
        self, category_scores: dict[str, float], convergence_index: float
    ) -> tuple[float, float]:
        """
        B = Σ w_c S_c
        Z = max(B, 0.7 × max_c S_c)
        Z' = min(100, Z × (1 + 0.2 × CI/100))
        Retourne (Z_raw, Z_prime).
        """
        total_weight = sum(self.category_weights.values())
        if total_weight == 0:
            return 0.0, 0.0

        B = sum(
            self.category_weights.get(cat, 0) * score / total_weight
            for cat, score in category_scores.items()
        )
        max_score = max(category_scores.values()) if category_scores else 0.0
        Z = max(B, 0.7 * max_score)
        Z_prime = min(100.0, Z * (1 + 0.2 * convergence_index / 100.0))
        return round(Z, 2), round(Z_prime, 2)

    # ------------------------------------------------------------------ #
    # Indice de convergence                                                #
    # ------------------------------------------------------------------ #
    def convergence_index(
        self, category_scores: dict[str, float], incidents: list[dict], zone: str
    ) -> tuple[float, list[dict]]:
        """
        CI = 100 × Σ d_ab √(S_a S_b)/100 ÷ Σ d_ab
        Sur les catégories avec S ≥ 20.
        links = couples d'incidents de catégories différentes, même pays, écart ≤ 48h.
        """
        active = {cat: s for cat, s in category_scores.items() if s >= 20}
        links_cfg = self._deps.get("links", {})

        if len(active) < 2:
            return 0.0, []

        numerator = 0.0
        denominator = 0.0
        for cat_a in active:
            for cat_b in active:
                if cat_a >= cat_b:
                    continue
                key = f"{cat_a}_{cat_b}" if f"{cat_a}_{cat_b}" in links_cfg else f"{cat_b}_{cat_a}"
                d = links_cfg.get(key, {}).get("d", 0.0)
                if d > 0:
                    s_a = active[cat_a]
                    s_b = active[cat_b]
                    numerator += d * math.sqrt(s_a * s_b) / 100.0
                    denominator += d

        ci = (100.0 * numerator / denominator) if denominator > 0 else 0.0

        # Identifier les liens incidents
        links = []
        for i, inc_a in enumerate(incidents):
            for inc_b in incidents[i + 1:]:
                if inc_a.get("category") == inc_b.get("category"):
                    continue
                # Même pays
                countries_a = set(inc_a.get("affected", {}).get("countries", []))
                countries_b = set(inc_b.get("affected", {}).get("countries", []))
                if not countries_a & countries_b:
                    continue
                # Écart ≤ 48h
                try:
                    t_a = datetime.fromisoformat(inc_a["published_at"].replace("Z", "+00:00"))
                    t_b = datetime.fromisoformat(inc_b["published_at"].replace("Z", "+00:00"))
                    if abs((t_a - t_b).total_seconds()) > 48 * 3600:
                        continue
                except Exception:
                    continue
                common_country = list(countries_a & countries_b)[0]
                links.append({
                    "incident_a": inc_a["id"],
                    "incident_b": inc_b["id"],
                    "category_a": inc_a["category"],
                    "category_b": inc_b["category"],
                    "country": common_country,
                })

        return round(ci, 2), links

    # ------------------------------------------------------------------ #
    # Indice de confiance                                                  #
    # ------------------------------------------------------------------ #
    def confidence_index(
        self,
        incidents: list[dict],
        zone: str,
        source_health: dict,
        sources_cfg: list[dict],
        collection_window_hours: float = 3.0,
    ) -> tuple[float, float, float, float, list[str], bool]:
        """
        CoI = 100 × Q × F × C
        Q = Σ(E·K)/ΣE
        F = part des sources de la zone collectées avec succès dans les 3 h
        C = part des 6 catégories couvertes par ≥1 source collectée dans les 3 h
        Retourne (CoI, Q, F, C, covered_categories, has_zone_sources).
        F=0 ou C=0 → CoI=0 (garde explicite).
        """
        # Q : qualité pondérée des événements
        sum_ek = 0.0
        sum_e = 0.0
        for inc in incidents:
            if inc.get("affected", {}).get("zones", []) and zone not in inc["affected"]["zones"]:
                continue
            es, _ = self.event_score(inc, zone)
            conf = inc.get("confidence", {})
            k = self.K(
                conf.get("max_tier", "D"),
                inc.get("status", "unverified"),
                conf.get("n_owners", 1),
            )
            sum_ek += es * k
            sum_e += es

        Q = (sum_ek / sum_e) if sum_e > 0 else 1.0

        # F : fraîcheur des sources (collecte réussie dans collection_window_hours)
        now = datetime.now(timezone.utc)
        zone_sources = [
            s for s in sources_cfg
            if s.get("enabled") and not s.get("excluded")
            and zone in s.get("zones_hint", [])
        ]
        has_zone_sources = len(zone_sources) > 0
        if zone_sources:
            healthy_count = 0
            for src in zone_sources:
                h = source_health.get(src["id"], {})
                last_success = h.get("last_success_ts")
                if last_success:
                    try:
                        ts = datetime.fromisoformat(last_success.replace("Z", "+00:00"))
                        age = (now - ts).total_seconds() / 3600
                        if age <= collection_window_hours:
                            healthy_count += 1
                    except Exception:
                        pass
            F = healthy_count / len(zone_sources)
        else:
            F = 0.0

        if F == 0.0:
            return 0.0, round(Q, 4), 0.0, 0.0, [], has_zone_sources

        # C : couverture catégories — uniquement sources collectées dans les 3 h
        covered_cats: set[str] = set()
        for src in zone_sources:
            h = source_health.get(src["id"], {})
            last_success = h.get("last_success_ts")
            if last_success:
                try:
                    ts = datetime.fromisoformat(last_success.replace("Z", "+00:00"))
                    age = (now - ts).total_seconds() / 3600
                    if age <= collection_window_hours:
                        cat = src.get("default_category")
                        if cat:
                            covered_cats.add(cat)
                except Exception:
                    pass
        C = len(covered_cats) / 6.0

        if C == 0.0:
            return 0.0, round(Q, 4), round(F, 4), 0.0, [], has_zone_sources

        CoI = 100.0 * Q * F * C
        return round(CoI, 2), round(Q, 4), round(F, 4), round(C, 4), sorted(covered_cats), has_zone_sources

    # ------------------------------------------------------------------ #
    # Calcul complet pour toutes les zones                                  #
    # ------------------------------------------------------------------ #
    def compute_all(
        self,
        incidents: list[dict],
        source_health: dict,
        sources_cfg: list[dict],
        last_successful_run_ts: Optional[str] = None,
    ) -> dict:
        """
        Calcule les scores pour toutes les zones et catégories.
        Retourne le dict complet pour scores.json.
        """
        now = datetime.now(timezone.utc)

        # Fraîcheur des données
        stale = False
        stale_warning = False
        if last_successful_run_ts:
            try:
                ts = datetime.fromisoformat(last_successful_run_ts.replace("Z", "+00:00"))
                age_h = (now - ts).total_seconds() / 3600
                stale = age_h > 12
                stale_warning = not stale and age_h > 3
            except Exception:
                pass

        result = {
            "generated_at": now.isoformat(),
            "scoring_version": self.version,
            "stale": stale,
            "stale_warning": stale_warning,
            "zones": {},
        }

        for zone in ZONES:
            cat_scores = {}
            all_caps = {}
            all_floors = {}
            all_contributing = {}

            for cat in CATEGORIES:
                score, caps, floors, contributing = self.category_score(incidents, zone, cat)
                cat_scores[cat] = score
                all_caps[cat] = caps
                all_floors[cat] = floors
                all_contributing[cat] = contributing

            ci, links = self.convergence_index(cat_scores, incidents, zone)
            z_raw, z_prime = self.zone_index(cat_scores, ci)
            coi, Q, F, C, covered_cats, has_zone_sources = self.confidence_index(
                incidents, zone, source_health, sources_cfg
            )

            # Statut de couverture
            if not has_zone_sources:
                coverage_status = "non_couvert"
            elif F == 0.0:
                coverage_status = "COUVERTURE_NULLE"
            elif C < 0.5 or coi < 40:
                coverage_status = "DONNEES_PARTIELLES"
            else:
                coverage_status = "OK"

            uncovered_cats = sorted(set(CATEGORIES) - set(covered_cats))

            # Zone sans sources : index null (aucune propagation ne justifie un niveau)
            if coverage_status == "non_couvert":
                z_prime = None
                z_raw = None
                level_str = None
            elif coverage_status in ("COUVERTURE_NULLE", "DONNEES_PARTIELLES"):
                z_prime = min(z_prime, 59.0)
                level_str = get_level(z_prime)
            else:
                level_str = get_level(z_prime)

            result["zones"][zone] = {
                "index": z_prime,
                "index_raw": z_raw,
                "level": level_str,
                "convergence_index": ci,
                "confidence": {"index": coi, "Q": Q, "F": F, "C": C},
                "coverage": {
                    "fraction": round(C, 4),
                    "status": coverage_status,
                    "covered_categories": covered_cats,
                    "uncovered_categories": uncovered_cats,
                },
                "categories": {
                    cat: {
                        "score": cat_scores[cat],
                        "caps_applied": all_caps[cat],
                        "floors_applied": all_floors[cat],
                        "contributing_incidents": all_contributing[cat],
                    }
                    for cat in CATEGORIES
                },
                "convergence_links": links,
            }

        return result
