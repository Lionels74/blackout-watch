"""Déduplication et clustering d'événements."""
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from .normalize import RawItem, normalize_text

logger = logging.getLogger(__name__)

WINDOW_HOURS = 72  # fenêtre de déduplication par défaut
JACCARD_THRESHOLD = 0.6
SYNDICATION_THRESHOLD = 0.85


def jaccard_tokens(text_a: str, text_b: str) -> float:
    """Indice de Jaccard sur les ensembles de tokens normalisés."""
    tokens_a = set(normalize_text(text_a).split())
    tokens_b = set(normalize_text(text_b).split())
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def _items_match(item_a: RawItem, item_b: RawItem,
                 window_hours: int, jaccard_thresh: float) -> bool:
    """Vérifie si deux items appartiennent au même événement."""
    # Fusion sur identifiant fort
    if item_a.raw_ids and item_b.raw_ids:
        common = set(item_a.raw_ids) & set(item_b.raw_ids)
        if common:
            return True

    # Vérifier la fenêtre temporelle
    dt = abs((item_a.published_at - item_b.published_at).total_seconds()) / 3600
    if dt > window_hours:
        return False

    # Même catégorie implicite (via source) + similarité titre
    if jaccard_tokens(item_a.title, item_b.title) >= jaccard_thresh:
        return True

    return False


def _is_syndication(item_a: RawItem, item_b: RawItem, thresh: float) -> bool:
    """
    Deux reports d'owners différents avec Jaccard ≥ thresh = syndication.
    Syndication = une seule origine (n_owners ne compte pas +1).
    """
    if item_a.owner == item_b.owner:
        return False
    return jaccard_tokens(item_a.title, item_b.title) >= thresh


class Cluster:
    """Groupe d'items représentant un même événement."""

    def __init__(self, initial: RawItem):
        self.items: list[RawItem] = [initial]
        self.raw_ids: set = set(initial.raw_ids)
        self.syndicated_pairs: list[tuple[str, str]] = []

    def add(self, item: RawItem, is_syndication: bool = False):
        self.items.append(item)
        self.raw_ids.update(item.raw_ids)
        if is_syndication:
            self.syndicated_pairs.append((self.items[0].owner, item.owner))

    @property
    def n_owners(self) -> int:
        """Nombre d'owners distincts, en tenant compte des syndications."""
        all_owners = [i.owner for i in self.items]
        unique = set(all_owners)
        # Pour chaque paire de syndication, réduire de 1 (ils comptent comme une origine)
        # Simplification : on retire les owners qui n'apparaissent que dans des paires syndiquées
        syndicated_owners = set()
        for a, b in self.syndicated_pairs:
            # L'owner secondaire d'une syndication n'apporte pas d'indépendance
            syndicated_owners.add(b)
        independent = unique - syndicated_owners
        return max(1, len(independent))

    @property
    def max_tier(self) -> str:
        tiers = {"A": 4, "B": 3, "C": 2, "D": 1}
        best = max(self.items, key=lambda i: tiers.get(i.tier, 0))
        return best.tier

    @property
    def published_at(self) -> datetime:
        return min(i.published_at for i in self.items)


def cluster_items(
    items: list[RawItem],
    window_hours: int = WINDOW_HOURS,
    jaccard_thresh: float = JACCARD_THRESHOLD,
    syndication_thresh: float = SYNDICATION_THRESHOLD,
) -> list[Cluster]:
    """
    Groupe les items en clusters d'événements.
    Algorithme glouton : O(n²) acceptable pour les volumes attendus (< 10 000 items).
    """
    clusters: list[Cluster] = []

    for item in items:
        matched = False
        for cluster in clusters:
            # Vérifier si l'item correspond à l'un des items du cluster
            for existing in cluster.items:
                if _items_match(existing, item, window_hours, jaccard_thresh):
                    is_syn = _is_syndication(existing, item, syndication_thresh)
                    cluster.add(item, is_syndication=is_syn)
                    matched = True
                    break
            if matched:
                break
        if not matched:
            clusters.append(Cluster(item))

    logger.info("Déduplication : %d items → %d clusters", len(items), len(clusters))
    return clusters
