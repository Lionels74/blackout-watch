"""Classe de base pour tous les adapters de sources."""
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """
    Interface commune pour tous les adapters.
    Chaque adapter transforme une source externe en liste de RawItems.
    """

    def __init__(self, source_cfg: dict, settings: dict):
        self.source_id: str = source_cfg["id"]
        self.source_name: str = source_cfg["name"]
        self.tier: str = source_cfg["tier"]
        self.owner: str = source_cfg["owner"]
        self.url: str = source_cfg.get("url", "")
        self.default_category: str = source_cfg.get("default_category", "geopolitics")
        self.zones_hint: list = source_cfg.get("zones_hint", [])
        self.max_age_days: int = source_cfg.get("max_age_days", 30)
        self.max_bytes: int | None = source_cfg.get("max_bytes", None)
        self.settings = settings

    @abstractmethod
    def fetch(self, http_client, run_counter: int = 0) -> list:
        """
        Récupère et normalise les items de la source.
        Retourne une liste de RawItem.
        Lève une exception sur tout échec réseau, HTTP ≠ 200, corps vide, parse KO.
        Les erreurs sur des items individuels sont loggées + ignorées (graceful degradation).
        """
        pass

    def _safe_fetch(self, http_client, run_counter: int = 0) -> list:
        """Wrapper qui attrape toutes les exceptions et retourne [] en cas d'erreur."""
        try:
            return self.fetch(http_client, run_counter)
        except Exception as e:
            logger.error("Adapter %s : erreur inattendue : %s", self.source_id, e, exc_info=True)
            return []
