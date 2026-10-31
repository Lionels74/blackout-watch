"""Client HTTP avec cache conditionnel, circuit breaker et retry."""
import json
import logging
import time
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Valeurs par défaut (remplacées par settings à l'usage)
DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 2
DEFAULT_MAX_BYTES = 5_242_880  # 5 Mo
DEFAULT_UA = "BlackoutWatch/1.0 (+https://github.com/signalead/blackout-watch)"


class CircuitOpenError(Exception):
    pass


class HttpClient:
    def __init__(self, settings: dict, cache_path: Path, health_path: Path):
        self.timeout = settings.get("collection", {}).get("timeout_seconds", DEFAULT_TIMEOUT)
        self.max_retries = settings.get("collection", {}).get("max_retries", DEFAULT_RETRIES)
        self.max_bytes = settings.get("collection", {}).get("max_response_bytes", DEFAULT_MAX_BYTES)
        self.user_agent = settings.get("collection", {}).get("user_agent", DEFAULT_UA)
        self.cb_failures = settings.get("collection", {}).get("circuit_breaker_failures", 5)
        self.cb_skip_runs = settings.get("collection", {}).get("circuit_breaker_skip_runs", 6)

        self.cache_path = cache_path
        self.health_path = health_path

        self._cache: dict = {}
        self._health: dict = {}
        self._load_state()

    def _load_state(self):
        if self.cache_path.exists():
            try:
                self._cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                self._cache = {}
        if self.health_path.exists():
            try:
                self._health = json.loads(self.health_path.read_text(encoding="utf-8"))
            except Exception:
                self._health = {}

    def save_state(self):
        """Persiste cache et health sur disque (appelé en fin de run)."""
        _atomic_write(self.cache_path, json.dumps(self._cache, ensure_ascii=False, indent=2))
        _atomic_write(self.health_path, json.dumps(self._health, ensure_ascii=False, indent=2))

    def _check_circuit(self, source_id: str, run_counter: int) -> bool:
        """Retourne True si la source est utilisable."""
        h = self._health.get(source_id, {})
        failures = h.get("consecutive_failures", 0)
        skip_until = h.get("skip_until_run", 0)
        if failures >= self.cb_failures and run_counter < skip_until:
            return False
        return True

    def _record_success(self, source_id: str):
        from datetime import datetime, timezone
        self._health.setdefault(source_id, {})
        self._health[source_id]["consecutive_failures"] = 0
        self._health[source_id]["last_success_ts"] = datetime.now(timezone.utc).isoformat()

    def _record_failure(self, source_id: str, run_counter: int):
        h = self._health.setdefault(source_id, {})
        h["consecutive_failures"] = h.get("consecutive_failures", 0) + 1
        if h["consecutive_failures"] >= self.cb_failures:
            h["skip_until_run"] = run_counter + self.cb_skip_runs
            logger.warning(
                "Circuit ouvert pour %s (%d échecs consécutifs), skip jusqu'au run %d",
                source_id, h["consecutive_failures"], h["skip_until_run"]
            )

    def get(self, source_id: str, url: str, run_counter: int = 0,
            extra_headers: Optional[dict] = None,
            max_bytes: Optional[int] = None) -> Optional[bytes]:
        """
        Requête GET avec cache ETag/If-Modified-Since.
        Lève CircuitOpenError si la source est en circuit ouvert.
        Retourne None si la source n'a pas changé (304).
        Retourne bytes du corps si succès.
        """
        if not self._check_circuit(source_id, run_counter):
            raise CircuitOpenError(f"Circuit ouvert pour {source_id}")

        cached = self._cache.get(url, {})
        headers = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "gzip, deflate",
        }
        if extra_headers:
            headers.update(extra_headers)
        if cached.get("etag"):
            headers["If-None-Match"] = cached["etag"]
        if cached.get("last_modified"):
            headers["If-Modified-Since"] = cached["last_modified"]

        last_error = None
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                time.sleep(2 ** attempt)  # backoff exponentiel
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    resp = client.get(url, headers=headers)

                if resp.status_code == 304:
                    # Pas de changement — retourner le contenu mis en cache si disponible
                    self._record_success(source_id)
                    return None

                resp.raise_for_status()

                # Vérifier la taille (max_bytes par source si fourni, sinon global)
                content = resp.content
                effective_max = max_bytes if max_bytes is not None else self.max_bytes
                if len(content) > effective_max:
                    raise ValueError(f"Réponse trop volumineuse : {len(content)} > {effective_max}")

                # Mettre à jour le cache conditionnel
                cache_entry = {}
                if resp.headers.get("ETag"):
                    cache_entry["etag"] = resp.headers["ETag"]
                if resp.headers.get("Last-Modified"):
                    cache_entry["last_modified"] = resp.headers["Last-Modified"]
                if cache_entry:
                    self._cache[url] = cache_entry

                if not content:
                    raise ValueError(f"Corps de réponse vide pour {url} (HTTP {resp.status_code})")

                self._record_success(source_id)
                return content

            except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as e:
                last_error = e
                logger.warning("Tentative %d/%d échouée pour %s : %s", attempt + 1, self.max_retries + 1, url, e)

        self._record_failure(source_id, run_counter)
        logger.error("Échec définitif pour %s après %d tentatives : %s", url, self.max_retries + 1, last_error)
        raise last_error


def _atomic_write(path: Path, content: str):
    """Écriture atomique via fichier temporaire + rename."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
