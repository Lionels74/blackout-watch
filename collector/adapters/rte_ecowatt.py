"""Adapter RTE Ecowatt (OAuth2 client_credentials)."""
import base64
import json
import logging
import os
import time
from datetime import datetime, timezone

import httpx

from .base import BaseAdapter
from ..normalize import make_raw_item, RawItem

logger = logging.getLogger(__name__)

TOKEN_URL = "https://digital.iservices.rte-france.com/token/oauth/"
# Sandbox pour les tests
TOKEN_SANDBOX_URL = "https://digital.iservices.rte-france.com/token/oauth/"


class RteEcowattAdapter(BaseAdapter):
    """
    Lit les signaux Ecowatt RTE.
    Authentification OAuth2 client_credentials.
    Cache du token en mémoire (valide 2h).
    Max 1 appel API par run (quota RTE : 1 appel/15min).
    """

    _token_cache: dict = {}  # Partagé entre instances dans le même process

    def fetch(self, http_client, run_counter: int = 0) -> list[RawItem]:
        client_id = os.environ.get("RTE_CLIENT_ID", "")
        client_secret = os.environ.get("RTE_CLIENT_SECRET", "")

        if not client_id or not client_secret:
            logger.warning("RTE Ecowatt : RTE_CLIENT_ID/RTE_CLIENT_SECRET non définis")
            return []

        token = self._get_token(client_id, client_secret)
        if not token:
            return []

        try:
            content = http_client.get(
                self.source_id, self.url, run_counter,
                extra_headers={"Authorization": f"Bearer {token}"}, max_bytes=self.max_bytes
            )
        except Exception as e:
            logger.error("RTE Ecowatt : fetch signaux échoué : %s", e)
            return []

        if content is None:
            return []

        try:
            data = json.loads(content)
        except Exception as e:
            logger.error("RTE Ecowatt : parse JSON échoué : %s", e)
            return []

        return self._parse_signals(data)

    def _get_token(self, client_id: str, client_secret: str) -> str | None:
        """Obtient ou réutilise un token OAuth2."""
        cached = self.__class__._token_cache
        now = time.time()

        # Token valide si il reste > 60s
        if cached.get("token") and cached.get("expires_at", 0) > now + 60:
            return cached["token"]

        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.post(
                    TOKEN_URL,
                    headers={
                        "Authorization": f"Basic {credentials}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    content=b"grant_type=client_credentials",
                )
                resp.raise_for_status()
                token_data = resp.json()
                token = token_data.get("access_token")
                expires_in = int(token_data.get("expires_in", 7200))
                self.__class__._token_cache = {
                    "token": token,
                    "expires_at": now + expires_in,
                }
                logger.info("RTE Ecowatt : token OAuth2 obtenu (expire dans %ds)", expires_in)
                return token
        except Exception as e:
            logger.error("RTE Ecowatt : échec obtention token : %s", e)
            return None

    def _parse_signals(self, data: dict) -> list[RawItem]:
        signals = data.get("signals", [])
        items = []

        for signal in signals:
            try:
                # Un signal Ecowatt = un jour
                signal_date = signal.get("jour", "")
                # Valeur du jour : 1=vert, 2=orange, 3=rouge
                dvalue = signal.get("dvalue", 1)

                if dvalue <= 1:
                    # Vert = normal, pas d'incident
                    continue

                published_at = datetime.fromisoformat(
                    signal_date.replace("Z", "+00:00")
                ) if signal_date else datetime.now(timezone.utc)

                level_labels = {1: "vert (normal)", 2: "orange (vigilance)", 3: "rouge (alerte)"}
                level = level_labels.get(dvalue, str(dvalue))
                title = f"RTE Ecowatt: signal {level} pour la France"
                summary = (
                    f"Signal Ecowatt RTE: {level} le {signal_date}. "
                    f"Le réseau électrique français est sous tension."
                )

                item = make_raw_item(
                    source_id=self.source_id,
                    tier=self.tier,
                    owner=self.owner,
                    url="https://www.monecowatt.fr/",
                    title=title,
                    summary=summary,
                    published_at=published_at,
                    raw_ids=[f"ecowatt_{signal_date}"],
                    geo_hints=["FR"],
                    extra={"ecowatt_value": dvalue, "signal_date": signal_date},
                )
                items.append(item)

            except Exception as e:
                logger.warning("RTE Ecowatt : signal ignoré : %s", e)
                continue

        return items
