"""Système d'alertes Telegram avec hystérésis et cooldown."""
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

ALERT_STATE_PATH = Path(__file__).parent.parent / "data" / "state" / "alert_state.json"


class AlertManager:
    """
    Gère les alertes Telegram.
    Par défaut en mode shadow (log uniquement, pas d'envoi).
    """

    def __init__(self, settings: dict):
        alerts_cfg = settings.get("alerts", {})
        self.enabled: bool = alerts_cfg.get("enabled", False)
        self.shadow: bool = alerts_cfg.get("shadow", True)
        self.shadow_min_days: int = alerts_cfg.get("shadow_min_days", 14)
        self.zone_threshold: int = alerts_cfg.get("zone_threshold", 40)
        self.hysteresis: int = alerts_cfg.get("zone_hysteresis", 5)
        self.cooldown_hours: int = alerts_cfg.get("cooldown_hours", 12)
        self.max_per_run: int = alerts_cfg.get("max_messages_per_run", 5)
        self.priority_zones: list = alerts_cfg.get("priority_zones", [])

        self._bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self._chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

        self._state = self._load_state()
        self._sent_count = 0

        # Enregistrer la date de première activation shadow (pour shadow_min_days)
        if "first_shadow_at" not in self._state:
            self._state["first_shadow_at"] = datetime.now(timezone.utc).isoformat()
            self._save_state()

    def _load_state(self) -> dict:
        if ALERT_STATE_PATH.exists():
            try:
                return json.loads(ALERT_STATE_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"zone_states": {}, "last_alerts": {}}

    def _save_state(self):
        content = json.dumps(self._state, ensure_ascii=False, indent=2)
        tmp = ALERT_STATE_PATH.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(ALERT_STATE_PATH)

    def _is_in_cooldown(self, key: str) -> bool:
        last = self._state.get("last_alerts", {}).get(key)
        if not last:
            return False
        try:
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - last_dt) < timedelta(hours=self.cooldown_hours)
        except Exception:
            return False

    def _record_alert(self, key: str):
        self._state.setdefault("last_alerts", {})[key] = datetime.now(timezone.utc).isoformat()
        self._sent_count += 1

    def check_zone_threshold(self, zone: str, new_index, scores: dict):
        """Vérifie si l'index d'une zone franchit le seuil."""
        if new_index is None:
            return
        if self._sent_count >= self.max_per_run:
            return

        zone_states = self._state.setdefault("zone_states", {})
        prev_above = zone_states.get(zone, {}).get("above_threshold", False)

        if new_index >= self.zone_threshold and not prev_above:
            # Franchissement vers le haut
            zone_states[zone] = {"above_threshold": True, "last_index": new_index}
            alert_key = f"zone_threshold_{zone}"
            if not self._is_in_cooldown(alert_key):
                self._send_zone_alert(zone, new_index, scores)
                self._record_alert(alert_key)

        elif new_index < (self.zone_threshold - self.hysteresis) and prev_above:
            # Réarmement : index redescendu sous seuil - hystérésis
            zone_states[zone] = {"above_threshold": False, "last_index": new_index}

    def check_critical_incident(self, incident: dict, zone: str):
        """Alerte sur incident confirmed tier A severity >= 4."""
        if self._sent_count >= self.max_per_run:
            return
        if zone not in self.priority_zones:
            return

        status = incident.get("status")
        severity = incident.get("severity", 0)
        tier = incident.get("confidence", {}).get("max_tier", "D")

        if status == "confirmed" and severity >= 4 and tier == "A":
            alert_key = f"incident_{incident['id']}_{zone}"
            if not self._is_in_cooldown(alert_key):
                self._send_incident_alert(incident, zone)
                self._record_alert(alert_key)

    def _send_zone_alert(self, zone: str, index: float, scores: dict):
        level = scores.get("zones", {}).get(zone, {}).get("level", "?")
        msg = (
            f"⚠️ BLACKOUT WATCH — {zone.upper()}\n"
            f"Index {index:.0f}/100 — Niveau {level}\n"
            f"\n"
            f"⚠️ Indicateur de veille — pas une probabilité.\n"
            f"Un score élevé ne garantit pas un incident imminent.\n"
        )
        self._dispatch(f"zone_{zone}", msg)

    def _send_incident_alert(self, incident: dict, zone: str):
        title = incident.get("title", "")[:100]
        category = incident.get("category", "")
        severity = incident.get("severity", 0)
        msg = (
            f"🚨 BLACKOUT WATCH — Incident critique ({zone.upper()})\n"
            f"{title}\n"
            f"Catégorie: {category} | Gravité: {severity}/5\n"
            f"Statut: confirmé (source officielle)\n"
            f"\n"
            f"⚠️ Indicateur de veille — pas une probabilité.\n"
        )
        self._dispatch(f"incident_{incident['id']}", msg)

    def _is_shadow_min_days_elapsed(self) -> bool:
        """Vérifie que shadow_min_days jours se sont écoulés depuis la première activation."""
        first = self._state.get("first_shadow_at")
        if not first:
            return False
        try:
            first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - first_dt) >= timedelta(days=self.shadow_min_days)
        except Exception:
            return False

    def _dispatch(self, key: str, message: str):
        """Envoie un message Telegram ou log en mode shadow."""
        # Forcer shadow si shadow_min_days n'est pas écoulé
        if not self._is_shadow_min_days_elapsed():
            remaining = self.shadow_min_days
            logger.info("[ALERT SHADOW — période minimale %dd non écoulée] %s", remaining, key)
            return

        if self.shadow or not self.enabled:
            logger.info("[ALERT SHADOW] %s : %s", key, message[:100])
            return

        if not self._bot_token or not self._chat_id:
            logger.warning("Telegram non configuré (TELEGRAM_BOT_TOKEN/CHAT_ID manquants)")
            return

        import httpx
        try:
            url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
            with httpx.Client(timeout=10) as client:
                resp = client.post(url, json={
                    "chat_id": self._chat_id,
                    "text": message,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                })
                resp.raise_for_status()
                logger.info("Alerte Telegram envoyée : %s", key)
        except Exception as e:
            logger.error("Échec envoi Telegram : %s", e)

    def finalize(self):
        """Persiste l'état des alertes."""
        self._save_state()
