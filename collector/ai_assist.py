"""
Module d'assistance IA (optionnel, désactivé par défaut).
Traite uniquement les événements unverified/ambigus.
La sortie ne peut QUE proposer category/subtype/résumé.
Elle n'écrase JAMAIS status, severity >= 4 ou origin.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class AiAssist:
    def __init__(self, settings: dict):
        ai_cfg = settings.get("ai", {})
        self.enabled: bool = ai_cfg.get("enabled", False)
        self.mode: str = ai_cfg.get("mode", "assist")
        self.model: str = ai_cfg.get("model", "claude-haiku-4-5-20251001")
        self.max_calls: int = ai_cfg.get("max_calls_per_run", 10)
        self.max_tokens: int = ai_cfg.get("max_tokens", 500)
        self._calls_made = 0

    def process_incident(self, incident: dict) -> dict:
        """
        Propose une classification IA pour un incident unverified/ambigu.
        Ne modifie JAMAIS : status, severity >= 4, origin.
        Retourne le dict incident potentiellement enrichi de classification.ai_suggestion.
        """
        if not self.enabled:
            return incident

        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            logger.debug("AI Assist : ANTHROPIC_API_KEY non défini, désactivé")
            return incident

        status = incident.get("status", "unverified")
        severity = incident.get("severity", 1)

        # Uniquement unverified ou probable
        if status not in ("unverified", "probable"):
            return incident

        if self._calls_made >= self.max_calls:
            return incident

        try:
            suggestion = self._call_ai(incident, api_key)
            if suggestion:
                incident.setdefault("classification", {})["ai_suggestion"] = suggestion
                self._calls_made += 1
        except Exception as e:
            logger.warning("AI Assist : erreur pour incident %s : %s", incident.get("id"), e)

        return incident

    def _call_ai(self, incident: dict, api_key: str) -> Optional[dict]:
        """Appel API Claude pour suggestion de classification."""
        import anthropic

        title = incident.get("title", "")[:200]
        summary = incident.get("summary", "")[:500]

        prompt = (
            f"Classify this infrastructure risk incident:\n"
            f"Title: {title}\n"
            f"Summary: {summary}\n\n"
            f"Respond with JSON only:\n"
            f'{{"category": "electricity|cables|finance|cyber|logistics|geopolitics", '
            f'"subtype": "string or null", "summary_fr": "résumé factuel en 1 phrase (max 100 chars)"}}'
        )

        client = anthropic.Anthropic(api_key=api_key)
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text.strip()

            # Valider que c'est du JSON
            suggestion = json.loads(content)

            valid_categories = ["electricity", "cables", "finance", "cyber", "logistics", "geopolitics"]
            if suggestion.get("category") not in valid_categories:
                return None

            suggestion["model"] = self.model
            suggestion["timestamp"] = datetime.now(timezone.utc).isoformat()
            return suggestion

        except json.JSONDecodeError:
            logger.warning("AI Assist : réponse non-JSON reçue")
            return None
