"""Normalisation des items bruts → RawItem."""
import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

# Paramètres UTM et tracking à supprimer
_TRACKING_PARAMS = frozenset([
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "yclid", "mc_cid", "mc_eid", "ref", "_ga",
])

# Balises HTML
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</(script|style)>", re.DOTALL | re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.DOTALL)
_WHITESPACE_RE = re.compile(r"\s+")
_AMP_RE = re.compile(r"https?://[^/]*\.ampproject\.org/v\d+/[^?]+")
_AMP_SUFFIX_RE = re.compile(r"/amp/?$")


@dataclass
class RawItem:
    source_id: str
    tier: str
    owner: str
    url: str
    title: str
    summary_text: str  # HTML retiré, max 2000 chars
    published_at: datetime  # UTC
    raw_ids: list = field(default_factory=list)   # CVE, eventid, outageId, etc.
    geo_hints: list = field(default_factory=list)  # pays/noms bruts depuis la source
    extra: dict = field(default_factory=dict)      # champs spécifiques à la source


def strip_html(text: str) -> str:
    """Retire le HTML et le contenu des balises script/style."""
    if not text:
        return ""
    # Supprimer entièrement le contenu des balises script et style (XSS)
    text = _SCRIPT_STYLE_RE.sub(" ", text)
    # Remplacer les entités HTML courantes
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    text = _HTML_TAG_RE.sub(" ", text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


def canonicalize_url(url: str) -> str:
    """
    Normalise une URL :
    - Force HTTPS
    - Supprime les paramètres de tracking
    - Supprime le fragment
    - Supprime le slash final
    - Retire le suffixe AMP
    """
    if not url:
        return url
    try:
        parsed = urlparse(url)
        # Force HTTPS sauf pour localhost
        scheme = "https" if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1") else parsed.scheme
        # Filtrer les paramètres de tracking
        params = [(k, v) for k, v in parse_qsl(parsed.query) if k.lower() not in _TRACKING_PARAMS]
        query = urlencode(params)
        # Retirer le slash final du path
        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path
        # Retirer le suffixe AMP
        path = _AMP_SUFFIX_RE.sub("", path)
        # Reconstruire sans fragment
        result = urlunparse((scheme, parsed.netloc, path, parsed.params, query, ""))
        return result
    except Exception:
        return url


def sanitize_url(url: str) -> Optional[str]:
    """
    Valide et assainit une URL externe.
    Retourne None si le schéma n'est pas http/https.
    """
    if not url:
        return None
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None  # Neutralise javascript:, data:, etc.
        return url
    except Exception:
        return None


def normalize_text(title: str) -> str:
    """Normalise un titre pour la déduplication (minuscules, sans accents, sans stopwords)."""
    text = title.lower()
    # Supprimer les accents
    text = "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")
    # Garder uniquement les caractères alphanumériques
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    # Supprimer les stopwords FR/EN
    tokens = text.split()
    tokens = [t for t in tokens if t not in _STOPWORDS and len(t) > 2]
    return " ".join(tokens)


def make_raw_item(
    source_id: str,
    tier: str,
    owner: str,
    url: str,
    title: str,
    summary: str,
    published_at: datetime,
    raw_ids: Optional[list] = None,
    geo_hints: Optional[list] = None,
    extra: Optional[dict] = None,
) -> RawItem:
    """Crée un RawItem normalisé."""
    clean_title = strip_html(title or "")[:500]
    clean_summary = strip_html(summary or "")[:2000]
    clean_url = canonicalize_url(sanitize_url(url) or url)

    # S'assurer que published_at est en UTC
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=timezone.utc)
    else:
        published_at = published_at.astimezone(timezone.utc)

    return RawItem(
        source_id=source_id,
        tier=tier,
        owner=owner,
        url=clean_url,
        title=clean_title,
        summary_text=clean_summary,
        published_at=published_at,
        raw_ids=raw_ids or [],
        geo_hints=geo_hints or [],
        extra=extra or {},
    )


def item_fingerprint(item: RawItem) -> str:
    """Empreinte unique d'un item pour la déduplication."""
    key = f"{item.source_id}|{item.url}|{item.published_at.isoformat()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


_STOPWORDS = frozenset([
    # FR
    "le", "la", "les", "un", "une", "des", "du", "de", "en", "et", "est",
    "au", "aux", "par", "sur", "dans", "pour", "que", "qui", "se", "son",
    "sa", "ses", "ce", "si", "il", "ils", "elle", "elles", "nous", "vous",
    "on", "ne", "pas", "plus", "avec", "ou", "mais", "car", "donc", "or",
    "ni", "or", "une", "plus", "tres", "bien", "tout", "tous", "toute",
    # EN
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "has", "have", "had", "will", "would", "could", "should", "may", "might",
    "this", "that", "these", "those", "its", "their", "it", "they", "we",
    "you", "he", "she", "not", "no", "new", "also", "about", "after",
])
