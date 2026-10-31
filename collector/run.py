"""
Point d'entrée du collecteur BLACKOUT WATCH.
Usage: python -m collector.run [--dry-run] [--sources source1,source2] [--skip-deploy]
"""
import argparse
import hashlib
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
STATE_DIR = DATA_DIR / "state"
CONFIG_DIR = BASE_DIR / "config"


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def load_json(path: Path) -> dict | list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_incident_from_cluster(
    cluster, classifier, geo_resolver, incident_id: str,
    src_defaults: dict | None = None,
    src_zones_hint: dict | None = None,
) -> dict | None:
    """Construit un dict incident à partir d'un cluster de RawItems."""
    from .dedup import Cluster

    if not cluster.items:
        return None

    first = cluster.items[0]
    # Utiliser default_category de la source comme fallback de classification
    default_cat = (src_defaults or {}).get(first.source_id, "geopolitics")

    # Classification
    title = first.title
    summary = " ".join(set(i.summary_text for i in cluster.items[:3]))
    category, secondary_cats = classifier.classify_text(title, summary, default_cat)

    # Statut
    status = classifier.determine_status(cluster.items, category)

    # Type d'événement
    kind = classifier.classify_kind(cluster.items, category)

    # Gravité + infrastructure
    severity, infra_type = classifier.apply_severity_rules(cluster.items, category)

    # Cap sévérité pour les vulnérabilités (jamais ≥ 3)
    if kind == "vulnerability":
        is_active = (
            classifier.has_active_exploitation(cluster.items)
            or any(i.source_id == "cisa_kev" for i in cluster.items)
        )
        is_ics = (
            classifier.has_ics_critical_sector(cluster.items)
            or any(i.source_id in {"cert_fr_scada", "cisa_ics"} for i in cluster.items)
        )
        severity = min(severity, 2 if (is_active and is_ics) else 1)

    # Géolocalisation
    all_hints = []
    for item in cluster.items:
        all_hints.extend(item.geo_hints)

    affected_countries = geo_resolver.resolve_countries(all_hints)
    affected_zones = geo_resolver.iso_to_zones(affected_countries)

    # Fallback : zones_hint de la source si pas de géo résolue
    # Si des geo_hints existent mais n'ont pas été reconnus → global seulement (évite l'inflation)
    if not affected_zones:
        if all_hints:
            affected_zones = ["global"]
        else:
            from .classify import HAZARD_SOURCES
            if first.source_id in HAZARD_SOURCES:
                # Hazard sans pays résolu → global uniquement (jamais zones_hint)
                affected_zones = ["global"]
            else:
                affected_zones = (src_zones_hint or {}).get(first.source_id, ["global"])

    # Origine de la menace
    actor_result = geo_resolver.resolve_threat_actor(f"{title} {summary}")
    origin_country = []
    threat_actor = None
    attribution = "none"
    if actor_result:
        threat_actor, origin_iso = actor_result
        origin_country = [origin_iso]
        attribution = "press_allegation"  # jusqu'à confirmation tier A

    # Coordinated campaign
    coordinated = classifier.detect_coordinated(cluster.items, cluster.max_tier)

    # Infrastructure importance
    infra_type_geo, _ = geo_resolver.get_infrastructure_importance(
        affected_countries, affected_zones[0] if affected_zones else "global"
    )
    if infra_type == "non_critical":
        infra_type = infra_type_geo

    infra_importance_map = {"national": 1.0, "regional": 0.7, "local": 0.4, "non_critical": 0.2}
    importance = infra_importance_map.get(infra_type, 0.2)

    # is_ongoing
    is_ongoing = status not in ("resolved", "denied")

    # Duration
    duration_hours = None
    for item in cluster.items:
        if item.extra.get("duration_hours"):
            duration_hours = item.extra["duration_hours"]
            break

    # Reports
    reports = []
    for item in cluster.items[:10]:  # max 10 sources
        safe_url = item.url
        if not safe_url.startswith(("http://", "https://")):
            continue
        reports.append({
            "source_id": item.source_id,
            "tier": item.tier,
            "owner": item.owner,
            "url": safe_url,
            "title": item.title,
            "summary": item.summary_text[:500],
            "published_at": item.published_at.isoformat(),
            "raw_ids": item.raw_ids,
        })

    if not reports:
        return None

    now = datetime.now(timezone.utc).isoformat()
    incident = {
        "id": incident_id,
        "title": title[:500],
        "summary": summary[:2000],
        "category": category,
        "secondary_categories": secondary_cats,
        "kind": kind,
        "subtype": None,
        "severity": severity,
        "status": status,
        "is_ongoing": is_ongoing,
        "published_at": cluster.published_at.isoformat(),
        "updated_at": now,
        "resolved_at": None,
        "duration_hours": duration_hours,
        "demo": False,
        "reports": reports,
        "affected": {
            "countries": affected_countries,
            "regions": [],
            "zones": list(set(affected_zones)) if isinstance(affected_zones, list) else [affected_zones],
            "infrastructure_type": infra_type,
            "importance": importance,
        },
        "origin": {
            "countries": origin_country,
            "attribution": attribution,
            "threat_actor": threat_actor,
            "coordinated_campaign": coordinated,
        },
        "score": {"by_zone": {}},
        "confidence": {
            "n_owners": cluster.n_owners,
            "max_tier": cluster.max_tier,
            "K": 0.0,
        },
        "history": [],
        "classification": {"ai_suggestion": None},
    }
    return incident


def make_incident_id(cluster) -> str:
    """Génère un ID stable pour un cluster."""
    # Préférer les raw_ids forts (CVE, eventid)
    if cluster.raw_ids:
        strong_id = sorted(cluster.raw_ids)[0]
        return "inc_" + strong_id.lower().replace(" ", "_")[:40]
    # Fallback : hash du titre normalisé + date
    from .normalize import normalize_text
    key = f"{normalize_text(cluster.items[0].title)}_{cluster.published_at.date()}"
    return "inc_" + hashlib.sha256(key.encode()).hexdigest()[:12]


def _get_required_env_vars(src: dict) -> list[str]:
    """Retourne la liste des env vars requises par une source (vide si auth=none)."""
    auth = src.get("auth", "none")
    if not auth or auth == "none":
        return []
    if auth.startswith("env:"):
        return [v.strip() for v in auth[4:].split(",") if v.strip()]
    return []


def _check_secrets_present(src: dict) -> tuple[bool, list[str]]:
    """Vérifie si toutes les env vars requises sont définies. Retourne (ok, manquantes)."""
    import os
    required = _get_required_env_vars(src)
    missing = [v for v in required if not os.environ.get(v)]
    return (len(missing) == 0, missing)


def _update_sources_status_ko(data_dir: Path, ko_entries: list[dict]):
    """Ajoute/met à jour les entrées ko dans sources_status.json."""
    status_path = data_dir / "sources_status.json"
    if not status_path.exists():
        return
    try:
        doc = json.loads(status_path.read_text(encoding="utf-8"))
        existing = {s["id"]: s for s in doc.get("sources", [])}
        for entry in ko_entries:
            existing[entry["id"]] = entry
        doc["sources"] = list(existing.values())
        tmp = status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(status_path)
    except Exception as e:
        logger.warning("sources_status.json mise à jour ko : %s", e)


def _update_sources_status_skipped(data_dir: Path, skipped: list[dict]):
    """Ajoute/met à jour les entrées skipped_no_secret dans sources_status.json."""
    status_path = data_dir / "sources_status.json"
    if not status_path.exists():
        return
    try:
        doc = json.loads(status_path.read_text(encoding="utf-8"))
        existing = {s["id"]: s for s in doc.get("sources", [])}
        for entry in skipped:
            existing[entry["id"]] = entry
        doc["sources"] = list(existing.values())
        tmp = status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(status_path)
    except Exception as e:
        logger.warning("sources_status.json mise à jour skipped : %s", e)


def run(
    dry_run: bool = False,
    sources_filter: list | None = None,
    run_counter: int = 0,
):
    """Exécute le pipeline de collecte complet."""
    from .http import HttpClient
    from .dedup import cluster_items
    from .classify import Classifier
    from .geo import GeoResolver
    from .scoring import Scorer
    from .storage import (
        load_incidents, save_incidents, save_scores,
        save_history, save_runs, load_runs, load_history
    )
    from .alerts import AlertManager
    from .ai_assist import AiAssist

    # Charger les adapters
    from .adapters.rss import RssAdapter
    from .adapters.cisa_kev import CisaKevAdapter
    from .adapters.ioda import IodaAdapter
    from .adapters.cloudflare_radar import CloudflareRadarAdapter
    from .adapters.hydroquebec import HydroquebecAdapter
    from .adapters.ceb_dataset import CebDatasetAdapter
    from .adapters.rte_ecowatt import RteEcowattAdapter
    from .adapters.entsoe import EntsoeAdapter
    from .adapters.gdacs import GdacsAdapter
    from .adapters.gdelt import GdeltAdapter

    ADAPTER_MAP = {
        "rss": RssAdapter,
        "json": None,  # délégué aux adapters spécialisés
        "xml": None,
    }
    SPECIALIZED_ADAPTERS = {
        "cisa_kev": CisaKevAdapter,
        "ioda": IodaAdapter,
        "cloudflare_radar": CloudflareRadarAdapter,
        "hydroquebec": HydroquebecAdapter,
        "ceb_dataset": CebDatasetAdapter,
        "rte_ecowatt": RteEcowattAdapter,
        "entsoe": EntsoeAdapter,
        "gdacs": GdacsAdapter,
        "gdelt": GdeltAdapter,
    }

    run_id = str(uuid.uuid4())[:8]
    started_at = datetime.now(timezone.utc)
    errors: list[str] = []

    # Chargement de la config
    settings = load_json(CONFIG_DIR / "settings.json")
    sources_cfg = load_json(CONFIG_DIR / "sources.json")["sources"]
    dedup_cfg = settings.get("dedup", {})

    # Filtrer les sources activées
    active_sources = [
        s for s in sources_cfg
        if s.get("enabled") and not s.get("excluded")
        and (not sources_filter or s["id"] in sources_filter)
    ]

    logger.info("Run %s : %d sources actives, dry_run=%s", run_id, len(active_sources), dry_run)

    # HTTP client
    http = HttpClient(
        settings,
        cache_path=STATE_DIR / "http_cache.json",
        health_path=STATE_DIR / "source_health.json",
    )

    # Classifier, geo, scorer
    classifier = Classifier(
        CONFIG_DIR / "keywords.json",
        CONFIG_DIR / "severity_rules.json",
    )
    geo = GeoResolver(
        CONFIG_DIR / "gazetteer.json",
        CONFIG_DIR / "threat_actors.json",
        CONFIG_DIR / "zones.json",
    )
    scorer = Scorer(settings, CONFIG_DIR / "zones.json", CONFIG_DIR / "dependencies.json")
    ai = AiAssist(settings)
    alert_mgr = AlertManager(settings)

    # Collecte
    all_raw_items = []
    sources_ok = 0
    sources_ko = 0
    sources_skipped_secrets: list[dict] = []
    api_calls = 0

    for src in active_sources:
        source_id = src["id"]

        # Vérification des secrets avant toute tentative réseau
        secrets_ok, missing = _check_secrets_present(src)
        if not secrets_ok:
            logger.info(
                "Source %s : secrets manquants %s → skipped_no_secret",
                source_id, missing
            )
            sources_skipped_secrets.append({
                "id": source_id,
                "name": src.get("name", ""),
                "status": "skipped_no_secret",
                "error_message": f"Secrets manquants : {', '.join(missing)}",
            })
            continue

        try:
            if source_id in SPECIALIZED_ADAPTERS:
                adapter = SPECIALIZED_ADAPTERS[source_id](src, settings)
            elif src.get("format") == "rss":
                adapter = RssAdapter(src, settings)
            else:
                logger.warning("Pas d'adapter pour %s (format=%s)", source_id, src.get("format"))
                continue

            items = adapter.fetch(http, run_counter=run_counter)
            all_raw_items.extend(items)
            sources_ok += 1
            api_calls += 1
            logger.info("Source %s : %d items", source_id, len(items))

        except Exception as e:
            sources_ko += 1
            error_msg = f"{source_id}: {type(e).__name__}: {str(e)[:100]}"
            errors.append(error_msg)
            logger.error("Source %s : %s", source_id, e)
            sources_skipped_secrets.append({
                "id": source_id,
                "name": src.get("name", ""),
                "status": "error",
                "error_message": error_msg,
            })

    logger.info("Collecte terminée : %d items bruts depuis %d sources", len(all_raw_items), sources_ok)

    # Filtrer les items trop anciens (fenêtre = incident_window_days de settings)
    from datetime import timedelta
    window_days = settings.get("storage", {}).get("max_item_age_days", 30)
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    before_filter = len(all_raw_items)
    all_raw_items = [item for item in all_raw_items if item.published_at >= cutoff]
    if before_filter != len(all_raw_items):
        logger.info("Filtre âge : %d → %d items (fenêtre %d jours)", before_filter, len(all_raw_items), window_days)

    # Déduplication
    clusters = cluster_items(
        all_raw_items,
        window_hours=dedup_cfg.get("window_hours", 72),
        jaccard_thresh=dedup_cfg.get("jaccard_threshold", 0.6),
        syndication_thresh=dedup_cfg.get("syndication_threshold", 0.85),
    )

    # Charger les incidents existants
    existing_incidents = load_incidents()
    existing_ids = {inc["id"] for inc in existing_incidents}

    # Index source → default_category et zones_hint pour classification/géo
    src_defaults = {s["id"]: s.get("default_category", "geopolitics") for s in sources_cfg}
    src_zones_hint = {s["id"]: s.get("zones_hint", ["global"]) for s in sources_cfg}

    # Construire les nouveaux incidents
    new_incidents = []
    for cluster in clusters:
        incident_id = make_incident_id(cluster)
        if incident_id in existing_ids:
            continue
        incident = build_incident_from_cluster(
            cluster, classifier, geo, incident_id, src_defaults, src_zones_hint
        )
        if incident:
            # IA optionnelle
            incident = ai.process_incident(incident)
            new_incidents.append(incident)

    all_incidents = existing_incidents + new_incidents
    items_new = len(new_incidents)

    # Calcul des scores
    source_health = {}
    if (STATE_DIR / "source_health.json").exists():
        source_health = load_json(STATE_DIR / "source_health.json")

    # Lire le timestamp du dernier run réussi (pour stale/stale_warning)
    run_state_path = STATE_DIR / "run_state.json"
    prev_last_run_ts = None
    if run_state_path.exists():
        try:
            rs = json.loads(run_state_path.read_text(encoding="utf-8"))
            prev_last_run_ts = rs.get("last_successful_run")
        except Exception:
            pass

    scores = scorer.compute_all(all_incidents, source_health, sources_cfg,
                                last_successful_run_ts=prev_last_run_ts)

    # Alertes
    for zone, zone_data in scores.get("zones", {}).items():
        alert_mgr.check_zone_threshold(zone, zone_data["index"], scores)
        for inc in all_incidents:
            if zone in inc.get("affected", {}).get("zones", []):
                alert_mgr.check_critical_incident(inc, zone)

    # Historique
    hourly_entries, daily_entries = load_history()
    ts = datetime.now(timezone.utc).isoformat()
    hourly_entry = {
        "timestamp": ts,
        "index": scores.get("zones", {}).get("global", {}).get("index", 0),
        "categories": {
            zone: {
                cat: scores["zones"][zone]["categories"].get(cat, {}).get("score", 0)
                for cat in ["electricity", "cables", "finance", "cyber", "logistics", "geopolitics"]
            }
            for zone in scores.get("zones", {})
        },
    }
    hourly_entries.append(hourly_entry)

    # Mise à jour daily (dernière valeur du jour)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily_entries = [e for e in daily_entries if not e.get("timestamp", "").startswith(today)]
    daily_entries.append(hourly_entry)

    # Persistance (sauf en dry_run)
    ended_at = datetime.now(timezone.utc)
    run_record = {
        "run_id": run_id,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_seconds": round((ended_at - started_at).total_seconds(), 2),
        "sources_ok": sources_ok,
        "sources_ko": sources_ko,
        "items_total": len(all_raw_items),
        "items_new": items_new,
        "api_calls": api_calls,
        "dry_run": dry_run,
        "errors_summary": errors[:20],
        "scoring_version": scorer.version,
    }

    if not dry_run:
        save_incidents(all_incidents)
        save_scores(scores)
        save_history(hourly_entries, daily_entries)
        http.save_state()
        alert_mgr.finalize()

        runs = load_runs()
        save_runs(runs, run_record)

        # Écrire le timestamp du run réussi pour stale/stale_warning
        run_state_path.write_text(
            json.dumps({"last_successful_run": ended_at.isoformat()},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # Mise à jour sources_status.json avec les sources skipped_no_secret
        if sources_skipped_secrets:
            _update_sources_status_skipped(DATA_DIR, sources_skipped_secrets)

        logger.info("Run %s terminé : %d nouveaux incidents, %d sources OK, %d KO",
                    run_id, items_new, sources_ok, sources_ko)
    else:
        logger.info("[DRY RUN] %s terminé : %d items, %d clusters, %d nouveaux incidents",
                    run_id, len(all_raw_items), len(clusters), items_new)

    return run_record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BLACKOUT WATCH Collector")
    parser.add_argument("--dry-run", action="store_true", help="Pas d'écriture sur disque")
    parser.add_argument("--sources", help="Sources à traiter (ex: cert_fr_alerte,gdacs)")
    parser.add_argument("--skip-deploy", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    setup_logging(args.log_level)

    sources_filter = args.sources.split(",") if args.sources else None
    result = run(
        dry_run=args.dry_run,
        sources_filter=sources_filter,
    )
    sys.exit(0)
