# BLACKOUT WATCH — Documentation des sources

## Sources actives (enabled=true)

| ID | Nom | Tier | Auth | Format | Zones |
|----|-----|------|------|--------|-------|
| cert_fr_alerte | CERT-FR Alertes | A | none | RSS | france, global |
| cert_fr_avis | CERT-FR Avis | A | none | RSS | france, global |
| cert_fr_cti | CERT-FR CTI | A | none | RSS | france, global |
| cert_fr_actualite | CERT-FR Actualités | A | none | RSS | france, global |
| cert_fr_scada | CERT-FR SCADA | A | none | RSS | france, global |
| cisa_advisories | CISA Advisories | A | none | RSS | global |
| cisa_alerts | CISA Alerts | A | none | RSS | global |
| cisa_ics | CISA ICS | A | none | RSS | global |
| cisa_kev | CISA KEV | A | none | JSON | global |
| cccs_fr | CCCS Canada (FR) | A | none | RSS | canada, global |
| cccs_en | CCCS Canada (EN) | A | none | RSS | canada, global |
| cert_eu | CERT-EU | A | none | RSS | france, global |
| ncsc_uk | NCSC UK | A | none | RSS | global |
| rte_ecowatt | RTE Ecowatt | A | env:RTE_CLIENT_ID,RTE_CLIENT_SECRET | JSON | france |
| entsoe | ENTSO-E | A | env:ENTSOE_TOKEN | XML | france, global |
| ceb_dataset | CEB Maurice Dataset | A | none | JSON | mauritius |
| cloudflare_radar | Cloudflare Radar | B | env:CLOUDFLARE_API_TOKEN | JSON | global |
| gdacs | GDACS | B | none | RSS | global |
| gdelt | GDELT DOC 2.0 | D | none | JSON | global |

**19 sources actives / 34 au total** (dont 3 nécessitent un secret GitHub)

## Sources désactivées (enabled=false, pending ou inaccessible)

| ID | Raison |
|----|--------|
| hydroquebec | `bisversion.json` redirige vers `client-externe.hydroquebec.com` (HTML). API non accessible publiquement sans session auth. |
| ioda | Endpoint `/v2/events` retourne 404. URL de l'API IODA à confirmer dans la documentation officielle. |
| bce | URL RSS BCE à confirmer par `verify_sources.py` |
| enisa | URL à vérifier |
| banque_france | URL à vérifier |
| banque_canada | URL à vérifier |
| bank_mauritius | URL à vérifier |
| reliefweb | Requiert appname pré-approuvé par OCHA (secret `RELIEFWEB_APPNAME`) |

## Sources exclues

| Source | Raison |
|--------|--------|
| CERT-MU | Pas de flux RSS/API. Publications en PDF uniquement. |
| TeleGeography | Données sous licence commerciale. Liste statique des câbles dans `config/infrastructure.json` avec attribution. |
| Reuters | Pas de RSS public. Couverture via GDELT uniquement. |
| Associated Press | Pas de RSS public. Couverture via GDELT uniquement. |
| Google News RSS | CGU ambiguës pour l'agrégation automatisée. |
| Pannes cartes/paiements | Pas de flux officiel disponible. |
| Freespoke | Pas de flux RSS ou API JSON public pour ingestion programmatique. Couverture anglophone via GDELT. |

## Système de tiers

| Tier | Description | Exemples |
|------|-------------|---------|
| A | Source officielle gouvernementale ou institutionnelle | CERT-FR, CISA, ENTSO-E |
| B | Mesure technique ou institution de recherche | Cloudflare Radar, GDACS |
| C | Presse fiable identifiée dans `trusted_press` | lemonde.fr, reuters.com, bbc.co.uk |
| D | Agrégateur ou source non vérifiée | GDELT (domaines non listés dans trusted_press) |
