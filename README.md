# BLACKOUT WATCH

Tableau de bord statique de veille des risques sur les infrastructures critiques.

> **Avertissement** : BLACKOUT WATCH est un outil de veille, pas une source prédictive. Les scores ne sont pas des probabilités d'incident. Un score faible ne garantit pas l'absence d'événement. Un incident cyber isolé n'est jamais présenté comme une guerre cyber coordonnée.

## Architecture

```
Sources (RSS/JSON/XML)
    ↓
Collecteur Python (GitHub Actions, toutes les heures)
    ↓
data/*.json (committed dans le repo)
    ↓
GitHub Pages → site/ (HTML/CSS/JS statique)
```

**Aucun serveur permanent, aucune base de données, 0 € de coût obligatoire.**

## Installation locale

```bash
# Cloner le dépôt
git clone https://github.com/VOTRE_USERNAME/blackout-watch.git
cd blackout-watch

# Environnement Python
python -m venv .venv
source .venv/bin/activate  # Windows : .venv\Scripts\activate
pip install -r requirements.txt

# Run à sec (pas d'écriture, pas de réseau si fixtures seulement)
python -m collector.run --dry-run

# Serveur local pour le frontend
python -m http.server 8080 -d site
# Puis ouvrir http://localhost:8080?demo=1
```

## Création du dépôt public et activation de Pages

1. Créer un dépôt public sur GitHub
2. `git remote add origin https://github.com/VOTRE_USERNAME/blackout-watch.git`
3. `git push -u origin main`
4. Dans Settings → Pages → Source : **GitHub Actions**
5. Déclencher le premier run manuellement : Actions → Monitoring → Run workflow

## Secrets GitHub

| Secret | Description | Comment l'obtenir |
|--------|-------------|-------------------|
| `RTE_CLIENT_ID` | Client ID RTE Ecowatt | Compte data.rte-france.com → Créer une application → Abonnement Ecowatt v4 |
| `RTE_CLIENT_SECRET` | Client Secret RTE | Même endroit. **Attention** : vérifier la version de l'API (v4) |
| `ENTSOE_TOKEN` | Token ENTSO-E | Inscription sur transparency.entsoe.eu → email "Restful API access" → délai ~3 jours ouvrés |
| `CLOUDFLARE_API_TOKEN` | Token Cloudflare Radar | dash.cloudflare.com → My Profile → API Tokens → Create Token → permission **Account:Cloudflare Radar:Read** |
| `RELIEFWEB_APPNAME` | Appname ReliefWeb | Demande à reliefweb.int/contact — quota 1000 appels/jour |
| `TELEGRAM_BOT_TOKEN` | Token bot Telegram | BotFather → /newbot. **Désactivé par défaut** (shadow mode) |
| `TELEGRAM_CHAT_ID` | Chat ID Telegram | Ouvrir le bot → envoyer un message → `api.telegram.org/bot{TOKEN}/getUpdates` |
| `ANTHROPIC_API_KEY` | API Claude (optionnel) | console.anthropic.com → API Keys. **Désactivé par défaut** |

## Activation progressive des alertes

1. Configurer `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID` dans GitHub Secrets
2. `config/settings.json` → `alerts.shadow: true` → tester pendant 24h (messages dans les logs)
3. `alerts.shadow: false`, `alerts.enabled: true` → alertes réelles

## Limites connues

- **Cron GitHub** : le schedule peut être retardé de 15–30 minutes, ou sauté lors de forte charge GitHub. Ne rien supposer de précis sur l'heure d'exécution.
- **Désactivation après 60 jours** : GitHub désactive les workflows cron si le dépôt n'a aucune activité (push, PR, etc.) pendant 60 jours. Pour éviter cela, utiliser le `workflow_dispatch` manuel ou pousser des commits réguliers.
- **Couverture Maurice** : limitée au dataset CEB (coupures planifiées) et IODA/GDELT. Pas de flux officiel temps réel pour les incidents non planifiés.
- **Couverture Canada hors Québec** : principalement CCCS, IODA et GDELT. Pas de données granulaires sur les pannes électriques hors Québec.
- **Pannes de paiement** : aucun flux officiel disponible. Non couvert.
- **Câbles sous-marins** : liste statique dans `config/infrastructure.json`. Pas de flux temps réel sur les ruptures (sauf Cloudflare Radar et IODA).
- **GDELT throttling** : 1 requête/6s, max 8/run. En cas de 429, le run s'arrête proprement jusqu'au prochain run.

## Ajouter une source

1. Vérifier qu'elle a un flux RSS, Atom, JSON ou XML publié (pas de scraping HTML)
2. Ajouter une entrée dans `config/sources.json` avec `enabled: false` et `verified: false`
3. Lancer `python -m collector.verify_sources` pour tester
4. Si OK : `enabled: true`, `verified: true`
5. Créer un adapter dans `collector/adapters/` si le format est spécifique
6. Ajouter des fixtures dans `tests/fixtures/` et des tests dans `tests/test_adapters.py`

## Coûts

- GitHub Actions : 0 € (2000 min/mois gratuits sur dépôt public)
- GitHub Pages : 0 € (dépôt public)
- Toutes les sources par défaut : 0 €
- Secrets optionnels (RTE, ENTSO-E, Cloudflare) : 0 € avec les plans gratuits
- ANTHROPIC_API_KEY : facturation à l'usage (désactivé par défaut)

## Licence et attributions

Code : MIT License.

**Attributions des sources :**
- CERT-FR/ANSSI : données publiques ANSSI
- CISA : domaine public gouvernement américain
- CCCS : données ouvertes gouvernement du Canada
- CERT-EU : données publiques CERT-EU
- NCSC UK : Open Government Licence v3.0
- Hydro-Québec : données ouvertes Hydro-Québec
- IODA : CC BY-SA 4.0 — Georgia Tech / CAIDA
- GDACS : libre usage non commercial — JRC/OCHA
- CEB Dataset : MIT License — MrSunshyne
- Cloudflare Radar : API Cloudflare, conditions d'utilisation Cloudflare
- GDELT : données ouvertes GDELT Project
- Câbles sous-marins : TeleGeography Submarine Cable Map (référence uniquement)
