# Politique de sécurité — BLACKOUT WATCH

## Signalement d'une vulnérabilité

Pour signaler une vulnérabilité, ouvrez une issue privée via GitHub Security Advisories
ou contactez le mainteneur directement.

## Périmètre

### Dans le périmètre
- Injection de données malveillantes dans les flux RSS/JSON
- XSS via le contenu des incidents dans le frontend
- Fuite de secrets (variables d'environnement, tokens)
- Contournement de la politique CSP

### Hors périmètre
- Attaques nécessitant un accès physique au serveur
- Déni de service sur les sources tierces (CERT-FR, CISA, etc.)
- Problèmes dans les bibliothèques tierces (à signaler à leurs mainteneurs)

## Mesures de sécurité implémentées

### Frontend
- CSP stricte en meta-tag : `default-src 'self'; script-src 'self'; ...`
- Aucun `innerHTML` avec des données utilisateur (utilisation de `textContent` et `createElement`)
- Liens externes avec `rel="noopener noreferrer"` et validation du schéma (`https://` ou `http://` uniquement)
- Les liens `javascript:`, `data:` et autres schémas dangereux sont neutralisés

### Collecteur
- `defusedxml` pour prévenir les attaques XXE dans les flux XML
- Validation JSON Schema de toutes les données avant écriture
- Écriture atomique (fichier temporaire + rename)
- Taille maximale de réponse HTTP : 5 Mo
- Aucun secret dans le code ou les fichiers versionnés
- Les secrets viennent exclusivement de GitHub Secrets via variables d'environnement

### Général
- Dépendances épinglées dans `requirements.txt`
- Dependabot activé pour les mises à jour de sécurité
- Actions GitHub épinglées par SHA de commit
