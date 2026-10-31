# BLACKOUT WATCH — Formules de scoring (version 1.0)

> Ce document est la référence normative. Les formules implémentées dans `collector/scoring.py` doivent correspondre exactement à ce qui est décrit ici.

## Avertissement

Les scores BLACKOUT WATCH sont des **indicateurs de veille**, pas des probabilités. Un score faible ne garantit pas l'absence d'incident. Un incident cyber isolé n'est jamais présenté comme une guerre cyber coordonnée.

---

## Score d'un événement (E)

```
E(i,z) = 100 × G × K × P(z) × I × D × S × T    (plafonné à 100)
```

### G — Gravité normalisée
```
G = severity / 5
```

### K — Fiabilité × Validation
```
K = V × min(1, R_max + 0.1 × (n − 1))
```
| Source    | R    |
|-----------|------|
| Tier A    | 1.00 |
| Tier B    | 0.85 |
| Tier C    | 0.60 |
| Tier D    | 0.30 |

| Statut     | V    |
|------------|------|
| confirmed  | 1.00 |
| probable   | 0.70 |
| unverified | 0.35 |
| denied     | 0.00 |
| resolved   | 1.00 |

### P(z) — Proximité géographique

| Cas                         | P     |
|-----------------------------|-------|
| Zone affectée               | 1.00  |
| Voisin interconnecté        | 0.50  |
| Même macro-région           | 0.25  |
| Autre                       | 0.05  |
| Global (1 pays)             | 0.60  |
| Global (≥2 pays ou systémique) | 1.00 |
| Québec → Canada             | 0.70  |

### I — Importance de l'infrastructure

| Type           | I    |
|----------------|------|
| national       | 1.00 |
| regional       | 0.70 |
| local          | 0.40 |
| non_critical   | 0.20 |

### D — Durée

```
D = 0.6 + 0.4 × min(1, ln(1+h) / ln(73))
```
- `h` inconnu → D = 0.8
- `h = 0` → D = 0.6
- `h = 72` → D = 1.0

### S — Propagation

| Cas                           | S   |
|-------------------------------|-----|
| Aucune propagation            | 1.0 |
| Multi-zones                   | 1.2 |
| Cascade intersectorielle      | 1.4 |

### T — Décroissance temporelle

```
T = 2^(−Δt / h_c)
```

| Catégorie   | h_c (heures) |
|-------------|--------------|
| electricity | 12           |
| finance     | 24           |
| cyber       | 72           |
| geopolitics | 120          |
| cables      | 168          |
| logistics   | 168          |

**Exceptions :**
- `resolved` → h_c ÷ 3
- `confirmed` + `is_ongoing` → T = 1.0 pendant `max_ongoing_days` (cables 60j, electricity 7j, autres 14j)

---

## Score de catégorie (S_c)

```
S(c,z) = 100 × [1 − Π(1 − E(i,z)/100)]
```

**Catégorie secondaire** : contribue avec un facteur 0.5.

### Caps et planchers (dans l'ordre d'application)

**(a)** Si le score sans les événements `unverified` est < 40 → S ≤ 39
(cap enregistré : `unverified_cap_39`)

**(b)** S ≥ 80 exige ≥1 événement `confirmed` tier A (ou B dans son domaine), sinon S ≤ 79
(cap : `no_authoritative_cap_79`)

**(c)** Si tous les contributeurs sont tier C/D avec n=1 → S ≤ 59
(cap : `all_cd_n1_cap_59`)

**(d) Planchers officiels :**
- Ecowatt signal = 2 → France électricité ≥ 40 (floor : `ecowatt_2_floor_40`)
- Ecowatt signal = 3 → France électricité ≥ 65 (floor : `ecowatt_3_floor_65`)
- GDACS Orange affectant Maurice → électricité/logistique ≥ 30 (floor : `gdacs_orange_floor_30`)
- GDACS Red affectant Maurice → ≥ 50 (floor : `gdacs_red_floor_50`)

---

## Index de zone (Z)

```
B = Σ w_c × S_c          (somme pondérée, Σw = 100)
Z = max(B, 0.7 × max_c S_c)
Z' = min(100, Z × (1 + 0.2 × CI/100))
```

**Poids par catégorie :**

| Catégorie   | Poids |
|-------------|-------|
| electricity | 25    |
| cables      | 20    |
| finance     | 15    |
| cyber       | 15    |
| logistics   | 15    |
| geopolitics | 10    |

**Niveaux :**

| Score  | Niveau        |
|--------|---------------|
| 0–19   | NORMAL        |
| 20–39  | VIGILANCE     |
| 40–59  | PRÉALERTE     |
| 60–79  | ALERTE ÉLEVÉE |
| 80–100 | CRITIQUE      |

---

## Indice de convergence (CI)

```
CI = 100 × Σ d_ab √(S_a S_b)/100 ÷ Σ d_ab
```
Calculé uniquement sur les catégories avec S ≥ 20.

Les valeurs `d_ab` sont dans `config/dependencies.json`.

---

## Indice de confiance (CoI)

```
CoI = 100 × Q × F × C
```

- **Q** = Σ(E·K) / ΣE (qualité pondérée, 1.0 si aucun événement)
- **F** = part des sources de la zone collectées avec succès dans les 3 dernières heures
- **C** = part des 6 catégories couvertes par ≥1 source saine

---

## Fraîcheur

- Âge > 3h → `stale_warning = true` (avertissement dans le header)
- Âge > 12h → `stale = true` (scores grisés dans le frontend)
