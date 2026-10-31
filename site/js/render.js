/**
 * Fonctions de rendu DOM — uniquement textContent/createElement (pas d'innerHTML avec data).
 */

const LEVEL_CLASS = {
  'NORMAL':       'level-normal',
  'VIGILANCE':    'level-vigilance',
  'PRÉALERTE':    'level-prealerte',
  'ALERTE ÉLEVÉE':'level-alerte',
  'CRITIQUE':     'level-critique',
};

const SCORE_COLOR_CLASS = {
  'NORMAL':       'score-color-normal',
  'VIGILANCE':    'score-color-vigilance',
  'PRÉALERTE':    'score-color-prealerte',
  'ALERTE ÉLEVÉE':'score-color-alerte',
  'CRITIQUE':     'score-color-critique',
};

const CAT_COLORS = {
  electricity: '#c17f24',
  cables:      '#4a90d9',
  finance:     '#7b68ee',
  cyber:       '#e05c5c',
  logistics:   '#5cb85c',
  geopolitics: '#9b59b6',
};

const CAT_LABELS = {
  electricity: 'Électricité',
  cables:      'Câbles',
  finance:     'Finance',
  cyber:       'Cyber',
  logistics:   'Logistique',
  geopolitics: 'Géopolitique',
};

const STATUS_LABELS = {
  confirmed:  'Confirmé',
  probable:   'Probable',
  unverified: 'Non vérifié',
  denied:     'Démenti',
  resolved:   'Résolu',
};

export function getLevelClass(level) {
  return LEVEL_CLASS[level] || 'level-normal';
}

export function getScoreColorClass(level) {
  return SCORE_COLOR_CLASS[level] || 'score-color-normal';
}

/** Crée un élément avec du texte (jamais innerHTML) */
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

/** Crée un lien externe sécurisé */
function safeLink(url, text, cls) {
  // Valider le schéma
  if (!url || !/^https?:\/\//i.test(url)) return el('span', cls, text);
  const a = document.createElement('a');
  a.href = url;
  a.textContent = text;
  a.rel = 'noopener noreferrer';
  a.target = '_blank';
  if (cls) a.className = cls;
  return a;
}

export function renderZoneCard(zone, zoneData, isSelected, onSelect) {
  const card = document.createElement('div');
  card.className = 'zone-card' + (isSelected ? ' selected' : '');
  card.setAttribute('role', 'listitem');
  card.setAttribute('tabindex', '0');
  card.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
  card.dataset.zone = zone;

  const level = zoneData.level || 'NORMAL';
  const index = Math.round(zoneData.index ?? 0);

  const nameEl = el('div', 'zone-name', zoneLabel(zone));
  const scoreEl = el('div', `zone-score ${getScoreColorClass(level)}`, String(index));
  const levelEl = el('div', `zone-level ${getLevelClass(level)}`, level);

  card.appendChild(nameEl);
  card.appendChild(scoreEl);
  card.appendChild(levelEl);

  card.addEventListener('click', () => onSelect(zone));
  card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(zone); }});

  return card;
}

export function renderCategoryCard(cat, data, isStale) {
  const card = el('div', 'category-card');

  const header = el('div', 'cat-header');
  const nameEl = el('span', 'cat-name', CAT_LABELS[cat] || cat);
  const score = Math.round(data.score ?? 0);
  const scoreEl = el('span', `cat-score ${isStale ? '' : scoreColor(score)}`, String(score));
  header.appendChild(nameEl);
  header.appendChild(scoreEl);
  card.appendChild(header);

  // Barre de progression
  const track = el('div', 'cat-bar-track');
  const fill = el('div', 'cat-bar-fill');
  fill.style.width = `${score}%`;
  fill.style.background = CAT_COLORS[cat] || '#4a90d9';
  if (isStale) fill.style.opacity = '0.3';
  track.appendChild(fill);
  card.appendChild(track);

  // Badges cap/floor
  const badges = el('div', 'cat-badges');
  (data.caps_applied || []).forEach(cap => {
    const b = el('span', 'badge badge-cap', '▼');
    b.title = `Plafond appliqué : ${cap}`;
    badges.appendChild(b);
  });
  (data.floors_applied || []).forEach(floor => {
    const b = el('span', 'badge badge-floor', '▲');
    b.title = `Plancher appliqué : ${floor}`;
    badges.appendChild(b);
  });
  card.appendChild(badges);

  return card;
}

export function renderIncidentCard(incident, onClick) {
  const card = document.createElement('div');
  const status = incident.status || 'unverified';
  const sev = incident.severity || 1;
  const isCritical = status === 'confirmed' && sev >= 4;

  card.className = `incident-card severity-${sev}${isCritical ? ' critical' : ''}`;
  card.setAttribute('tabindex', '0');
  card.setAttribute('role', 'article');
  card.dataset.incidentId = incident.id || '';

  // Gravité
  const sevEl = el('div', 'incident-severity', String(sev));
  card.appendChild(sevEl);

  // Corps
  const body = el('div', 'incident-body');
  const titleEl = el('div', 'incident-title', incident.title || '(sans titre)');
  body.appendChild(titleEl);

  const meta = el('div', 'incident-meta');
  meta.appendChild(el('span', null, CAT_LABELS[incident.category] || incident.category || ''));
  if (incident.published_at) {
    const dateStr = formatDate(incident.published_at);
    meta.appendChild(el('span', null, dateStr));
  }
  const affected = (incident.affected?.countries || []).join(', ');
  if (affected) meta.appendChild(el('span', null, affected));
  body.appendChild(meta);
  card.appendChild(body);

  // Badges statut
  const badgeContainer = el('div', 'incident-badges');
  const statusBadge = el('span', `badge-status badge-${status}`, STATUS_LABELS[status] || status);
  badgeContainer.appendChild(statusBadge);
  card.appendChild(badgeContainer);

  card.addEventListener('click', () => onClick(incident));
  card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(incident); }});

  return card;
}

export function renderIncidentPanel(incident, scores) {
  const frag = document.createDocumentFragment();
  const status = incident.status || 'unverified';
  const sev = incident.severity || 1;

  // Titre et statut
  const sec0 = el('div', 'panel-section');
  const titleEl = el('h2', 'panel-title', incident.title || '');
  sec0.appendChild(titleEl);
  const statusBadge = el('span', `badge-status badge-${status}`, STATUS_LABELS[status] || status);
  sec0.appendChild(statusBadge);
  frag.appendChild(sec0);

  // Infos générales
  const sec1 = el('div', 'panel-section');
  sec1.appendChild(el('div', 'panel-subtitle', 'Informations'));
  const grid = el('div', 'panel-grid');

  appendRow(grid, 'Catégorie', CAT_LABELS[incident.category] || incident.category || '');
  appendRow(grid, 'Gravité', `${sev}/5`);
  if (incident.published_at) appendRow(grid, 'Publié', formatDate(incident.published_at));
  if (incident.updated_at) appendRow(grid, 'Mis à jour', formatDate(incident.updated_at));
  appendRow(grid, 'Pays affectés', (incident.affected?.countries || []).join(', ') || '—');
  if (incident.affected?.regions?.length) appendRow(grid, 'Régions', incident.affected.regions.join(', '));
  appendRow(grid, 'Infrastructure', incident.affected?.infrastructure_type || '—');
  if (incident.duration_hours) appendRow(grid, 'Durée', `${incident.duration_hours.toFixed(1)}h`);
  sec1.appendChild(grid);
  frag.appendChild(sec1);

  // Résumé
  if (incident.summary) {
    const sec2 = el('div', 'panel-section');
    sec2.appendChild(el('div', 'panel-subtitle', 'Résumé'));
    sec2.appendChild(el('p', 'panel-text', incident.summary));
    frag.appendChild(sec2);
  }

  // Sources
  if (incident.reports?.length) {
    const sec3 = el('div', 'panel-section');
    sec3.appendChild(el('div', 'panel-subtitle', 'Sources'));
    const ul = el('ul', 'source-list');
    incident.reports.forEach(r => {
      const li = el('li', 'source-item');
      const link = safeLink(r.url, r.title || r.source_id || r.url, 'source-link');
      li.appendChild(link);
      const tierBadge = el('span', 'tier-badge', `Tier ${r.tier}`);
      li.appendChild(tierBadge);
      ul.appendChild(li);
    });
    sec3.appendChild(ul);
    frag.appendChild(sec3);
  }

  // Origine
  const origin = incident.origin;
  if (origin?.countries?.length || origin?.threat_actor) {
    const sec4 = el('div', 'panel-section');
    sec4.appendChild(el('div', 'panel-subtitle', 'Origine'));
    const g2 = el('div', 'panel-grid');
    if (origin.countries?.length) appendRow(g2, 'Pays d\'origine', origin.countries.join(', '));
    if (origin.threat_actor) appendRow(g2, 'Acteur', origin.threat_actor);
    appendRow(g2, 'Attribution', origin.attribution || 'none');
    if (origin.coordinated_campaign) appendRow(g2, 'Campagne coordonnée', 'Oui (source officielle)');
    sec4.appendChild(g2);
    frag.appendChild(sec4);
  }

  // Score par zone
  const byZone = incident.score?.by_zone;
  if (byZone && Object.keys(byZone).length) {
    const sec5 = el('div', 'panel-section');
    sec5.appendChild(el('div', 'panel-subtitle', 'Score par zone'));
    Object.entries(byZone).forEach(([zone, zdata]) => {
      if (!zdata?.value && zdata?.value !== 0) return;
      const row = el('div', 'meta-row');
      row.appendChild(el('span', 'meta-label', zoneLabel(zone) + ' :'));
      row.appendChild(el('span', 'meta-value', Math.round(zdata.value)));
      sec5.appendChild(row);

      if (zdata.factors) {
        const table = el('table', 'factor-table');
        Object.entries(zdata.factors).forEach(([k, v]) => {
          const tr = document.createElement('tr');
          tr.appendChild(el('td', null, k));
          tr.appendChild(el('td', null, typeof v === 'number' ? v.toFixed(4) : String(v)));
          table.appendChild(tr);
        });
        sec5.appendChild(table);
      }
    });
    frag.appendChild(sec5);
  }

  // Suggestion IA
  const aiSuggestion = incident.classification?.ai_suggestion;
  if (aiSuggestion) {
    const sec6 = el('div', 'panel-section');
    const aiBox = el('div', 'ai-suggestion');
    aiBox.appendChild(el('div', 'ai-label', `Suggestion IA (${aiSuggestion.model || 'Claude'})`));
    if (aiSuggestion.category) aiBox.appendChild(el('div', null, `Catégorie suggérée : ${aiSuggestion.category}`));
    if (aiSuggestion.summary_fr) aiBox.appendChild(el('p', 'panel-text', aiSuggestion.summary_fr));
    sec6.appendChild(aiBox);
    frag.appendChild(sec6);
  }

  // Historique
  if (incident.history?.length) {
    const sec7 = el('div', 'panel-section');
    sec7.appendChild(el('div', 'panel-subtitle', 'Historique des mises à jour'));
    incident.history.forEach(h => {
      const entry = el('div', 'panel-text');
      entry.textContent = `${formatDate(h.timestamp)} — ${h.field}: ${String(h.from)} → ${String(h.to)}`;
      sec7.appendChild(entry);
    });
    frag.appendChild(sec7);
  }

  // Couverture externe — Freespoke
  const secFs = el('div', 'panel-section panel-section--external');
  const fsTitle = incident.title || '';
  const fsUrl = 'https://freespoke.com/search/web?q=' + encodeURIComponent(fsTitle.substring(0, 200));
  const fsLink = safeLink(fsUrl, 'Voir la couverture sur Freespoke', 'external-search-link');
  secFs.appendChild(fsLink);
  frag.appendChild(secFs);

  return frag;
}

function appendRow(grid, key, value) {
  grid.appendChild(el('span', 'panel-key', key));
  grid.appendChild(el('span', 'panel-val', String(value)));
}

function scoreColor(score) {
  if (score >= 80) return 'score-color-critique';
  if (score >= 60) return 'score-color-alerte';
  if (score >= 40) return 'score-color-prealerte';
  if (score >= 20) return 'score-color-vigilance';
  return 'score-color-normal';
}

function zoneLabel(zone) {
  const labels = { global: 'Global', france: 'France', canada: 'Canada', quebec: 'Québec', mauritius: 'Maurice' };
  return labels[zone] || zone;
}

function formatDate(isoStr) {
  if (!isoStr) return '';
  try {
    const d = new Date(isoStr);
    return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return isoStr; }
}
