/**
 * BLACKOUT WATCH — Point d'entrée principal.
 * Charge les données, met à jour l'interface, gère les interactions.
 */
import { loadAllData, IS_DEMO } from './data.js';
import {
  renderZoneCard, renderCategoryCard, renderIncidentCard, getLevelClass, getScoreColorClass,
} from './render.js';
import { initChart, updateChart } from './charts.js';
import {
  readFiltersFromHash, writeFiltersToHash, applyFilters,
  bindFilters, syncFiltersToDOM, readFiltersFromDOM,
} from './filters.js';
import {
  setIncidents, openIncidentPanel, closeIncidentPanel,
  checkHashForIncident, bindPanelClose,
} from './incidents.js';

// --- État global ---
let _state = {
  scores: null,
  incidents: [],
  historyHourly: [],
  historyDaily: [],
  selectedZone: 'global',
  selectedPeriod: 7,
  filters: readFiltersFromHash(),
};

// --- Initialisation ---
async function init() {
  // Bandeau démo
  if (IS_DEMO) {
    document.getElementById('demo-banner')?.classList.remove('hidden');
  }

  // Liaison des événements
  bindFilters(onFiltersChange);
  bindPanelClose();
  syncFiltersToDOM(_state.filters);

  // Boutons de période
  document.querySelectorAll('.btn-period').forEach(btn => {
    btn.addEventListener('click', () => {
      _state.selectedPeriod = parseInt(btn.dataset.period, 10);
      document.querySelectorAll('.btn-period').forEach(b => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', b === btn ? 'true' : 'false');
      });
      refreshChart();
    });
  });

  // Sélecteur de zone pour l'historique
  document.getElementById('history-zone-select')?.addEventListener('change', e => {
    refreshChart();
  });

  // Initialiser Chart.js
  initChart('history-chart');

  // Charger les données
  try {
    const data = await loadAllData();
    _state = { ..._state, ...data };
    render();
    checkHashForIncident(_state.scores);
  } catch (err) {
    console.error('Erreur chargement données:', err);
    showError('Impossible de charger les données. Réessayez plus tard.');
  }
}

// --- Rendu principal ---
function render() {
  const { scores, incidents, isDemo } = _state;

  // Bandeau bêta : nombre de catégories actives pour global
  if (scores?.zones?.global?.coverage?.covered_categories) {
    const n = scores.zones.global.coverage.covered_categories.length;
    const el = document.getElementById('beta-active-count');
    if (el) el.textContent = n;
  }

  // Fraîcheur
  if (scores?.stale) {
    document.body.classList.add('stale');
    document.getElementById('stale-banner')?.classList.remove('hidden');
  } else if (scores?.stale_warning) {
    document.getElementById('stale-banner')?.classList.remove('hidden');
  }

  // Header : dernière collecte
  if (scores?.generated_at) {
    const dt = new Date(scores.generated_at);
    const timeEl = document.getElementById('last-update-time');
    if (timeEl) {
      timeEl.textContent = dt.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) +
        ' (' + dt.toLocaleDateString('fr-FR') + ')';
    }
    const ageEl = document.getElementById('last-update-age');
    if (ageEl) {
      const ageMin = Math.round((Date.now() - dt.getTime()) / 60000);
      ageEl.textContent = ageMin < 60 ? `(il y a ${ageMin} min)` : `(il y a ${Math.round(ageMin/60)}h)`;
    }
  }

  // Global index
  renderGlobalIndex(scores);

  // Zones
  renderZones(scores);

  // Catégories pour la zone sélectionnée
  renderCategories(scores, _state.selectedZone);

  // Incidents
  setIncidents(_state.incidents);
  renderIncidents();

  // Historique
  refreshChart();
}

function renderGlobalIndex(scores) {
  const globalData = scores?.zones?.global;
  const index = Math.round(globalData?.index ?? 0);
  const level = globalData?.level || 'NORMAL';
  const ci = Math.round(globalData?.convergence_index ?? 0);
  const coi = Math.round(globalData?.confidence?.index ?? 0);

  const scoreEl = document.getElementById('global-score');
  const levelEl = document.getElementById('global-level');
  if (scoreEl) {
    scoreEl.textContent = String(index);
    scoreEl.className = `global-score ${getScoreColorClass(level)}`;
    if (scores?.stale) scoreEl.style.color = '';
  }
  if (levelEl) {
    levelEl.textContent = level;
    levelEl.className = `global-level ${getLevelClass(level)}`;
  }
  const ciEl = document.getElementById('global-ci');
  if (ciEl) ciEl.textContent = String(ci);
  const coiEl = document.getElementById('global-coi');
  if (coiEl) coiEl.textContent = String(coi);
  const headerCoiEl = document.getElementById('coi-value');
  if (headerCoiEl) headerCoiEl.textContent = String(coi);
}

function renderZones(scores) {
  const grid = document.getElementById('zones-grid');
  if (!grid) return;
  while (grid.firstChild) grid.removeChild(grid.firstChild);

  const zoneOrder = ['global', 'france', 'canada', 'quebec', 'mauritius'];
  zoneOrder.forEach(zone => {
    const zoneData = scores?.zones?.[zone];
    if (!zoneData) return;
    const card = renderZoneCard(zone, zoneData, zone === _state.selectedZone, onZoneSelect);
    grid.appendChild(card);
  });
}

function renderCategories(scores, zone) {
  const grid = document.getElementById('categories-grid');
  const labelEl = document.getElementById('selected-zone-label');
  if (!grid) return;

  const zoneLabels = { global: 'Global', france: 'France', canada: 'Canada', quebec: 'Québec', mauritius: 'Maurice' };
  if (labelEl) labelEl.textContent = zoneLabels[zone] || zone;

  while (grid.firstChild) grid.removeChild(grid.firstChild);

  const categories = ['electricity', 'cables', 'finance', 'cyber', 'logistics', 'geopolitics'];
  const zoneData = scores?.zones?.[zone];
  categories.forEach(cat => {
    const catData = zoneData?.categories?.[cat] || { score: 0, caps_applied: [], floors_applied: [] };
    const card = renderCategoryCard(cat, catData, !!scores?.stale);
    grid.appendChild(card);
  });
}

function renderIncidents() {
  const { incidents, filters } = _state;
  const filtered = applyFilters(incidents, filters);

  // Incidents critiques (confirmed + severity >= 4) en tête
  const critical = filtered.filter(i => i.status === 'confirmed' && (i.severity || 1) >= 4);
  const rest = filtered.filter(i => !(i.status === 'confirmed' && (i.severity || 1) >= 4));

  const criticalContainer = document.getElementById('critical-incidents');
  const listContainer = document.getElementById('incidents-list');

  if (criticalContainer) {
    while (criticalContainer.firstChild) criticalContainer.removeChild(criticalContainer.firstChild);
    critical.forEach(inc => {
      const card = renderIncidentCard(inc, onIncidentClick);
      criticalContainer.appendChild(card);
    });
  }

  if (listContainer) {
    while (listContainer.firstChild) listContainer.removeChild(listContainer.firstChild);
    if (rest.length === 0 && critical.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'incidents-empty';
      empty.textContent = filtered.length === 0 ? 'Aucun événement pour ces filtres.' : 'Aucun événement récent.';
      listContainer.appendChild(empty);
    } else {
      rest.forEach(inc => {
        const card = renderIncidentCard(inc, onIncidentClick);
        listContainer.appendChild(card);
      });
    }
  }
}

function refreshChart() {
  const zone = document.getElementById('history-zone-select')?.value || 'global';
  const period = _state.selectedPeriod;
  const entries = period <= 7 ? _state.historyHourly : _state.historyDaily;
  updateChart(entries, zone, period);
}

// --- Gestionnaires d'événements ---
function onZoneSelect(zone) {
  _state.selectedZone = zone;
  renderZones(_state.scores);
  renderCategories(_state.scores, zone);
}

function onFiltersChange() {
  _state.filters = readFiltersFromDOM();
  writeFiltersToHash(_state.filters);
  renderIncidents();
}

function onIncidentClick(incident) {
  openIncidentPanel(incident, _state.scores);
}

function showError(msg) {
  const listContainer = document.getElementById('incidents-list');
  if (listContainer) {
    while (listContainer.firstChild) listContainer.removeChild(listContainer.firstChild);
    const errEl = document.createElement('div');
    errEl.className = 'incidents-empty';
    errEl.textContent = msg;
    listContainer.appendChild(errEl);
  }
}

// --- Lancement ---
document.addEventListener('DOMContentLoaded', init);
