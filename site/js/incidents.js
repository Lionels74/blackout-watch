/** Gestion du panneau de fiche incident et du hash #incident=ID. */
import { renderIncidentPanel } from './render.js';

let _incidentsMap = {};

export function setIncidents(incidents) {
  _incidentsMap = {};
  (incidents || []).forEach(inc => { if (inc.id) _incidentsMap[inc.id] = inc; });
}

export function openIncidentPanel(incident, scores) {
  const panel = document.getElementById('incident-panel');
  const content = document.getElementById('panel-content');
  const overlay = document.getElementById('panel-overlay');
  if (!panel || !content) return;

  // Vider le contenu précédent de façon sûre
  while (content.firstChild) content.removeChild(content.firstChild);

  const frag = renderIncidentPanel(incident, scores);
  content.appendChild(frag);

  panel.hidden = false;
  overlay?.classList.remove('hidden');

  // Mettre à jour l'URL
  const url = new URL(window.location.href);
  url.hash = `#incident=${encodeURIComponent(incident.id)}`;
  history.pushState({ incidentId: incident.id }, '', url.toString());

  // Focus pour l'accessibilité
  document.getElementById('panel-close')?.focus();
}

export function closeIncidentPanel() {
  const panel = document.getElementById('incident-panel');
  const overlay = document.getElementById('panel-overlay');
  panel.hidden = true;
  overlay?.classList.add('hidden');

  // Retirer l'incident du hash
  const url = new URL(window.location.href);
  if (url.hash.startsWith('#incident=')) {
    url.hash = '';
    history.replaceState(null, '', url.toString());
  }
}

export function checkHashForIncident(scores) {
  const hash = window.location.hash;
  if (!hash.startsWith('#incident=')) return;
  const id = decodeURIComponent(hash.replace('#incident=', ''));
  const incident = _incidentsMap[id];
  if (incident) openIncidentPanel(incident, scores);
}

export function bindPanelClose() {
  document.getElementById('panel-close')?.addEventListener('click', closeIncidentPanel);
  document.getElementById('panel-overlay')?.addEventListener('click', closeIncidentPanel);

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeIncidentPanel();
  });

  window.addEventListener('popstate', e => {
    if (!window.location.hash.startsWith('#incident=')) {
      closeIncidentPanel();
    }
  });
}
