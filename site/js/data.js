/**
 * Chargement des données JSON.
 * En mode démo (?demo=1), charge depuis demo/.
 */

const IS_DEMO = new URLSearchParams(window.location.search).has('demo');

const DATA_PATHS = {
  scores:   IS_DEMO ? 'demo/demo_scores.json'   : 'data/scores.json',
  incidents: IS_DEMO ? 'demo/demo_incidents.json' : 'data/incidents.json',
  historyHourly: IS_DEMO ? 'demo/demo_history.json' : 'data/history_hourly.json',
  historyDaily:  IS_DEMO ? 'demo/demo_history.json' : 'data/history_daily.json',
  sourcesStatus: 'data/sources_status.json',
};

async function fetchJSON(path) {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`HTTP ${resp.status} pour ${path}`);
  return resp.json();
}

export async function loadAllData() {
  const [scores, incidents, historyHourly, historyDaily] = await Promise.allSettled([
    fetchJSON(DATA_PATHS.scores),
    fetchJSON(DATA_PATHS.incidents),
    fetchJSON(DATA_PATHS.historyHourly),
    fetchJSON(DATA_PATHS.historyDaily),
  ]);

  return {
    scores: scores.status === 'fulfilled' ? scores.value : null,
    incidents: incidents.status === 'fulfilled' ? incidents.value : [],
    historyHourly: historyHourly.status === 'fulfilled' ? (historyHourly.value.entries || []) : [],
    historyDaily: historyDaily.status === 'fulfilled' ? (historyDaily.value.entries || []) : [],
    isDemo: IS_DEMO,
  };
}

export { IS_DEMO };
