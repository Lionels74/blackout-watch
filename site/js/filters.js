/** Gestion des filtres et persistance dans l'URL hash. */

const DEFAULT_FILTERS = {
  category: '',
  severity: '0',
  status: '',
  tier: '',
};

export function readFiltersFromHash() {
  const hash = window.location.hash.replace('#', '');
  if (!hash) return { ...DEFAULT_FILTERS };

  const params = new URLSearchParams(hash);
  return {
    category: params.get('cat') || '',
    severity: params.get('sev') || '0',
    status:   params.get('status') || '',
    tier:     params.get('tier') || '',
  };
}

export function writeFiltersToHash(filters) {
  const params = new URLSearchParams();
  if (filters.category) params.set('cat', filters.category);
  if (filters.severity && filters.severity !== '0') params.set('sev', filters.severity);
  if (filters.status)   params.set('status', filters.status);
  if (filters.tier)     params.set('tier', filters.tier);
  const str = params.toString();
  history.replaceState(null, '', str ? '#' + str : window.location.pathname + window.location.search);
}

export function applyFilters(incidents, filters) {
  return incidents.filter(inc => {
    if (filters.category && inc.category !== filters.category) return false;
    if (filters.severity && filters.severity !== '0') {
      if ((inc.severity || 1) < parseInt(filters.severity, 10)) return false;
    }
    if (filters.status && inc.status !== filters.status) return false;
    if (filters.tier) {
      const tiers = (inc.reports || []).map(r => r.tier);
      if (!tiers.includes(filters.tier)) return false;
    }
    return true;
  });
}

export function bindFilters(onChange) {
  ['filter-category', 'filter-severity', 'filter-status', 'filter-tier'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', onChange);
  });

  const resetBtn = document.getElementById('filter-reset');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      document.getElementById('filter-category').value = '';
      document.getElementById('filter-severity').value = '0';
      document.getElementById('filter-status').value = '';
      document.getElementById('filter-tier').value = '';
      onChange();
    });
  }
}

export function syncFiltersToDOM(filters) {
  const set = (id, val) => { const e = document.getElementById(id); if (e) e.value = val; };
  set('filter-category', filters.category);
  set('filter-severity', filters.severity);
  set('filter-status', filters.status);
  set('filter-tier', filters.tier);
}

export function readFiltersFromDOM() {
  const get = id => (document.getElementById(id)?.value || '');
  return {
    category: get('filter-category'),
    severity: get('filter-severity'),
    status:   get('filter-status'),
    tier:     get('filter-tier'),
  };
}
