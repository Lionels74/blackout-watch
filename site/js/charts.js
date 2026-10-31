/** Graphique historique avec Chart.js 4 (local). */

let _chart = null;

export function initChart(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  // Chart.js est disponible globalement via le script vendor
  if (typeof Chart === 'undefined') return;

  _chart = new Chart(canvas, {
    type: 'line',
    data: { labels: [], datasets: [] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#9ba3b5', font: { size: 11 } }
        },
        tooltip: {
          mode: 'index',
          intersect: false,
          backgroundColor: '#1e2535',
          titleColor: '#e8eaf0',
          bodyColor: '#9ba3b5',
          borderColor: '#2a3048',
          borderWidth: 1,
        },
      },
      scales: {
        x: {
          ticks: { color: '#636b7a', maxTicksLimit: 8, font: { size: 10 } },
          grid: { color: '#1a1f2e' },
        },
        y: {
          min: 0,
          max: 100,
          ticks: { color: '#636b7a', font: { size: 10 } },
          grid: { color: '#1a1f2e' },
        },
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false },
    },
  });
}

export function updateChart(entries, zone, periodDays) {
  if (!_chart) return;

  const cutoff = Date.now() - periodDays * 86400 * 1000;
  const filtered = entries.filter(e => {
    try { return new Date(e.timestamp).getTime() >= cutoff; }
    catch { return false; }
  }).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  const labels = filtered.map(e => {
    const d = new Date(e.timestamp);
    return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  });

  const indexData = filtered.map(e => {
    const zoneData = e.categories?.[zone];
    return e.index ?? 0;
  });

  _chart.data.labels = labels;
  _chart.data.datasets = [
    {
      label: 'Index global',
      data: indexData,
      borderColor: '#4a90d9',
      backgroundColor: 'rgba(74,144,217,0.08)',
      borderWidth: 2,
      pointRadius: 2,
      tension: 0.3,
      fill: true,
    },
  ];

  _chart.update('none');
}
