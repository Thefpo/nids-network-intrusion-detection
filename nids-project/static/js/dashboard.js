// ─── Charts Setup ─────────────────────────────────────────
const chartColors = ["#f85149","#f0883e","#e3b341","#58a6ff","#3fb950","#bc8cff"];

const typeCtx = document.getElementById("typeChart").getContext("2d");
const typeChart = new Chart(typeCtx, {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: chartColors, borderWidth: 0 }] },
  options: {
    responsive: true,
    plugins: { legend: { labels: { color: "#8b949e", font: { size: 12 } } } }
  }
});

const ipCtx = document.getElementById("ipChart").getContext("2d");
const ipChart = new Chart(ipCtx, {
  type: "bar",
  data: { labels: [], datasets: [{ data: [], backgroundColor: "#58a6ff55", borderColor: "#58a6ff", borderWidth: 1 }] },
  options: {
    indexAxis: "y",
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" } },
      y: { ticks: { color: "#8b949e", font: { family: "Courier New" } }, grid: { display: false } }
    }
  }
});

// ─── State ────────────────────────────────────────────────
let knownAlertIds = new Set();
let cleared = false;

// ─── Fetch & Render ───────────────────────────────────────
async function fetchSummary() {
  const res = await fetch("/api/summary");
  const d   = await res.json();

  document.getElementById("total-alerts").textContent  = d.total_alerts;
  document.getElementById("high-alerts").textContent   = d.severity.HIGH   || 0;
  document.getElementById("medium-alerts").textContent = d.severity.MEDIUM || 0;
  document.getElementById("total-ips").textContent     = d.total_ips;

  // Update type chart
  const labels = Object.keys(d.by_type);
  const values = Object.values(d.by_type);
  typeChart.data.labels = labels;
  typeChart.data.datasets[0].data = values;
  typeChart.update();
}

async function fetchAlerts() {
  const res  = await fetch("/api/alerts");
  const data = await res.json();
  if (!data.length) return;

  const tbody = document.getElementById("alerts-body");

  // First load
  if (tbody.querySelector(".empty")) tbody.innerHTML = "";

  let added = 0;
  data.forEach(a => {
    if (knownAlertIds.has(a.id)) return;
    knownAlertIds.add(a.id);

    if (cleared) return; // user cleared display, keep tracking but don't show

    const sev = a.severity || "LOW";
    const tr  = document.createElement("tr");
    tr.className = "new-alert";
    tr.innerHTML = `
      <td>${a.id}</td>
      <td>${a.time}</td>
      <td><strong>${escapeHtml(a.type)}</strong></td>
      <td><span class="badge badge-${sev}">${sev}</span></td>
      <td>${escapeHtml(a.src)}</td>
      <td>${escapeHtml(a.extra)}</td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
    added++;
  });

  // Keep table to 100 rows
  while (tbody.rows.length > 100) tbody.deleteRow(tbody.rows.length - 1);
}

async function fetchTraffic() {
  const res  = await fetch("/api/stats");
  const data = await res.json();
  const tbody = document.getElementById("traffic-body");

  if (!data.length) return;
  tbody.innerHTML = "";

  data.slice(0, 10).forEach(d => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(d.ip)}</td>
      <td>${d.packets.toLocaleString()}</td>
      <td>${formatBytes(d.bytes)}</td>
      <td>${d.ports}</td>
    `;
    tbody.appendChild(tr);
  });

  // Update IP chart
  ipChart.data.labels = data.slice(0,8).map(d => d.ip);
  ipChart.data.datasets[0].data = data.slice(0,8).map(d => d.packets);
  ipChart.update();
}

function clearAlertDisplay() {
  document.getElementById("alerts-body").innerHTML =
    '<tr><td colspan="6" class="empty">Display cleared — still monitoring…</td></tr>';
  cleared = true;
  setTimeout(() => { cleared = false; }, 0); // re-enable for future alerts
}

// ─── Helpers ──────────────────────────────────────────────
function escapeHtml(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function formatBytes(bytes) {
  if (bytes < 1024)        return bytes + " B";
  if (bytes < 1048576)     return (bytes/1024).toFixed(1) + " KB";
  return (bytes/1048576).toFixed(1) + " MB";
}

// ─── Polling ──────────────────────────────────────────────
async function refresh() {
  await Promise.all([fetchSummary(), fetchAlerts(), fetchTraffic()]);
}

refresh();
setInterval(refresh, 3000);
