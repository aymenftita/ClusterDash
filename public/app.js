/* ClusterDash front-end. Vanilla — no build step. */
'use strict';

// ------------------------------------------------------------- utilities ---

const $ = (sel, root = document) => root.querySelector(sel);
const el = (id) => document.getElementById(id);

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });
  if (res.status === 401) { showLogin(); throw new Error('not authenticated'); }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || `request failed (${res.status})`);
  return data;
}

function toast(message, kind = '') {
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  node.textContent = message;
  document.body.appendChild(node);
  setTimeout(() => node.remove(), 4600);
}

const pct = (v) => `${(v ?? 0).toFixed(v >= 10 ? 0 : 1)}%`;

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

const rate = (bytesPerSecond) => `${bytes(bytesPerSecond)}/s`;

function duration(seconds) {
  if (!seconds) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

const clock = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const stamp = (ts) => new Date(ts).toLocaleString([], {
  month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
});

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// Colour follows the entity, never its rank.
const SLOT_KEY = 'clusterdash.slots';
const SLOT_COUNT = 8;
let slots = {};
try { slots = JSON.parse(localStorage.getItem(SLOT_KEY) || '{}'); } catch { slots = {}; }

function slotFor(hostId) {
  if (slots[hostId] == null) {
    const taken = new Set(Object.values(slots));
    let next = 1;
    while (taken.has(next) && next <= SLOT_COUNT) next += 1;
    slots[hostId] = next > SLOT_COUNT ? 1 : next;
    localStorage.setItem(SLOT_KEY, JSON.stringify(slots));
  }
  return slots[hostId];
}

/**
 * Release the slots of hosts that no longer exist, so a deleted host does not
 * burn its colour forever. If anything still points past the end of the palette
 * — state left behind by earlier deletions — re-pack every current host into
 * slots 1..n once. Steady state is stable: a host keeps its colour, and removing
 * one never repaints the survivors.
 */
function reconcileSlots(hosts) {
  if (!hosts.length) return;
  const ids = hosts.map((h) => String(h.id));
  for (const key of Object.keys(slots)) if (!ids.includes(key)) delete slots[key];

  const needsRepack = Object.values(slots).some((s) => s > SLOT_COUNT || s > hosts.length);
  if (needsRepack) {
    [...hosts].sort((a, b) => a.id - b.id).forEach((h, i) => { slots[h.id] = (i % SLOT_COUNT) + 1; });
  }
  localStorage.setItem(SLOT_KEY, JSON.stringify(slots));
}

const hostColor = (hostId) => cssVar(`--series-${slotFor(hostId)}`) || cssVar('--series-1');

// Fixed metric→colour mapping, identical on every card and chart.
const METRIC_COLOR = { cpu: '--series-1', mem: '--series-2', disk: '--series-3', load1: '--series-4' };
const METRIC_LABEL = { cpu: 'CPU utilisation', mem: 'Memory used', disk: 'Disk used', load1: 'Load average' };

// ----------------------------------------------------------------- state ---

let state = {
  hosts: [], view: 'fleet', fleetMinutes: 60, fleetMetric: 'cpu',
  history: {}, fleetTable: false, alerts: [], notify: null,
};
let refreshTimer = null;

// ----------------------------------------------------------------- login ---

function showLogin() {
  el('login').classList.remove('hidden');
  el('app').classList.add('hidden');
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}

function showApp(me) {
  el('login').classList.add('hidden');
  el('app').classList.remove('hidden');
  el('who').textContent = me.user;
  el('poll-note').textContent = `polling every ${me.pollSeconds}s · ${me.retentionHours}h history`;
}

el('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const error = el('login-error');
  error.classList.add('hidden');
  try {
    await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
    });
    await boot();
  } catch (err) {
    error.textContent = err.message;
    error.classList.remove('hidden');
  }
});

el('logout').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  showLogin();
});

// ----------------------------------------------------------------- theme ---

const savedTheme = localStorage.getItem('clusterdash.theme');
if (savedTheme) document.documentElement.dataset.theme = savedTheme;

el('theme-toggle').addEventListener('click', () => {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const current = document.documentElement.dataset.theme || (dark ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('clusterdash.theme', next);
  render();
});

// ------------------------------------------------------------------ tabs ---

document.querySelectorAll('nav.tabs[role=tablist] button').forEach((tab) => {
  tab.addEventListener('click', () => {
    state.view = tab.dataset.view;
    document.querySelectorAll('nav.tabs[role=tablist] button')
      .forEach((b) => b.setAttribute('aria-selected', String(b === tab)));
    document.querySelectorAll('section.view')
      .forEach((s) => s.classList.toggle('active', s.id === `view-${state.view}`));
    if (state.view === 'audit') loadAudit();
    if (state.view === 'hosts') renderHostsTable();
    if (state.view === 'sites') loadChecks();
    if (state.view === 'alerts') loadAlerts();
    if (state.view === 'settings') loadNotifySettings();
  });
});

// ----------------------------------------------------------- line charts ---

/**
 * Multi-series time-series line chart with a crosshair tooltip.
 * Series are direct-labelled at their last point and repeated in a legend, so
 * identity never depends on colour alone.
 */
function drawLineChart(svg, series, options = {}) {
  const wrap = svg.parentElement;
  const width = Math.max(wrap.clientWidth, 320);
  const height = options.height || 240;
  const pad = { top: 12, right: options.labels === false ? 16 : 96, bottom: 26, left: 46 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const fmt = options.valueFormat || pct;

  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  svg.innerHTML = '';

  const points = series.flatMap((s) => s.points);
  if (!points.length) {
    svg.innerHTML = `<text x="${width / 2}" y="${height / 2}" text-anchor="middle"
      fill="${cssVar('--muted')}" font-size="13">No samples yet — first poll lands within a minute.</text>`;
    return;
  }

  const tMin = Math.min(...points.map((p) => p.ts));
  const tMax = Math.max(...points.map((p) => p.ts));
  const yMax = options.yMax ?? Math.max(1, Math.ceil(Math.max(...points.map((p) => p.v)) * 1.2));
  const span = tMax - tMin || 1;

  const x = (ts) => pad.left + ((ts - tMin) / span) * plotW;
  const y = (v) => pad.top + plotH - (Math.min(v, yMax) / yMax) * plotH;

  const ns = 'http://www.w3.org/2000/svg';
  const add = (tag, attrs, text) => {
    const node = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text != null) node.textContent = text;
    svg.appendChild(node);
    return node;
  };

  // Recessive grid + axis ink.
  const ticks = 4;
  for (let i = 0; i <= ticks; i += 1) {
    const value = (yMax / ticks) * i;
    const yy = y(value);
    add('line', { x1: pad.left, x2: pad.left + plotW, y1: yy, y2: yy,
                  stroke: cssVar('--grid'), 'stroke-width': 1 });
    add('text', { x: pad.left - 8, y: yy + 4, 'text-anchor': 'end',
                  fill: cssVar('--muted'), 'font-size': 11 }, fmt(value));
  }
  add('line', { x1: pad.left, x2: pad.left + plotW, y1: pad.top + plotH, y2: pad.top + plotH,
                stroke: cssVar('--axis'), 'stroke-width': 1 });

  const timeTicks = Math.min(5, Math.max(2, Math.floor(plotW / 90)));
  for (let i = 0; i <= timeTicks; i += 1) {
    const ts = tMin + (span / timeTicks) * i;
    add('text', { x: x(ts), y: height - 8,
                  'text-anchor': i === 0 ? 'start' : (i === timeTicks ? 'end' : 'middle'),
                  fill: cssVar('--muted'), 'font-size': 11 }, clock(ts));
  }

  for (const s of series) {
    if (!s.points.length) continue;
    const d = s.points.map((p, i) => `${i ? 'L' : 'M'}${x(p.ts).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ');
    add('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 2,
                  'stroke-linejoin': 'round', 'stroke-linecap': 'round' });
  }

  // Direct labels at the last point, nudged apart so they never overlap.
  if (options.labels !== false) {
    const GAP = 13;
    const ends = series
      .filter((s) => s.points.length)
      .map((s) => ({ s, y: y(s.points[s.points.length - 1].v) }))
      .sort((a, b) => a.y - b.y);

    // Push overlapping labels down, then lift the whole stack back inside the
    // plot if it ran off the bottom. Clamping each label individually would
    // pile them onto one line — which is what idle hosts near 0% do.
    for (let i = 1; i < ends.length; i += 1) {
      if (ends[i].y - ends[i - 1].y < GAP) ends[i].y = ends[i - 1].y + GAP;
    }
    const overflow = ends.length ? ends[ends.length - 1].y - (pad.top + plotH) : 0;
    if (overflow > 0) for (const end of ends) end.y = Math.max(pad.top + 8, end.y - overflow);

    for (const end of ends) {
      const last = end.s.points[end.s.points.length - 1];
      add('line', { x1: pad.left + plotW, x2: pad.left + plotW + 6,
                    y1: y(last.v), y2: end.y, stroke: end.s.color, 'stroke-width': 1, opacity: 0.6 });
      add('text', { x: pad.left + plotW + 9, y: end.y + 3.5,
                    fill: cssVar('--text-secondary'), 'font-size': 11 },
          `${end.s.name} ${fmt(last.v)}`);
    }
  }

  const crosshair = add('line', { x1: 0, x2: 0, y1: pad.top, y2: pad.top + plotH,
                                  stroke: cssVar('--axis'), 'stroke-width': 1, opacity: 0 });
  const markers = series.map((s) => add('circle', {
    r: 4, fill: s.color, stroke: cssVar('--surface-1'), 'stroke-width': 2, opacity: 0,
  }));

  let tip = wrap.querySelector('.tooltip');
  if (!tip) {
    tip = document.createElement('div');
    tip.className = 'tooltip hidden';
    wrap.appendChild(tip);
  }

  const overlay = add('rect', { x: pad.left, y: pad.top, width: plotW, height: plotH,
                                fill: 'transparent', style: 'cursor:crosshair' });

  overlay.addEventListener('pointermove', (event) => {
    const box = svg.getBoundingClientRect();
    const ts = tMin + ((event.clientX - box.left - pad.left) / plotW) * span;
    crosshair.setAttribute('opacity', 1);

    const rows = [];
    let anchorTs = ts;
    series.forEach((s, i) => {
      if (!s.points.length) { markers[i].setAttribute('opacity', 0); return; }
      let best = s.points[0];
      for (const p of s.points) if (Math.abs(p.ts - ts) < Math.abs(best.ts - ts)) best = p;
      anchorTs = best.ts;
      markers[i].setAttribute('cx', x(best.ts));
      markers[i].setAttribute('cy', y(best.v));
      markers[i].setAttribute('opacity', 1);
      rows.push({ name: s.name, color: s.color, value: best.v });
    });

    crosshair.setAttribute('x1', x(anchorTs));
    crosshair.setAttribute('x2', x(anchorTs));

    tip.className = 'tooltip';
    tip.innerHTML = `<div class="t-time">${clock(anchorTs)}</div>` + rows.map((r) => `
      <div class="t-row">
        <span class="lhs"><span class="key" style="background:${r.color}"></span>${esc(r.name)}</span>
        <span class="val">${fmt(r.value)}</span>
      </div>`).join('');

    const left = Math.min(Math.max(x(anchorTs) + 12, 4), width - tip.offsetWidth - 4);
    tip.style.left = `${left}px`;
    tip.style.top = `${pad.top + 4}px`;
  });

  overlay.addEventListener('pointerleave', () => {
    crosshair.setAttribute('opacity', 0);
    markers.forEach((m) => m.setAttribute('opacity', 0));
    tip.className = 'tooltip hidden';
  });
}

/** Bare sparkline for a stat tile: one series, no axes, no legend. */
function sparkline(values, color, width = 260, height = 26) {
  if (!values.length) return '';
  const max = Math.max(10, ...values);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const d = values
    .map((v, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)},${(height - (v / max) * (height - 3) - 1.5).toFixed(1)}`)
    .join(' ');
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-hidden="true">
    <path d="${d}" fill="none" stroke="${color}" stroke-width="2"
          stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
  </svg>`;
}

/** Uptime strip: one bar per check result, green up / red down. */
function uptimeStrip(history) {
  if (!history.length) return '<span style="color:var(--muted);font-size:12px">no samples yet</span>';
  return `<div class="strip">${history.map((h) => `
    <span class="bar ${h.ok ? 'up' : 'down'}" title="${clock(h.ts)} — ${h.ok ? 'up' : 'down'}${h.ms != null ? ` (${Math.round(h.ms)} ms)` : ''}"></span>
  `).join('')}</div>`;
}

// ------------------------------------------------------------ fleet view ---

function statusMarkup(host) {
  if (host.online) return '<span class="status up"><span class="dot"></span>✓ Online</span>';
  if (host.checkedAt) return '<span class="status down"><span class="dot"></span>✕ Unreachable</span>';
  return '<span class="status unknown"><span class="dot"></span>• Not checked yet</span>';
}

function tile(label, metricKey, valueText, subText, series) {
  const color = cssVar(METRIC_COLOR[metricKey]);
  return `
    <div class="tile">
      <div class="label"><span class="swatch" style="background:${color}"></span>${label}</div>
      <div class="value">${valueText}</div>
      <div class="sub">${subText}</div>
      ${sparkline(series, color)}
    </div>`;
}

function renderHostCards() {
  const grid = el('host-grid');
  if (!state.hosts.length) {
    grid.innerHTML = `<div class="empty">No hosts yet. Open the <strong>Hosts</strong> tab and add your servers.</div>`;
    return;
  }
  grid.innerHTML = state.hosts.map((host) => {
    const s = host.sample;
    const rows = state.history[host.id] || [];
    const info = (s && s.info) || {};
    const tiles = s ? `
      <div class="tiles">
        ${tile('CPU', 'cpu', pct(s.cpu), `${info.ncpu || 1} vCPU · load ${(s.load1 || 0).toFixed(2)}`,
               rows.map((r) => r.cpu || 0))}
        ${tile('Memory', 'mem', pct(s.mem), `${bytes(info.memTotalBytes || 0)} total`,
               rows.map((r) => r.mem || 0))}
        ${tile('Disk', 'disk', pct(s.disk), `${bytes(info.diskUsedBytes || 0)} of ${bytes(info.diskTotalBytes || 0)}`,
               rows.map((r) => r.disk || 0))}
      </div>
      <div class="meta-row">
        <span>${esc(info.os || 'unknown')}</span>
        <span>up ${duration(s.uptime)}</span>
        <span>↓ ${rate(s.rx)} · ↑ ${rate(s.tx)}</span>
        <span>${s.procs || 0} procs</span>
      </div>` : `<p class="hint" style="margin:12px 0 0">${esc(host.error || 'Waiting for the first sample…')}</p>`;

    return `
      <article class="host-card" data-host="${host.id}" tabindex="0">
        <header>
          <span class="key" style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${hostColor(host.id)}"></span>
          <span class="name">${esc(host.name)}</span>
          <span class="role">${esc(host.role)}</span>
          <span style="flex:1"></span>
          ${statusMarkup(host)}
        </header>
        <div class="addr">${esc(host.username)}@${esc(host.hostname)}:${host.port}</div>
        ${tiles}
      </article>`;
  }).join('');

  grid.querySelectorAll('.host-card').forEach((card) => {
    const open = () => openDetail(Number(card.dataset.host));
    card.addEventListener('click', open);
    card.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
  });
}

const isPercentMetric = () => state.fleetMetric !== 'load1';
const fleetFormat = (v) => (isPercentMetric() ? pct(v) : (v ?? 0).toFixed(2));

function fleetSeries() {
  return state.hosts.map((host) => ({
    id: host.id,
    name: host.name,
    color: hostColor(host.id),
    points: (state.history[host.id] || []).map((r) => ({ ts: r.ts, v: r[state.fleetMetric] || 0 })),
  }));
}

function renderFleetChart() {
  const series = fleetSeries();
  el('fleet-title').textContent = `${METRIC_LABEL[state.fleetMetric]} across the fleet`;

  drawLineChart(el('fleet-chart'), series, {
    yMax: isPercentMetric() ? 100 : undefined,
    valueFormat: fleetFormat,
    height: 250,
  });

  el('fleet-legend').innerHTML = series.map((s) => `
    <span class="item"><span class="key" style="background:${s.color}"></span>${esc(s.name)}</span>`).join('');

  // Table view is the relief for light-mode series below 3:1 contrast.
  const stamps = [...new Set(series.flatMap((s) => s.points.map((p) => p.ts)))]
    .sort((a, b) => b - a).slice(0, 60);
  el('fleet-table').innerHTML = `<table>
    <thead><tr><th>Time</th>${series.map((s) => `<th class="num">${esc(s.name)}</th>`).join('')}</tr></thead>
    <tbody>${stamps.map((ts) => `<tr><td>${clock(ts)}</td>${series.map((s) => {
      const hit = s.points.find((p) => Math.abs(p.ts - ts) < 5000);
      return `<td class="num">${hit ? fleetFormat(hit.v) : '—'}</td>`;
    }).join('')}</tr>`).join('')}</tbody></table>`;
}

el('fleet-metric').addEventListener('change', (e) => {
  state.fleetMetric = e.target.value;
  renderFleetChart();
});

el('fleet-range').addEventListener('change', (e) => {
  state.fleetMinutes = Number(e.target.value);
  el('fleet-range-note').textContent =
    `Last ${state.fleetMinutes >= 60 ? `${state.fleetMinutes / 60} hour(s)` : `${state.fleetMinutes} minutes`}, sampled over SSH.`;
  refresh();
});

el('fleet-table-toggle').addEventListener('click', (e) => {
  state.fleetTable = !state.fleetTable;
  e.target.setAttribute('aria-pressed', String(state.fleetTable));
  el('fleet-table').classList.toggle('hidden', !state.fleetTable);
  el('fleet-chart-wrap').classList.toggle('hidden', state.fleetTable);
  e.target.textContent = state.fleetTable ? 'Chart view' : 'Table view';
});

// ------------------------------------------------------------ hosts view ---

function renderHostsTable() {
  el('hosts-table').innerHTML = `<table>
    <thead><tr>
      <th>Name</th><th>Address</th><th>Role</th><th>Provider</th><th>Status</th><th></th>
    </tr></thead>
    <tbody>${state.hosts.map((h) => `
      <tr>
        <td><span class="key" style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${hostColor(h.id)};margin-right:6px"></span>${esc(h.name)}</td>
        <td class="mono">${esc(h.username)}@${esc(h.hostname)}:${h.port}</td>
        <td>${esc(h.role)}</td>
        <td>${esc(h.provider || '—')}</td>
        <td>${statusMarkup(h)}</td>
        <td style="text-align:right;white-space:nowrap">
          <button data-test="${h.id}">Test</button>
          <button class="danger" data-remove="${h.id}">Remove</button>
        </td>
      </tr>`).join('')}</tbody></table>`;

  el('hosts-table').querySelectorAll('[data-test]').forEach((b) => {
    b.addEventListener('click', async () => {
      b.disabled = true;
      b.textContent = 'Testing…';
      try {
        await api(`/api/hosts/${b.dataset.test}/test`, { method: 'POST' });
        toast('SSH connection succeeded.', 'ok');
      } catch (err) {
        toast(`SSH failed: ${err.message}`, 'error');
      } finally {
        b.disabled = false;
        b.textContent = 'Test';
      }
    });
  });

  el('hosts-table').querySelectorAll('[data-remove]').forEach((b) => {
    b.addEventListener('click', async () => {
      const host = state.hosts.find((h) => h.id === Number(b.dataset.remove));
      if (!confirm(`Remove ${host.name}? Its stored credentials and pooled connection are deleted. Metric history and the audit trail are kept.`)) return;
      await api(`/api/hosts/${b.dataset.remove}`, { method: 'DELETE' });
      toast('Host removed.', 'ok');
      await refresh();
      renderHostsTable();
    });
  });
}

el('add-host').addEventListener('click', () => el('add-modal').classList.remove('hidden'));
el('add-close').addEventListener('click', () => el('add-modal').classList.add('hidden'));

el('add-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = Object.fromEntries(new FormData(event.target).entries());
  payload.port = Number(payload.port) || 22;
  const button = $('button[type=submit]', event.target);
  button.disabled = true;
  button.textContent = 'Adding…';
  try {
    const { id } = await api('/api/hosts', { method: 'POST', body: JSON.stringify(payload) });
    el('add-modal').classList.add('hidden');
    event.target.reset();
    await refresh();
    renderHostsTable();
    try {
      await api(`/api/hosts/${id}/test`, { method: 'POST' });
      toast(`${payload.name} added — SSH connection verified.`, 'ok');
    } catch (err) {
      toast(`${payload.name} added, but SSH failed: ${err.message}`, 'error');
    }
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Add and test connection';
  }
});

// ------------------------------------------------------------ sites view ---

async function loadChecks() {
  const target = el('checks-body');
  try {
    const checks = await api('/api/checks');
    if (!checks.length) {
      target.innerHTML = `<div class="empty">No monitors yet. Add your web app's URL to find out when it stops
        answering — a green server does not mean a working site.</div>`;
      return;
    }
    target.innerHTML = checks.map((c) => `
      <div class="check-card">
        <header>
          <span class="status ${c.up === null ? 'unknown' : c.up ? 'up' : 'down'}">
            <span class="dot"></span>${c.up === null ? '• pending' : c.up ? '✓ Up' : '✕ Down'}
          </span>
          <strong>${esc(c.name)}</strong>
          ${c.enabled ? '' : '<span class="pill idle">○ paused</span>'}
          <span class="spacer"></span>
          <button data-toggle="${c.id}">${c.enabled ? 'Pause' : 'Resume'}</button>
          <button class="danger" data-del="${c.id}">Remove</button>
        </header>
        <a href="${esc(c.url)}" target="_blank" rel="noopener" class="check-url">${esc(c.url)}</a>
        <div class="check-stats">
          <div><span class="k">Uptime 24h</span><span class="v">${c.uptime24h == null ? '—' : `${c.uptime24h.toFixed(2)}%`}</span></div>
          <div><span class="k">Response</span><span class="v">${c.ms == null ? '—' : `${Math.round(c.ms)} ms`}</span></div>
          <div><span class="k">Average</span><span class="v">${c.avgMs == null ? '—' : `${Math.round(c.avgMs)} ms`}</span></div>
          <div><span class="k">Status</span><span class="v">${c.status ?? '—'}</span></div>
          <div><span class="k">TLS expiry</span><span class="v ${c.tlsDays != null && c.tlsDays <= 14 ? 'warn' : ''}">${
            c.tlsDays == null ? '—' : `${c.tlsDays} days`}</span></div>
        </div>
        ${uptimeStrip(c.history)}
        ${c.error ? `<p class="hint" style="color:var(--critical);margin:8px 0 0">${esc(c.error)}</p>` : ''}
      </div>`).join('');

    target.querySelectorAll('[data-del]').forEach((b) => {
      b.addEventListener('click', async () => {
        if (!confirm('Remove this monitor and its history?')) return;
        await api(`/api/checks/${b.dataset.del}`, { method: 'DELETE' });
        loadChecks();
      });
    });
    target.querySelectorAll('[data-toggle]').forEach((b) => {
      b.addEventListener('click', async () => {
        await api(`/api/checks/${b.dataset.toggle}/toggle`, { method: 'POST' });
        loadChecks();
      });
    });
  } catch (err) {
    target.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

el('add-check').addEventListener('click', () => el('check-modal').classList.remove('hidden'));
el('check-close').addEventListener('click', () => el('check-modal').classList.add('hidden'));

el('check-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = Object.fromEntries(new FormData(event.target).entries());
  payload.expect_status = Number(payload.expect_status) || 200;
  try {
    await api('/api/checks', { method: 'POST', body: JSON.stringify(payload) });
    el('check-modal').classList.add('hidden');
    event.target.reset();
    toast('Monitor added — first check runs immediately.', 'ok');
    setTimeout(loadChecks, 1200);
  } catch (err) {
    toast(err.message, 'error');
  }
});

// ----------------------------------------------------------- alerts view ---

async function loadAlerts() {
  state.alerts = await api('/api/alerts?limit=200');
  const open = state.alerts.filter((a) => !a.resolved_at);
  const badge = el('alert-badge');
  badge.textContent = open.length;
  badge.classList.toggle('hidden', open.length === 0);

  const icon = { critical: '🔴', warning: '🟠', good: '🟢' };
  el('alerts-table').innerHTML = state.alerts.length ? `<table>
    <thead><tr><th>Opened</th><th>Severity</th><th>Subject</th><th>Detail</th><th>State</th></tr></thead>
    <tbody>${state.alerts.map((a) => `<tr>
      <td style="white-space:nowrap">${stamp(a.opened_at)}</td>
      <td>${icon[a.severity] || '⚠️'} ${esc(a.severity)}</td>
      <td><strong>${esc(a.subject)}</strong></td>
      <td style="max-width:420px;white-space:pre-wrap">${esc(a.message)}</td>
      <td>${a.resolved_at
        ? `<span class="pill ok">✓ resolved</span><div style="color:var(--muted);font-size:11px">${stamp(a.resolved_at)}</div>`
        : '<span class="pill error">● open</span>'}</td>
    </tr>`).join('')}</tbody></table>`
    : '<div class="empty">No alerts recorded. That is the good outcome.</div>';
}

el('alerts-refresh').addEventListener('click', loadAlerts);

// ------------------------------------------------------------ audit view ---

let auditRows = [];

function renderAudit() {
  const needle = el('audit-search').value.trim().toLowerCase();
  const rows = needle
    ? auditRows.filter((r) => `${r.actor} ${r.action} ${r.host_name} ${r.detail} ${r.result}`
        .toLowerCase().includes(needle))
    : auditRows;
  const pillClass = (r) => (r === 'ok' ? 'ok' : r === 'denied' ? 'denied' : 'error');

  el('audit-table').innerHTML = rows.length ? `<table>
    <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Host</th><th>Detail</th><th>Result</th></tr></thead>
    <tbody>${rows.map((r) => `
      <tr>
        <td style="white-space:nowrap">${stamp(r.ts)}</td>
        <td>${esc(r.actor)}${r.ip ? `<div style="color:var(--muted);font-size:11px">${esc(r.ip)}</div>` : ''}</td>
        <td class="mono">${esc(r.action)}</td>
        <td>${esc(r.host_name || '—')}</td>
        <td style="max-width:420px">${esc(r.detail)}</td>
        <td><span class="pill ${pillClass(r.result)}">${esc(r.result)}</span></td>
      </tr>`).join('')}</tbody></table>`
    : `<div class="empty">${auditRows.length ? 'Nothing matches that filter.' : 'No audit entries yet.'}</div>`;
}

async function loadAudit() {
  const hostId = el('audit-filter').value;
  auditRows = await api(`/api/audit?limit=500${hostId ? `&host=${hostId}` : ''}`);
  renderAudit();
}

el('audit-refresh').addEventListener('click', loadAudit);
el('audit-filter').addEventListener('change', loadAudit);
el('audit-search').addEventListener('input', renderAudit);

// --------------------------------------------------- console recordings ---

async function loadRecordings() {
  const target = el('rec-table');
  target.innerHTML = '<p class="hint">Loading…</p>';
  try {
    const rows = await api('/api/recordings?limit=200');
    target.innerHTML = rows.length ? `<table>
      <thead><tr><th>Started</th><th>Actor</th><th>Host</th><th>Type</th><th>Duration</th><th class="num">Size</th><th></th></tr></thead>
      <tbody>${rows.map((r) => `<tr>
        <td style="white-space:nowrap">${stamp(r.started)}</td>
        <td>${esc(r.actor)}</td>
        <td>${esc(r.host_name)}</td>
        <td class="mono">${esc(r.kind)}</td>
        <td>${r.ended ? `${Math.max(1, Math.round((r.ended - r.started) / 1000))}s` : 'active'}</td>
        <td class="num">${bytes(r.bytes)}</td>
        <td style="text-align:right"><button data-rec="${esc(r.id)}">View</button></td>
      </tr>`).join('')}</tbody></table>`
      : '<div class="empty">No console sessions recorded yet.</div>';

    target.querySelectorAll('[data-rec]').forEach((b) => {
      b.addEventListener('click', async () => {
        try {
          const rec = await api(`/api/recordings/${b.dataset.rec}`);
          el('rec-title').textContent = `${rec.kind} — ${rec.host_name} — ${stamp(rec.started)}`;
          el('rec-output').textContent = rec.transcript;
          el('rec-modal').classList.remove('hidden');
        } catch (err) {
          toast(err.message, 'error');
        }
      });
    });
  } catch (err) {
    target.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

el('rec-refresh').addEventListener('click', loadRecordings);
el('rec-close').addEventListener('click', () => el('rec-modal').classList.add('hidden'));

// --------------------------------------------------------- settings view ---

async function loadNotifySettings() {
  const target = el('notify-body');
  try {
    const s = await api('/api/notify/status');
    state.notify = s;
    const t = s.thresholds;
    target.innerHTML = `
      <div class="check-stats" style="margin-bottom:14px">
        <div><span class="k">Provider</span><span class="v">${esc(s.provider)}</span></div>
        <div><span class="k">Status</span><span class="v">${s.configured
          ? '<span class="pill ok">✓ configured</span>'
          : '<span class="pill error">✕ not configured</span>'}</span></div>
        <div><span class="k">Daily report</span><span class="v">${s.dailyReport ? `every day at ${String(s.dailyReportHour).padStart(2, '0')}:00` : 'off'}</span></div>
        <div><span class="k">Re-notify after</span><span class="v">${t.cooldownMinutes} min</span></div>
      </div>
      ${s.configured ? '' : `<p class="hint">Set <code>WHATSAPP_PROVIDER</code> in <code>.env</code> and restart.
        Alerts are still recorded in the Alerts tab either way — only delivery is off.</p>`}
      <h4 style="margin:16px 0 8px;font-size:13px">Alert thresholds</h4>
      <div class="table-scroll"><table>
        <thead><tr><th>Condition</th><th>Fires when</th></tr></thead>
        <tbody>
          <tr><td>Host unreachable</td><td>2 consecutive failed SSH polls</td></tr>
          <tr><td>Disk full</td><td>≥ ${t.disk}% used</td></tr>
          <tr><td>Memory high</td><td>≥ ${t.memory}% used</td></tr>
          <tr><td>CPU pinned</td><td>≥ ${t.cpu}% for ${t.cpuSustainMinutes} min continuously</td></tr>
          <tr><td>Site down</td><td>unexpected status, keyword missing, or no response</td></tr>
          <tr><td>Site slow</td><td>response time &gt; ${t.latencyMs} ms</td></tr>
          <tr><td>TLS expiring</td><td>≤ ${t.tlsDays} days remaining</td></tr>
        </tbody>
      </table></div>
      <p class="hint" style="margin-top:12px">All thresholds are environment variables — see <code>.env.example</code>.</p>`;
  } catch (err) {
    target.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

el('notify-test').addEventListener('click', async (e) => {
  if (!confirm('Send a real WhatsApp message to your configured number now?')) return;
  e.target.disabled = true;
  e.target.textContent = 'Sending…';
  try {
    await api('/api/notify/test', { method: 'POST' });
    toast('Test message sent — check WhatsApp.', 'ok');
  } catch (err) {
    toast(`Failed: ${err.message}`, 'error');
  } finally {
    e.target.disabled = false;
    e.target.textContent = 'Send test message';
  }
});

el('report-preview').addEventListener('click', async () => {
  try {
    const { preview } = await api('/api/notify/report/preview');
    el('report-output').textContent = preview;
    el('report-modal').classList.remove('hidden');
  } catch (err) {
    toast(err.message, 'error');
  }
});

el('report-close').addEventListener('click', () => el('report-modal').classList.add('hidden'));

el('report-send').addEventListener('click', async (e) => {
  if (!confirm('Send this report to WhatsApp now?')) return;
  e.target.disabled = true;
  try {
    await api('/api/notify/report', { method: 'POST' });
    toast('Report sent.', 'ok');
    el('report-modal').classList.add('hidden');
  } catch (err) {
    toast(`Failed: ${err.message}`, 'error');
  } finally {
    e.target.disabled = false;
  }
});

// ----------------------------------------------------------- host detail ---

let terminal = null;
let terminalSocket = null;
let detailHostId = null;
let detailTab = 'overview';
const loaded = { services: false, k8s: false };

function closeTerminal() {
  if (terminalSocket) { terminalSocket.close(); terminalSocket = null; }
  if (terminal) { terminal.dispose(); terminal = null; }
}

function closeDetail() {
  closeTerminal();
  detailHostId = null;
  el('detail-modal').classList.add('hidden');
}

el('detail-close').addEventListener('click', closeDetail);
el('detail-modal').addEventListener('click', (e) => { if (e.target === el('detail-modal')) closeDetail(); });

// Escape closes the topmost layer only, so it never yanks the detail view out
// from under an open log or transcript window.
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  for (const id of ['log-modal', 'rec-modal', 'report-modal', 'check-modal', 'add-modal']) {
    if (!el(id).classList.contains('hidden')) { el(id).classList.add('hidden'); return; }
  }
  closeDetail();
});

function showDetailTab(tab) {
  detailTab = tab;
  document.querySelectorAll('#detail-tabs button')
    .forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === tab)));
  document.querySelectorAll('#detail-body > .pane')
    .forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== tab));

  if (tab === 'services' && !loaded.services) { loaded.services = true; loadServices(detailHostId); }
  if (tab === 'k8s' && !loaded.k8s) { loaded.k8s = true; loadK8s(detailHostId); }
}

document.querySelectorAll('#detail-tabs button').forEach((b) => {
  b.addEventListener('click', () => showDetailTab(b.dataset.tab));
});

async function openDetail(hostId) {
  detailHostId = hostId;
  loaded.services = false;
  loaded.k8s = false;
  const host = state.hosts.find((h) => h.id === hostId);
  el('detail-title').textContent = host.name;
  el('detail-status').innerHTML = statusMarkup(host);
  el('detail-modal').classList.remove('hidden');

  const isMaster = host.role === 'master';
  $('#detail-tabs [data-tab=k8s]').classList.toggle('hidden', !isMaster);

  el('detail-body').innerHTML = `
    <div class="pane" data-pane="overview">
      <div class="panel">
        <header><h3>Resource history</h3><div class="spacer"></div>
          <span style="font-size:12px;color:var(--muted)">${esc(host.username)}@${esc(host.hostname)}:${host.port}</span>
        </header>
        <p class="subtitle">CPU, memory and disk for the last hour.</p>
        <div class="chart-wrap"><svg id="detail-chart"></svg></div>
        <div class="legend" id="detail-legend"></div>
      </div>
      <div class="panel">
        <header><h3>Top processes</h3></header>
        <div class="table-scroll" id="proc-table"></div>
      </div>
    </div>

    <div class="pane hidden" data-pane="console">
      <div class="panel">
        <header><h3 id="term-heading">Console</h3><div class="spacer"></div>
          <button id="term-connect" class="primary">Open shell</button>
          <button id="term-disconnect" disabled>Disconnect</button>
        </header>
        <div class="term-bar" id="term-status">Not connected. Sessions are recorded and auditable.</div>
        <div id="terminal-host"></div>
      </div>
    </div>

    <div class="pane hidden" data-pane="services">
      <div class="panel">
        <header><h3>Services</h3><div class="spacer"></div>
          <input id="svc-search" placeholder="Filter units…" style="width:180px">
          <button id="svc-refresh">Refresh</button>
        </header>
        <div class="table-scroll" id="svc-table"><p class="hint">Loading…</p></div>
      </div>
    </div>

    <div class="pane hidden" data-pane="k8s">
      <div class="panel">
        <header><h3>Kubernetes</h3><div class="spacer"></div>
          <button id="k8s-reload">Refresh</button>
        </header>
        <div id="k8s-body"><p class="hint">Loading…</p></div>
      </div>
    </div>`;

  renderTopProcesses(host);
  loadDetailChart(hostId);
  showDetailTab('overview');

  el('term-connect').addEventListener('click', () => connectTerminal(hostId));
  el('term-disconnect').addEventListener('click', () => {
    closeTerminal();
    el('term-status').textContent = 'Disconnected.';
    el('term-connect').disabled = false;
    el('term-disconnect').disabled = true;
  });
  el('svc-refresh').addEventListener('click', () => loadServices(hostId));
  el('svc-search').addEventListener('input', renderServices);
  el('k8s-reload').addEventListener('click', () => loadK8s(hostId));
}

function renderTopProcesses(host) {
  const target = el('proc-table');
  if (!target) return;
  const top = (host.sample && host.sample.info && host.sample.info.top) || [];
  target.innerHTML = top.length ? `<table>
    <thead><tr><th>Command</th><th class="num">CPU</th><th class="num">Memory</th></tr></thead>
    <tbody>${top.map((p) => `<tr>
      <td class="mono">${esc(p.command)}</td>
      <td class="num">${p.cpu.toFixed(1)}%</td>
      <td class="num">${p.mem.toFixed(1)}%</td>
    </tr>`).join('')}</tbody></table>` : '<p class="hint">No sample yet.</p>';
}

async function loadDetailChart(hostId) {
  const rows = await api(`/api/hosts/${hostId}/metrics?minutes=60`);
  const series = [
    { name: 'CPU', color: cssVar('--series-1'), points: rows.map((r) => ({ ts: r.ts, v: r.cpu })) },
    { name: 'Memory', color: cssVar('--series-2'), points: rows.map((r) => ({ ts: r.ts, v: r.mem })) },
    { name: 'Disk', color: cssVar('--series-3'), points: rows.map((r) => ({ ts: r.ts, v: r.disk })) },
  ];
  drawLineChart(el('detail-chart'), series, { yMax: 100, height: 220 });
  el('detail-legend').innerHTML = series.map((s) => `
    <span class="item"><span class="key" style="background:${s.color}"></span>${s.name}</span>`).join('');
}

// -------------------------------------------------------------- services ---

let serviceRows = [];

/** systemd state -> a status pill plus a word. Never colour alone. */
function serviceStatus(s) {
  if (s.active === 'failed' || s.sub === 'failed') return { cls: 'error', icon: '✕', text: 'failed' };
  if (s.sub === 'running') return { cls: 'ok', icon: '●', text: 'running' };
  if (s.active === 'activating') return { cls: 'denied', icon: '◐', text: 'starting' };
  if (s.sub === 'exited') return { cls: 'idle', icon: '○', text: 'exited' };
  return { cls: 'idle', icon: '○', text: s.sub || s.active || 'stopped' };
}

function renderServices() {
  const target = el('svc-table');
  if (!target) return;
  const needle = (el('svc-search')?.value || '').trim().toLowerCase();
  const rows = needle
    ? serviceRows.filter((s) => `${s.unit} ${s.description}`.toLowerCase().includes(needle))
    : serviceRows;

  const running = serviceRows.filter((s) => s.sub === 'running').length;
  const failed = serviceRows.filter((s) => s.active === 'failed' || s.sub === 'failed').length;

  target.innerHTML = `
    <p class="hint" style="margin:0 0 10px">
      ${serviceRows.length} units — ${running} running, ${failed} failed${needle ? ` · showing ${rows.length}` : ''}.
    </p>
    <table>
      <thead><tr><th>Unit</th><th>Status</th><th>Description</th><th></th></tr></thead>
      <tbody>${rows.map((s) => {
        const st = serviceStatus(s);
        const isRunning = s.sub === 'running';
        return `<tr>
          <td class="mono">${esc(s.unit)}</td>
          <td><span class="pill ${st.cls}">${st.icon} ${esc(st.text)}</span></td>
          <td>${esc(s.description)}</td>
          <td style="text-align:right;white-space:nowrap">
            ${isRunning
              ? `<button data-svc="restart" data-unit="${esc(s.unit)}">Restart</button>
                 <button class="danger" data-svc="stop" data-unit="${esc(s.unit)}">Stop</button>`
              : `<button data-svc="start" data-unit="${esc(s.unit)}">Start</button>`}
          </td></tr>`;
      }).join('')}</tbody></table>`;

  target.querySelectorAll('[data-svc]').forEach((b) => {
    b.addEventListener('click', async () => {
      await runAction(detailHostId, `service.${b.dataset.svc}`, b.dataset.unit);
      loadServices(detailHostId);
    });
  });
}

async function loadServices(hostId) {
  const target = el('svc-table');
  target.innerHTML = '<p class="hint">Loading…</p>';
  try {
    serviceRows = await api(`/api/hosts/${hostId}/services`);
    renderServices();
  } catch (err) {
    target.innerHTML = `<p class="hint">Could not list services: ${esc(err.message)}</p>`;
  }
}

async function runAction(hostId, action, unit) {
  const host = state.hosts.find((h) => h.id === hostId);
  const what = unit ? `${action.split('.')[1]} ${unit}` : action;
  if (!confirm(`${what} on ${host.name} (${host.hostname})?\n\nThis is recorded in the audit trail.`)) return;
  try {
    const result = await api(`/api/hosts/${hostId}/action`, {
      method: 'POST', body: JSON.stringify({ action, unit }),
    });
    toast(`${what}: ${result.output || 'done'}`.slice(0, 160), result.ok ? 'ok' : 'error');
  } catch (err) {
    toast(`${what} failed: ${err.message}`, 'error');
  }
}

el('detail-reboot').addEventListener('click', () => detailHostId && runAction(detailHostId, 'reboot'));

// ------------------------------------------------------------ kubernetes ---

const k8sState = { namespace: 'default', tab: 'workloads' };

function podPill(pod) {
  if (pod.healthy) return `<span class="pill ok">● ${esc(pod.phase)}</span>`;
  if (/Succeeded|Completed/.test(pod.phase)) return `<span class="pill idle">○ ${esc(pod.phase)}</span>`;
  if (/Pending|ContainerCreating|Init/.test(pod.phase)) return `<span class="pill denied">◐ ${esc(pod.phase)}</span>`;
  return `<span class="pill error">✕ ${esc(pod.phase)}</span>`;
}

async function loadK8s(hostId) {
  const target = el('k8s-body');
  target.innerHTML = '<p class="hint">Talking to the cluster…</p>';
  try {
    const { nodes, namespaces } = await api(`/api/hosts/${hostId}/k8s`);
    if (!namespaces.includes(k8sState.namespace)) {
      k8sState.namespace = namespaces.includes('default') ? 'default' : (namespaces[0] || 'default');
    }

    target.innerHTML = `
      <h4 style="margin:0 0 8px;font-size:13px">Nodes</h4>
      <div class="table-scroll">
        <table>
          <thead><tr><th>Node</th><th>Status</th><th>Roles</th><th>Version</th><th>Age</th></tr></thead>
          <tbody>${nodes.map((n) => `<tr>
            <td class="mono">${esc(n.name)}</td>
            <td><span class="pill ${n.ready ? 'ok' : 'error'}">${n.ready ? '●' : '✕'} ${esc(n.status)}</span></td>
            <td>${esc(n.roles)}</td>
            <td class="mono">${esc(n.version)}</td>
            <td>${esc(n.age)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>

      <div style="display:flex;align-items:center;gap:10px;margin:18px 0 8px;flex-wrap:wrap">
        <nav class="tabs subtabs" id="k8s-tabs">
          <button data-k8stab="workloads" aria-selected="${k8sState.tab === 'workloads'}">Workloads</button>
          <button data-k8stab="events" aria-selected="${k8sState.tab === 'events'}">Events</button>
        </nav>
        <span class="spacer" style="flex:1"></span>
        <select id="k8s-ns" style="width:auto">
          <option value="*">All namespaces</option>
          ${namespaces.map((n) => `<option value="${esc(n)}"${n === k8sState.namespace ? ' selected' : ''}>${esc(n)}</option>`).join('')}
        </select>
      </div>
      <div id="k8s-content"><p class="hint">Loading…</p></div>`;

    el('k8s-ns').addEventListener('change', (e) => {
      k8sState.namespace = e.target.value;
      loadK8sContent(hostId);
    });
    target.querySelectorAll('[data-k8stab]').forEach((b) => {
      b.addEventListener('click', () => {
        k8sState.tab = b.dataset.k8stab;
        target.querySelectorAll('[data-k8stab]')
          .forEach((x) => x.setAttribute('aria-selected', String(x === b)));
        loadK8sContent(hostId);
      });
    });
    loadK8sContent(hostId);
  } catch (err) {
    target.innerHTML = `<p class="hint">${esc(err.message)}${
      /kubectl not found/.test(err.message) ? ' — this host does not look like a control-plane node.' : ''}</p>`;
  }
}

const loadK8sContent = (hostId) =>
  (k8sState.tab === 'events' ? loadEvents(hostId) : loadWorkloads(hostId));

async function loadWorkloads(hostId) {
  const target = el('k8s-content');
  if (!target) return;
  target.innerHTML = '<p class="hint">Loading…</p>';
  try {
    const { pods, deployments } = await api(
      `/api/hosts/${hostId}/k8s/workloads?ns=${encodeURIComponent(k8sState.namespace)}`);
    const showNs = k8sState.namespace === '*';

    target.innerHTML = `
      <div class="table-scroll" style="margin-bottom:18px">
        <table>
          <thead><tr>
            <th>Deployment</th>${showNs ? '<th>Namespace</th>' : ''}
            <th>Ready</th><th class="num">Up-to-date</th><th class="num">Available</th><th>Age</th><th>Replicas</th><th></th>
          </tr></thead>
          <tbody>${deployments.length ? deployments.map((d) => `<tr>
            <td class="mono">${esc(d.name)}</td>
            ${showNs ? `<td>${esc(d.namespace)}</td>` : ''}
            <td><span class="pill ${d.healthy ? 'ok' : 'denied'}">${d.healthy ? '●' : '◐'} ${esc(d.ready)}</span></td>
            <td class="num">${d.upToDate}</td>
            <td class="num">${d.available}</td>
            <td>${esc(d.age)}</td>
            <td style="white-space:nowrap">
              <button class="tiny" data-scale="down" data-name="${esc(d.name)}" data-ns="${esc(d.namespace)}"
                      data-current="${d.ready.split('/')[1]}">−</button>
              <span style="padding:0 6px;font-variant-numeric:tabular-nums">${esc(d.ready.split('/')[1])}</span>
              <button class="tiny" data-scale="up" data-name="${esc(d.name)}" data-ns="${esc(d.namespace)}"
                      data-current="${d.ready.split('/')[1]}">+</button>
            </td>
            <td style="text-align:right"><button data-restart="${esc(d.name)}" data-ns="${esc(d.namespace)}">Restart</button></td>
          </tr>`).join('') : `<tr><td colspan="${showNs ? 8 : 7}" style="color:var(--muted)">No deployments.</td></tr>`}</tbody>
        </table>
      </div>

      <div class="table-scroll">
        <table>
          <thead><tr>
            <th>Pod</th>${showNs ? '<th>Namespace</th>' : ''}
            <th>Status</th><th>Ready</th><th class="num">Restarts</th>
            <th>Containers</th><th>Node</th><th>Age</th><th></th>
          </tr></thead>
          <tbody>${pods.length ? pods.map((p) => `<tr>
            <td class="mono">${esc(p.name)}</td>
            ${showNs ? `<td>${esc(p.namespace)}</td>` : ''}
            <td>${podPill(p)}</td>
            <td>${esc(p.ready)}</td>
            <td class="num"${p.restarts > 0 ? ' style="color:var(--serious);font-weight:600"' : ''}>${p.restarts}</td>
            <td class="mono" style="font-size:11px">${p.containers.map(esc).join(', ')}</td>
            <td class="mono" style="font-size:11px">${esc(p.node)}</td>
            <td>${esc(p.age)}</td>
            <td style="text-align:right;white-space:nowrap">
              <button data-logs="${esc(p.name)}" data-ns="${esc(p.namespace)}"
                      data-containers="${esc(p.containers.join(','))}">Logs</button>
              <button data-exec="${esc(p.name)}" data-ns="${esc(p.namespace)}"
                      data-container="${esc(p.containers[0] || '')}">Shell</button>
            </td>
          </tr>`).join('') : `<tr><td colspan="${showNs ? 9 : 8}" style="color:var(--muted)">No pods.</td></tr>`}</tbody>
        </table>
      </div>`;

    target.querySelectorAll('[data-logs]').forEach((b) => {
      b.addEventListener('click', () => openLogs(hostId, b.dataset.ns, b.dataset.logs,
        b.dataset.containers ? b.dataset.containers.split(',') : []));
    });
    target.querySelectorAll('[data-exec]').forEach((b) => {
      b.addEventListener('click', () => openExec(hostId, b.dataset.ns, b.dataset.exec, b.dataset.container));
    });
    target.querySelectorAll('[data-restart]').forEach((b) => {
      b.addEventListener('click', () => deploymentAction(hostId, 'restart', b.dataset.ns, b.dataset.restart));
    });
    target.querySelectorAll('[data-scale]').forEach((b) => {
      b.addEventListener('click', () => {
        const current = Number(b.dataset.current) || 0;
        const next = b.dataset.scale === 'up' ? current + 1 : Math.max(0, current - 1);
        if (next === current) return;
        deploymentAction(hostId, 'scale', b.dataset.ns, b.dataset.name, next);
      });
    });
  } catch (err) {
    target.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

async function deploymentAction(hostId, action, namespace, name, replicas) {
  const what = action === 'scale' ? `scale ${name} to ${replicas} replica(s)` : `restart ${name}`;
  if (!confirm(`${what} in namespace ${namespace}?\n\nThis is recorded in the audit trail.`)) return;
  try {
    const r = await api(`/api/hosts/${hostId}/k8s/deployment`, {
      method: 'POST',
      body: JSON.stringify({ action, name, namespace, replicas }),
    });
    toast(r.output || `${what} done`, 'ok');
    setTimeout(() => loadWorkloads(hostId), 1200);
  } catch (err) {
    toast(`${what} failed: ${err.message}`, 'error');
  }
}

async function loadEvents(hostId) {
  const target = el('k8s-content');
  if (!target) return;
  target.innerHTML = '<p class="hint">Loading…</p>';
  try {
    const events = await api(`/api/hosts/${hostId}/k8s/events?ns=${encodeURIComponent(k8sState.namespace)}`);
    target.innerHTML = events.length ? `<div class="table-scroll"><table>
      <thead><tr><th>Age</th><th>Type</th><th>Reason</th><th>Object</th><th class="num">Count</th><th>Message</th></tr></thead>
      <tbody>${events.map((e) => `<tr>
        <td>${esc(e.age)}</td>
        <td><span class="pill ${e.type === 'Warning' ? 'error' : 'idle'}">${e.type === 'Warning' ? '⚠' : '○'} ${esc(e.type)}</span></td>
        <td class="mono">${esc(e.reason)}</td>
        <td class="mono" style="font-size:11px">${esc(e.object)}</td>
        <td class="num">${e.count}</td>
        <td style="max-width:420px">${esc(e.message)}</td>
      </tr>`).join('')}</tbody></table></div>`
      : '<p class="hint">No events in this namespace.</p>';
  } catch (err) {
    target.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
  }
}

// ------------------------------------------------------------- pod logs ---

let logContext = null;

function openLogs(hostId, ns, pod, containers) {
  logContext = { hostId, ns, pod, containers };
  el('log-title').textContent = `${ns}/${pod}`;
  el('log-container').innerHTML = containers.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
  el('log-container').classList.toggle('hidden', containers.length < 2);
  el('log-modal').classList.remove('hidden');
  fetchLogs();
}

async function fetchLogs() {
  if (!logContext) return;
  const output = el('log-output');
  output.textContent = 'Fetching…';
  const container = el('log-container').value || logContext.containers[0] || '';
  const tail = el('log-tail').value;
  try {
    const { logs } = await api(`/api/hosts/${logContext.hostId}/k8s/logs`
      + `?ns=${encodeURIComponent(logContext.ns)}&pod=${encodeURIComponent(logContext.pod)}`
      + `&container=${encodeURIComponent(container)}&tail=${tail}`);
    output.textContent = logs || '(no output — the container has logged nothing)';
    output.scrollTop = output.scrollHeight;
  } catch (err) {
    output.textContent = err.message;
  }
}

el('log-close').addEventListener('click', () => { el('log-modal').classList.add('hidden'); logContext = null; });
el('log-refresh').addEventListener('click', fetchLogs);
el('log-container').addEventListener('change', fetchLogs);
el('log-tail').addEventListener('change', fetchLogs);
el('log-modal').addEventListener('click', (e) => {
  if (e.target === el('log-modal')) { el('log-modal').classList.add('hidden'); logContext = null; }
});

// -------------------------------------------------------------- terminal ---

/** Same terminal component, pointed at `kubectl exec` instead of a login shell. */
function openExec(hostId, ns, pod, container) {
  showDetailTab('console');
  el('term-heading').textContent = `Pod shell — ${ns}/${pod}`;
  connectTerminal(hostId, { ns, pod, container });
}

function connectTerminal(hostId, exec) {
  closeTerminal();
  const TerminalCtor = window.Terminal;
  const FitCtor = (window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon)) || null;
  if (!TerminalCtor) { toast('Terminal library failed to load.', 'error'); return; }

  el('term-connect').disabled = true;
  el('term-status').textContent = 'Connecting…';

  terminal = new TerminalCtor({
    fontFamily: 'ui-monospace, Menlo, Consolas, monospace',
    fontSize: 13,
    cursorBlink: true,
    theme: { background: '#0d0d0d', foreground: '#e6e5df' },
  });
  const fit = FitCtor ? new FitCtor() : null;
  if (fit) terminal.loadAddon(fit);
  terminal.open(el('terminal-host'));
  if (fit) fit.fit();

  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const params = new URLSearchParams({ host: String(hostId) });
  if (exec) {
    params.set('pod', exec.pod);
    params.set('ns', exec.ns);
    if (exec.container) params.set('container', exec.container);
  }
  const socket = new WebSocket(`${scheme}://${location.host}/ws/terminal?${params}`);
  terminalSocket = socket;

  socket.addEventListener('open', () => {
    el('term-status').textContent = 'Connected — this session is being recorded.';
    el('term-disconnect').disabled = false;
    socket.send(JSON.stringify({ t: 'r', cols: terminal.cols, rows: terminal.rows }));
  });
  socket.addEventListener('message', (event) => terminal.write(event.data));
  socket.addEventListener('close', () => {
    el('term-status').textContent = 'Session closed.';
    el('term-connect').disabled = false;
    el('term-disconnect').disabled = true;
  });
  socket.addEventListener('error', () => {
    el('term-status').textContent = 'Connection error.';
    el('term-connect').disabled = false;
  });

  terminal.onData((data) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ t: 'd', d: data }));
  });

  const onResize = () => {
    if (!fit || !terminal) return;
    fit.fit();
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ t: 'r', cols: terminal.cols, rows: terminal.rows }));
    }
  };
  window.addEventListener('resize', onResize);
  socket.addEventListener('close', () => window.removeEventListener('resize', onResize));
}

// --------------------------------------------------------------- refresh ---

async function refresh() {
  state.hosts = await api('/api/hosts');
  reconcileSlots(state.hosts);

  const histories = await Promise.all(state.hosts.map((h) =>
    api(`/api/hosts/${h.id}/metrics?minutes=${state.fleetMinutes}`).catch(() => [])));
  state.history = {};
  state.hosts.forEach((h, i) => { state.history[h.id] = histories[i]; });

  const filter = el('audit-filter');
  const keep = filter.value;
  filter.innerHTML = '<option value="">All hosts</option>' +
    state.hosts.map((h) => `<option value="${h.id}">${esc(h.name)}</option>`).join('');
  filter.value = keep;

  // Keep the alert badge live regardless of which tab is showing.
  try {
    const alerts = await api('/api/alerts?limit=200');
    const open = alerts.filter((a) => !a.resolved_at).length;
    const badge = el('alert-badge');
    badge.textContent = open;
    badge.classList.toggle('hidden', open === 0);
  } catch { /* non-fatal */ }

  render();
}

function render() {
  renderHostCards();
  renderFleetChart();
  if (state.view === 'hosts') renderHostsTable();
  if (detailHostId) {
    const host = state.hosts.find((h) => h.id === detailHostId);
    if (host) {
      el('detail-status').innerHTML = statusMarkup(host);
      renderTopProcesses(host);
    }
  }
}

let resizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(render, 150);
});

// ------------------------------------------------------------------ boot ---

async function boot() {
  const me = await api('/api/me');
  showApp(me);
  await refresh();
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => refresh().catch(() => {}), 15000);
}

boot().catch(() => showLogin());
