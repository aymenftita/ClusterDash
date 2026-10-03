'use strict';
/**
 * ClusterDash — agentless SSH dashboard for a small VPS fleet.
 *
 * Everything lives here: auth, encrypted host store, SQLite persistence,
 * the SSH connection pool, the metrics poller, the audit trail, the REST API
 * and the websocket terminal bridge.
 */

const path = require('path');
const fs = require('fs');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const express = require('express');
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const Database = require('better-sqlite3');

// ---------------------------------------------------------------- config ---

const PORT = Number(process.env.PORT || 8080);
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const MASTER_KEY = process.env.MASTER_KEY || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const POLL_MS = Number(process.env.POLL_INTERVAL_SECONDS || 15) * 1000;
const RETENTION_HOURS = Number(process.env.RETENTION_HOURS || 48);
const SECURE_COOKIES = process.env.SECURE_COOKIES === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// --- notifications -------------------------------------------------------
const WHATSAPP_PROVIDER = (process.env.WHATSAPP_PROVIDER || 'none').toLowerCase();
const CALLMEBOT_PHONE = process.env.CALLMEBOT_PHONE || '';
const CALLMEBOT_APIKEY = process.env.CALLMEBOT_APIKEY || '';
const META_PHONE_NUMBER_ID = process.env.META_PHONE_NUMBER_ID || '';
const META_ACCESS_TOKEN = process.env.META_ACCESS_TOKEN || '';
const META_RECIPIENT = process.env.META_RECIPIENT || '';
const META_TEMPLATE_NAME = process.env.META_TEMPLATE_NAME || '';
const ALERT_WEBHOOK_URL = process.env.ALERT_WEBHOOK_URL || '';

// --- alert thresholds ----------------------------------------------------
const ALERT_DISK_PCT = Number(process.env.ALERT_DISK_PCT || 85);
const ALERT_MEM_PCT = Number(process.env.ALERT_MEM_PCT || 90);
const ALERT_CPU_PCT = Number(process.env.ALERT_CPU_PCT || 95);
const ALERT_CPU_SUSTAIN_MIN = Number(process.env.ALERT_CPU_SUSTAIN_MINUTES || 10);
const ALERT_DOWN_POLLS = Number(process.env.ALERT_DOWN_POLLS || 2);
const ALERT_COOLDOWN_MS = Number(process.env.ALERT_COOLDOWN_MINUTES || 60) * 60 * 1000;
const ALERT_LATENCY_MS = Number(process.env.ALERT_LATENCY_MS || 3000);
const ALERT_TLS_DAYS = Number(process.env.ALERT_TLS_DAYS || 14);

// --- scheduled report ----------------------------------------------------
const DAILY_REPORT_HOUR = Number(process.env.DAILY_REPORT_HOUR ?? 8);
const DAILY_REPORT_ENABLED = process.env.DAILY_REPORT_ENABLED !== '0';

// --- http monitors -------------------------------------------------------
const CHECK_INTERVAL_MS = Number(process.env.CHECK_INTERVAL_SECONDS || 60) * 1000;

// --- console recording ---------------------------------------------------
const RECORD_CONSOLE = process.env.RECORD_CONSOLE !== '0';
const RECORD_RETENTION_DAYS = Number(process.env.RECORD_RETENTION_DAYS || 30);

for (const [name, value] of [['ADMIN_PASSWORD', ADMIN_PASSWORD], ['MASTER_KEY', MASTER_KEY]]) {
  if (!value || value.startsWith('change-me')) {
    console.error(`[fatal] ${name} is not set (or still the example value). See .env.example.`);
    process.exit(1);
  }
}
fs.mkdirSync(DATA_DIR, { recursive: true });
const RECORD_DIR = path.join(DATA_DIR, 'console');
fs.mkdirSync(RECORD_DIR, { recursive: true });

// ---------------------------------------------------------------- crypto ---

const KEY = crypto.scryptSync(MASTER_KEY, 'clusterdash.secretbox.v1', 32);

function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64');
}

function decrypt(blob) {
  const raw = Buffer.from(blob, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

function passwordMatches(attempt) {
  const a = crypto.scryptSync(String(attempt), 'clusterdash.auth.v1', 32);
  const b = crypto.scryptSync(ADMIN_PASSWORD, 'clusterdash.auth.v1', 32);
  return crypto.timingSafeEqual(a, b);
}

// -------------------------------------------------------------- database ---

const db = new Database(path.join(DATA_DIR, 'clusterdash.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS hosts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  hostname   TEXT NOT NULL,
  port       INTEGER NOT NULL DEFAULT 22,
  username   TEXT NOT NULL DEFAULT 'root',
  secret     TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'standalone',
  provider   TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS metrics (
  host_id INTEGER NOT NULL,
  ts      INTEGER NOT NULL,
  cpu     REAL, mem REAL, disk REAL, swap REAL,
  load1   REAL, rx REAL, tx REAL,
  uptime  REAL, procs INTEGER
);
CREATE INDEX IF NOT EXISTS metrics_host_ts ON metrics (host_id, ts);
CREATE TABLE IF NOT EXISTS audit (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  actor     TEXT NOT NULL,
  ip        TEXT NOT NULL DEFAULT '',
  action    TEXT NOT NULL,
  host_id   INTEGER,
  host_name TEXT NOT NULL DEFAULT '',
  detail    TEXT NOT NULL DEFAULT '',
  result    TEXT NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts DESC);
CREATE TABLE IF NOT EXISTS sessions (
  token   TEXT PRIMARY KEY,
  actor   TEXT NOT NULL,
  expires INTEGER NOT NULL
);

-- HTTP monitors: "is the site up", as opposed to "is the server up".
CREATE TABLE IF NOT EXISTS checks (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  url           TEXT NOT NULL,
  expect_status INTEGER NOT NULL DEFAULT 200,
  keyword       TEXT NOT NULL DEFAULT '',
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS check_results (
  check_id INTEGER NOT NULL,
  ts       INTEGER NOT NULL,
  ok       INTEGER NOT NULL,
  status   INTEGER,
  ms       REAL,
  error    TEXT NOT NULL DEFAULT '',
  tls_days INTEGER
);
CREATE INDEX IF NOT EXISTS check_results_ts ON check_results (check_id, ts);

-- One row per alert condition, opened when it trips and closed when it clears.
CREATE TABLE IF NOT EXISTS alerts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key         TEXT NOT NULL,
  severity    TEXT NOT NULL,
  subject     TEXT NOT NULL,
  message     TEXT NOT NULL,
  opened_at   INTEGER NOT NULL,
  resolved_at INTEGER,
  notified_at INTEGER,
  value       REAL
);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts (key, resolved_at);
CREATE INDEX IF NOT EXISTS alerts_opened ON alerts (opened_at DESC);

-- Console recordings: metadata here, the transcript itself on disk.
CREATE TABLE IF NOT EXISTS console_sessions (
  id        TEXT PRIMARY KEY,
  host_id   INTEGER,
  host_name TEXT NOT NULL DEFAULT '',
  actor     TEXT NOT NULL,
  kind      TEXT NOT NULL DEFAULT 'ssh',
  started   INTEGER NOT NULL,
  ended     INTEGER,
  bytes     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS console_started ON console_sessions (started DESC);
`);

const q = {
  allHosts: db.prepare('SELECT * FROM hosts ORDER BY role DESC, name'),
  host: db.prepare('SELECT * FROM hosts WHERE id = ?'),
  insertHost: db.prepare(`INSERT INTO hosts (name, hostname, port, username, secret, role, provider, created_at)
                          VALUES (@name, @hostname, @port, @username, @secret, @role, @provider, @created_at)`),
  deleteHost: db.prepare('DELETE FROM hosts WHERE id = ?'),
  insertMetric: db.prepare(`INSERT INTO metrics (host_id, ts, cpu, mem, disk, swap, load1, rx, tx, uptime, procs)
                            VALUES (@host_id, @ts, @cpu, @mem, @disk, @swap, @load1, @rx, @tx, @uptime, @procs)`),
  metricsSince: db.prepare('SELECT * FROM metrics WHERE host_id = ? AND ts >= ? ORDER BY ts'),
  pruneMetrics: db.prepare('DELETE FROM metrics WHERE ts < ?'),
  insertAudit: db.prepare(`INSERT INTO audit (ts, actor, ip, action, host_id, host_name, detail, result)
                           VALUES (@ts, @actor, @ip, @action, @host_id, @host_name, @detail, @result)`),
  openAlert: db.prepare('SELECT * FROM alerts WHERE key = ? AND resolved_at IS NULL'),
  insertAlert: db.prepare(`INSERT INTO alerts (key, severity, subject, message, opened_at, notified_at, value)
                           VALUES (@key, @severity, @subject, @message, @opened_at, @notified_at, @value)`),
  touchAlert: db.prepare('UPDATE alerts SET notified_at = ?, value = ?, message = ? WHERE id = ?'),
  resolveAlert: db.prepare('UPDATE alerts SET resolved_at = ? WHERE id = ?'),
  alertsSince: db.prepare('SELECT * FROM alerts WHERE opened_at >= ? ORDER BY opened_at DESC'),
  recentAlerts: db.prepare('SELECT * FROM alerts ORDER BY opened_at DESC LIMIT ?'),

  allChecks: db.prepare('SELECT * FROM checks ORDER BY name'),
  check: db.prepare('SELECT * FROM checks WHERE id = ?'),
  insertCheck: db.prepare(`INSERT INTO checks (name, url, expect_status, keyword, enabled, created_at)
                           VALUES (@name, @url, @expect_status, @keyword, 1, @created_at)`),
  deleteCheck: db.prepare('DELETE FROM checks WHERE id = ?'),
  toggleCheck: db.prepare('UPDATE checks SET enabled = ? WHERE id = ?'),
  insertCheckResult: db.prepare(`INSERT INTO check_results (check_id, ts, ok, status, ms, error, tls_days)
                                 VALUES (@check_id, @ts, @ok, @status, @ms, @error, @tls_days)`),
  checkResultsSince: db.prepare('SELECT * FROM check_results WHERE check_id = ? AND ts >= ? ORDER BY ts'),
  pruneCheckResults: db.prepare('DELETE FROM check_results WHERE ts < ?'),

  insertConsole: db.prepare(`INSERT INTO console_sessions (id, host_id, host_name, actor, kind, started)
                             VALUES (@id, @host_id, @host_name, @actor, @kind, @started)`),
  endConsole: db.prepare('UPDATE console_sessions SET ended = ?, bytes = ? WHERE id = ?'),
  consoleSessions: db.prepare('SELECT * FROM console_sessions ORDER BY started DESC LIMIT ?'),
  consoleSession: db.prepare('SELECT * FROM console_sessions WHERE id = ?'),
  pruneConsole: db.prepare('DELETE FROM console_sessions WHERE started < ?'),

  session: db.prepare('SELECT * FROM sessions WHERE token = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token, actor, expires) VALUES (?, ?, ?)'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  pruneSessions: db.prepare('DELETE FROM sessions WHERE expires < ?'),
};

function audit(entry) {
  q.insertAudit.run({
    ts: Date.now(), actor: 'system', ip: '', host_id: null,
    host_name: '', detail: '', result: 'ok', ...entry,
  });
}

// ---------------------------------------------------- whatsapp notifier ---

/**
 * One interface, three transports. The alert engine never knows which is in use.
 *
 *  callmebot — free, personal use, plain GET. Simplest to set up.
 *  meta      — official WhatsApp Cloud API. Free-form text only reaches you
 *              inside a 24 h window opened by YOUR message to the number;
 *              outside it Meta requires a pre-approved template, which is why
 *              META_TEMPLATE_NAME exists.
 *  webhook   — POST {text} anywhere (n8n, Slack, Discord, your own relay).
 */
async function deliver(text) {
  const timeout = AbortSignal.timeout(15000);

  if (WHATSAPP_PROVIDER === 'callmebot') {
    if (!CALLMEBOT_PHONE || !CALLMEBOT_APIKEY) throw new Error('CALLMEBOT_PHONE / CALLMEBOT_APIKEY not set');
    const url = 'https://api.callmebot.com/whatsapp.php'
      + `?phone=${encodeURIComponent(CALLMEBOT_PHONE)}`
      + `&text=${encodeURIComponent(text)}`
      + `&apikey=${encodeURIComponent(CALLMEBOT_APIKEY)}`;
    const res = await fetch(url, { signal: timeout });
    const body = await res.text();
    if (!res.ok) throw new Error(`CallMeBot ${res.status}: ${body.slice(0, 200)}`);
    return body.slice(0, 200);
  }

  if (WHATSAPP_PROVIDER === 'meta') {
    if (!META_PHONE_NUMBER_ID || !META_ACCESS_TOKEN || !META_RECIPIENT) {
      throw new Error('META_PHONE_NUMBER_ID / META_ACCESS_TOKEN / META_RECIPIENT not set');
    }
    const payload = META_TEMPLATE_NAME
      ? { messaging_product: 'whatsapp', to: META_RECIPIENT, type: 'template',
          template: { name: META_TEMPLATE_NAME, language: { code: 'en' },
            components: [{ type: 'body', parameters: [{ type: 'text', text: text.slice(0, 1024) }] }] } }
      : { messaging_product: 'whatsapp', to: META_RECIPIENT, type: 'text',
          text: { preview_url: false, body: text.slice(0, 4096) } };
    const res = await fetch(`https://graph.facebook.com/v21.0/${META_PHONE_NUMBER_ID}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${META_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: timeout,
    });
    const body = await res.text();
    if (!res.ok) throw new Error(`Meta ${res.status}: ${body.slice(0, 300)}`);
    return body.slice(0, 200);
  }

  if (WHATSAPP_PROVIDER === 'webhook') {
    if (!ALERT_WEBHOOK_URL) throw new Error('ALERT_WEBHOOK_URL not set');
    const res = await fetch(ALERT_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, content: text }),  // `content` keeps Discord happy
      signal: timeout,
    });
    if (!res.ok) throw new Error(`Webhook ${res.status}`);
    return 'sent';
  }

  const err = new Error('no WhatsApp provider configured (set WHATSAPP_PROVIDER)');
  err.kind = 'unconfigured';
  throw err;
}

// Serialised so a burst of alerts cannot fire concurrent requests at the API.
let sendQueue = Promise.resolve();

function notify(text, context = 'alert') {
  sendQueue = sendQueue.then(async () => {
    try {
      await deliver(text);
      audit({ action: 'notify.sent', detail: `${context}: ${text.split('\n')[0]}`.slice(0, 300) });
    } catch (err) {
      if (err.kind === 'unconfigured') return;   // silent when the user has not set it up
      audit({ action: 'notify.failed', result: 'error',
              detail: `${context}: ${String(err.message || err)}`.slice(0, 300) });
    }
  }).catch(() => {});
  return sendQueue;
}

const notifierConfigured = () => WHATSAPP_PROVIDER !== 'none' && WHATSAPP_PROVIDER !== '';

// ------------------------------------------------------------ ssh layer ---

/** hostId -> Promise<Client>.  A rejected/closed entry is evicted so the next call redials. */
const pool = new Map();

function dial(row) {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    const fail = (err) => {
      pool.delete(row.id);
      if (!settled) { settled = true; reject(err); }
    };
    client.on('ready', () => { if (!settled) { settled = true; resolve(client); } });
    client.on('error', fail);
    client.on('close', () => { pool.delete(row.id); });
    client.connect({
      host: row.hostname,
      port: row.port,
      username: row.username,
      password: decrypt(row.secret),
      readyTimeout: 15000,
      keepaliveInterval: 20000,
      keepaliveCountMax: 3,
    });
  });
}

function getConnection(row) {
  let pending = pool.get(row.id);
  if (!pending) {
    pending = dial(row);
    pool.set(row.id, pending);
  }
  return pending;
}

function dropConnection(id) {
  const pending = pool.get(id);
  pool.delete(id);
  if (pending) Promise.resolve(pending).then((c) => c.end()).catch(() => {});
}

async function sshExec(row, command, timeoutMs = 20000) {
  const client = await getConnection(row);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('command timed out')), timeoutMs);
    client.exec(command, (err, stream) => {
      if (err) { clearTimeout(timer); return reject(err); }
      let stdout = '';
      let stderr = '';
      stream.on('data', (d) => { stdout += d; });
      stream.stderr.on('data', (d) => { stderr += d; });
      stream.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
    });
  });
}

// --------------------------------------------------------- metrics probe ---

// One round trip per poll. `@@` markers delimit sections; nothing in the output
// of these commands legitimately starts with `@@`.
const PROBE = [
  'echo "@@os"; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"',
  'echo "@@kernel"; uname -r',
  'echo "@@hostname"; hostname',
  'echo "@@uptime"; cut -d" " -f1 /proc/uptime',
  'echo "@@load"; cat /proc/loadavg',
  'echo "@@cpu"; head -n1 /proc/stat',
  'echo "@@ncpu"; grep -c ^processor /proc/cpuinfo',
  'echo "@@mem"; grep -E "^(MemTotal|MemAvailable|SwapTotal|SwapFree):" /proc/meminfo',
  'echo "@@disk"; df -PB1 / | tail -n1',
  'echo "@@net"; grep -E "^[ ]*(eth|ens|enp|eno|venet|wlp)[^:]*:" /proc/net/dev',
  'echo "@@procs"; ps -e --no-headers 2>/dev/null | wc -l',
  'echo "@@top"; ps -eo pcpu,pmem,comm --no-headers --sort=-pcpu 2>/dev/null | head -n5',
].join('; ');

function splitSections(text) {
  const out = {};
  let current = null;
  for (const line of text.split('\n')) {
    if (line.startsWith('@@')) { current = line.slice(2).trim(); out[current] = []; continue; }
    if (current) out[current].push(line);
  }
  return out;
}

const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

/** hostId -> previous counters, needed to turn cumulative jiffies/bytes into rates. */
const previous = new Map();
/** hostId -> last known live state (not persisted; rebuilt on each poll). */
const live = new Map();

function parseProbe(hostId, stdout) {
  const s = splitSections(stdout);
  const first = (k) => (s[k] && s[k][0] ? s[k][0].trim() : '');

  // CPU: percentage busy since the previous sample.
  const cpuFields = first('cpu').split(/\s+/).slice(1).map(num);
  const cpuTotal = cpuFields.reduce((a, b) => a + b, 0);
  const cpuIdle = (cpuFields[3] || 0) + (cpuFields[4] || 0);

  // Network: bytes/s since the previous sample, summed over physical interfaces.
  let rxBytes = 0;
  let txBytes = 0;
  for (const line of s.net || []) {
    const cols = line.split(':')[1];
    if (!cols) continue;
    const f = cols.trim().split(/\s+/).map(num);
    rxBytes += f[0] || 0;
    txBytes += f[8] || 0;
  }

  const now = Date.now();
  const prev = previous.get(hostId);
  previous.set(hostId, { cpuTotal, cpuIdle, rxBytes, txBytes, at: now });

  let cpu = 0;
  let rx = 0;
  let tx = 0;
  if (prev) {
    const dTotal = cpuTotal - prev.cpuTotal;
    const dIdle = cpuIdle - prev.cpuIdle;
    if (dTotal > 0) cpu = Math.min(100, Math.max(0, (1 - dIdle / dTotal) * 100));
    const dt = (now - prev.at) / 1000;
    if (dt > 0) {
      rx = Math.max(0, (rxBytes - prev.rxBytes) / dt);
      tx = Math.max(0, (txBytes - prev.txBytes) / dt);
    }
  }

  // /proc/meminfo values carry a " kB" suffix — take the leading number only.
  const mem = {};
  for (const line of s.mem || []) {
    const [k, v] = line.split(':');
    if (k && v) mem[k.trim()] = num(v.trim().split(/\s+/)[0]);
  }
  const memTotal = mem.MemTotal || 0;
  const memUsedPct = memTotal ? ((memTotal - (mem.MemAvailable || 0)) / memTotal) * 100 : 0;
  const swapTotal = mem.SwapTotal || 0;
  const swapUsedPct = swapTotal ? ((swapTotal - (mem.SwapFree || 0)) / swapTotal) * 100 : 0;

  const diskCols = first('disk').split(/\s+/);
  const diskTotal = num(diskCols[1]);
  const diskUsed = num(diskCols[2]);
  const diskPct = diskTotal ? (diskUsed / diskTotal) * 100 : 0;

  return {
    ts: now,
    cpu, mem: memUsedPct, disk: diskPct, swap: swapUsedPct,
    load1: num(first('load').split(/\s+/)[0]),
    rx, tx,
    uptime: num(first('uptime')),
    procs: Math.round(num(first('procs'))),
    info: {
      os: first('os') || 'unknown',
      kernel: first('kernel'),
      hostname: first('hostname'),
      ncpu: Math.round(num(first('ncpu'))) || 1,
      memTotalBytes: memTotal * 1024,
      diskTotalBytes: diskTotal,
      diskUsedBytes: diskUsed,
      top: (s.top || []).filter(Boolean).map((l) => {
        const [cpuPct, memPct, ...rest] = l.trim().split(/\s+/);
        return { cpu: num(cpuPct), mem: num(memPct), command: rest.join(' ') };
      }),
    },
  };
}

async function pollHost(row) {
  try {
    const { stdout } = await sshExec(row, PROBE, 25000);
    const sample = parseProbe(row.id, stdout);
    q.insertMetric.run({
      host_id: row.id, ts: sample.ts,
      cpu: sample.cpu, mem: sample.mem, disk: sample.disk, swap: sample.swap,
      load1: sample.load1, rx: sample.rx, tx: sample.tx,
      uptime: sample.uptime, procs: sample.procs,
    });
    const before = live.get(row.id);
    live.set(row.id, { online: true, at: sample.ts, error: null, sample });
    if (before && before.online === false) {
      audit({ action: 'host.recovered', host_id: row.id, host_name: row.name, detail: 'SSH reachable again' });
    }
  } catch (err) {
    const before = live.get(row.id);
    dropConnection(row.id);
    previous.delete(row.id);
    live.set(row.id, { online: false, at: Date.now(), error: String(err.message || err), sample: before && before.sample });
    if (!before || before.online !== false) {
      audit({ action: 'host.unreachable', host_id: row.id, host_name: row.name,
              detail: String(err.message || err), result: 'error' });
    }
  }
}

// ----------------------------------------------------------- alert engine ---

const SEVERITY_ICON = { critical: '🔴', warning: '🟠', good: '🟢' };

/**
 * Open an alert if it is not already open, and notify — but at most once per
 * cooldown window, so a disk sitting at 91% for a week does not message you
 * every 15 seconds. Re-notifying a still-open alert is deliberate: it is a
 * reminder, not a new incident.
 */
function raise({ key, severity, subject, message, value }) {
  const now = Date.now();
  const open = q.openAlert.get(key);
  if (open) {
    if (now - (open.notified_at || 0) < ALERT_COOLDOWN_MS) return;
    q.touchAlert.run(now, value ?? null, message, open.id);
    notify(`${SEVERITY_ICON[severity] || '⚠️'} *${subject}* (still active)\n${message}`, key);
    return;
  }
  q.insertAlert.run({ key, severity, subject, message, opened_at: now, notified_at: now, value: value ?? null });
  audit({ action: 'alert.raised', detail: `${subject} — ${message}`.slice(0, 400), result: 'error' });
  notify(`${SEVERITY_ICON[severity] || '⚠️'} *${subject}*\n${message}`, key);
}

/** Close an open alert and say so. Silent if nothing was open. */
function clear(key, subject, message) {
  const open = q.openAlert.get(key);
  if (!open) return;
  const now = Date.now();
  q.resolveAlert.run(now, open.id);
  const mins = Math.max(1, Math.round((now - open.opened_at) / 60000));
  audit({ action: 'alert.resolved', detail: `${subject} after ${mins}m` });
  notify(`🟢 *Resolved: ${subject}*\n${message}\nWas active for ${mins} min.`, `${key}.resolved`);
}

/** hostId -> consecutive failed polls, so one blip does not page you. */
const downStreak = new Map();

function evaluateHostAlerts(row, state) {
  const name = row.name;

  if (!state.online) {
    const streak = (downStreak.get(row.id) || 0) + 1;
    downStreak.set(row.id, streak);
    if (streak >= ALERT_DOWN_POLLS) {
      raise({
        key: `host.down.${row.id}`, severity: 'critical',
        subject: `${name} unreachable`,
        message: `${row.username}@${row.hostname} has failed ${streak} consecutive SSH polls.\n${state.error || ''}`.trim(),
      });
    }
    return;
  }

  downStreak.set(row.id, 0);
  clear(`host.down.${row.id}`, `${name} unreachable`, `${row.hostname} is answering SSH again.`);

  const s = state.sample;
  if (!s) return;

  const disk = s.disk || 0;
  if (disk >= ALERT_DISK_PCT) {
    const info = s.info || {};
    raise({
      key: `host.disk.${row.id}`, severity: disk >= 95 ? 'critical' : 'warning',
      subject: `${name} disk ${disk.toFixed(0)}%`,
      message: `Root filesystem is ${disk.toFixed(1)}% full`
        + `${info.diskTotalBytes ? ` (${humanBytes(info.diskUsedBytes)} of ${humanBytes(info.diskTotalBytes)})` : ''}.`
        + `\nThreshold is ${ALERT_DISK_PCT}%.`,
      value: disk,
    });
  } else if (disk < ALERT_DISK_PCT - 3) {
    // 3-point hysteresis so a value hovering on the line does not flap.
    clear(`host.disk.${row.id}`, `${name} disk`, `Disk is back to ${disk.toFixed(1)}%.`);
  }

  const mem = s.mem || 0;
  if (mem >= ALERT_MEM_PCT) {
    raise({
      key: `host.mem.${row.id}`, severity: 'warning',
      subject: `${name} memory ${mem.toFixed(0)}%`,
      message: `Memory is ${mem.toFixed(1)}% used. Threshold is ${ALERT_MEM_PCT}%.`,
      value: mem,
    });
  } else if (mem < ALERT_MEM_PCT - 3) {
    clear(`host.mem.${row.id}`, `${name} memory`, `Memory is back to ${mem.toFixed(1)}%.`);
  }

  // CPU only counts if it has been pinned for a sustained window — a single
  // spike is normal and not worth a message.
  const since = Date.now() - ALERT_CPU_SUSTAIN_MIN * 60 * 1000;
  const window = q.metricsSince.all(row.id, since);
  const enough = window.length >= Math.max(3, (ALERT_CPU_SUSTAIN_MIN * 60 * 1000) / POLL_MS * 0.6);
  if (enough && window.every((m) => (m.cpu || 0) >= ALERT_CPU_PCT)) {
    const avg = window.reduce((a, m) => a + (m.cpu || 0), 0) / window.length;
    raise({
      key: `host.cpu.${row.id}`, severity: 'warning',
      subject: `${name} CPU ${avg.toFixed(0)}%`,
      message: `CPU has been above ${ALERT_CPU_PCT}% for ${ALERT_CPU_SUSTAIN_MIN} minutes (avg ${avg.toFixed(1)}%).`,
      value: avg,
    });
  } else if (enough) {
    clear(`host.cpu.${row.id}`, `${name} CPU`, 'CPU has come back down.');
  }
}

function humanBytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

async function pollAll() {
  const rows = q.allHosts.all();
  await Promise.all(rows.map((r) => pollHost(r)));
  for (const row of rows) {
    const state = live.get(row.id);
    if (state) {
      try { evaluateHostAlerts(row, state); } catch (err) { console.error('[alert]', err.message); }
    }
  }
}

// --------------------------------------------------------- http monitors ---

/**
 * Days until the TLS certificate expires, or null if not applicable.
 * rejectUnauthorized is off on purpose: an already-expired certificate must
 * still be readable, otherwise the one case you most want to alert on is the
 * one case that fails to report.
 */
function tlsDaysLeft(urlString) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(urlString); } catch { return resolve(null); }
    if (u.protocol !== 'https:') return resolve(null);

    const socket = tls.connect({
      host: u.hostname,
      port: Number(u.port) || 443,
      servername: u.hostname,
      rejectUnauthorized: false,
      timeout: 10000,
    }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) return resolve(null);
      resolve(Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000));
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

/** checkId -> { days, at } so TLS is inspected hourly, not every minute. */
const tlsCache = new Map();

async function runCheck(row) {
  let ok = 0;
  let status = null;
  let ms = null;
  let error = '';

  const started = Date.now();
  try {
    const res = await fetch(row.url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'ClusterDash/1.0 (+uptime check)' },
    });
    ms = Date.now() - started;
    status = res.status;
    const body = row.keyword ? (await res.text()).slice(0, 500000) : '';
    if (status !== row.expect_status) {
      error = `expected HTTP ${row.expect_status}, got ${status}`;
    } else if (row.keyword && !body.includes(row.keyword)) {
      error = `keyword "${row.keyword}" not found in response`;
    } else {
      ok = 1;
    }
  } catch (err) {
    ms = Date.now() - started;
    error = String(err.message || err);
  }

  let cached = tlsCache.get(row.id);
  if (!cached || Date.now() - cached.at > 3600 * 1000) {
    cached = { days: await tlsDaysLeft(row.url), at: Date.now() };
    tlsCache.set(row.id, cached);
  }
  const tlsDays = cached.days;

  q.insertCheckResult.run({
    check_id: row.id, ts: Date.now(), ok, status, ms, error, tls_days: tlsDays,
  });

  if (!ok) {
    raise({
      key: `check.down.${row.id}`, severity: 'critical',
      subject: `${row.name} is DOWN`,
      message: `${row.url}\n${error}`,
    });
  } else {
    clear(`check.down.${row.id}`, `${row.name} is DOWN`, `${row.url} is responding normally (HTTP ${status}, ${ms} ms).`);

    if (ms > ALERT_LATENCY_MS) {
      raise({
        key: `check.slow.${row.id}`, severity: 'warning',
        subject: `${row.name} is slow`,
        message: `${row.url} responded in ${ms} ms (threshold ${ALERT_LATENCY_MS} ms).`,
        value: ms,
      });
    } else if (ms < ALERT_LATENCY_MS * 0.8) {
      clear(`check.slow.${row.id}`, `${row.name} is slow`, `Response time back to ${ms} ms.`);
    }
  }

  if (tlsDays != null && tlsDays <= ALERT_TLS_DAYS) {
    raise({
      key: `check.tls.${row.id}`, severity: tlsDays <= 3 ? 'critical' : 'warning',
      subject: `${row.name} TLS expires in ${tlsDays}d`,
      message: `The certificate for ${row.url} expires in ${tlsDays} day(s). Renew it before it lapses.`,
      value: tlsDays,
    });
  } else if (tlsDays != null && tlsDays > ALERT_TLS_DAYS) {
    clear(`check.tls.${row.id}`, `${row.name} TLS expiry`, `Certificate renewed — ${tlsDays} days remaining.`);
  }
}

async function runAllChecks() {
  const rows = q.allChecks.all().filter((c) => c.enabled);
  await Promise.all(rows.map((r) => runCheck(r).catch(() => {})));
}

// ---------------------------------------------------------- daily report ---

const pctOf = (n, d) => (d > 0 ? (n / d) * 100 : 0);

/** Pure enough to test: reads the database, returns the WhatsApp message. */
function composeDailyReport(now = Date.now()) {
  const since = now - 24 * 3600 * 1000;
  const lines = [];
  const date = new Date(now).toLocaleDateString(undefined, { weekday: 'short', day: '2-digit', month: 'short' });

  const hosts = q.allHosts.all();
  const checks = q.allChecks.all();
  const alerts = q.alertsSince.all(since);
  const openNow = alerts.filter((a) => !a.resolved_at);

  lines.push(`📊 *ClusterDash daily report* — ${date}`);
  lines.push('');

  // --- hosts ---
  lines.push(`*Hosts (${hosts.length})*`);
  const expectedSamples = Math.max(1, Math.floor((24 * 3600 * 1000) / POLL_MS));
  for (const h of hosts) {
    const rows = q.metricsSince.all(h.id, since);
    const state = live.get(h.id) || {};
    const availability = Math.min(100, pctOf(rows.length, expectedSamples));
    const peakCpu = rows.length ? Math.max(...rows.map((r) => r.cpu || 0)) : 0;
    const latest = rows.length ? rows[rows.length - 1] : null;

    lines.push(`${state.online ? '🟢' : '🔴'} ${h.name} — ${availability.toFixed(1)}% up`);
    if (latest) {
      lines.push(`   cpu peak ${peakCpu.toFixed(0)}% · mem ${(latest.mem || 0).toFixed(0)}% · disk ${(latest.disk || 0).toFixed(0)}%`);
    } else {
      lines.push('   no samples in the last 24 h');
    }
  }

  // --- monitors ---
  if (checks.length) {
    lines.push('');
    lines.push(`*Sites (${checks.length})*`);
    for (const c of checks) {
      const rows = q.checkResultsSince.all(c.id, since);
      const up = rows.filter((r) => r.ok).length;
      const uptime = pctOf(up, rows.length);
      const withMs = rows.filter((r) => r.ms != null);
      const avgMs = withMs.length ? withMs.reduce((a, r) => a + r.ms, 0) / withMs.length : 0;
      const tlsDays = rows.length ? rows[rows.length - 1].tls_days : null;
      lines.push(`${uptime >= 99.9 ? '🟢' : uptime >= 95 ? '🟠' : '🔴'} ${c.name} — ${rows.length ? `${uptime.toFixed(2)}% uptime` : 'no data'}`);
      if (rows.length) {
        lines.push(`   avg ${Math.round(avgMs)} ms${tlsDays != null ? ` · TLS ${tlsDays}d left` : ''}`);
      }
    }
  }

  // --- alerts ---
  lines.push('');
  if (alerts.length) {
    lines.push(`*Alerts in 24 h: ${alerts.length}* (${openNow.length} still open)`);
    for (const a of alerts.slice(0, 6)) {
      lines.push(`${a.resolved_at ? '✅' : SEVERITY_ICON[a.severity] || '⚠️'} ${a.subject}`);
    }
    if (alerts.length > 6) lines.push(`   …and ${alerts.length - 6} more`);
  } else {
    lines.push('*Alerts in 24 h: none* ✅');
  }

  return lines.join('\n');
}

const lastReport = db.prepare(
  "SELECT ts FROM audit WHERE action = 'report.daily' ORDER BY ts DESC LIMIT 1");

/** Fires on the hour configured; the audit trail is the "already sent" record. */
function maybeSendDailyReport() {
  if (!DAILY_REPORT_ENABLED || !notifierConfigured()) return;
  const now = new Date();
  if (now.getHours() !== DAILY_REPORT_HOUR) return;

  const previous = lastReport.get();
  if (previous && new Date(previous.ts).toDateString() === now.toDateString()) return;

  const text = composeDailyReport(now.getTime());
  audit({ action: 'report.daily', detail: `sent for ${now.toDateString()}` });
  notify(text, 'daily-report');
}

// ------------------------------------------------------------- schedulers ---

const SCHEDULERS = [
  setInterval(() => { pollAll().catch(() => {}); }, POLL_MS),
  setInterval(() => { runAllChecks().catch(() => {}); }, CHECK_INTERVAL_MS),
  setInterval(maybeSendDailyReport, 60 * 1000),
  setInterval(() => {
    q.pruneMetrics.run(Date.now() - RETENTION_HOURS * 3600 * 1000);
    q.pruneCheckResults.run(Date.now() - 30 * 24 * 3600 * 1000);
    q.pruneSessions.run(Date.now());
    pruneRecordings();
  }, 10 * 60 * 1000),
  setTimeout(() => { pollAll().catch(() => {}); }, 1500),
  setTimeout(() => { runAllChecks().catch(() => {}); }, 4000),
];

// ------------------------------------------------------------------ auth ---

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function sessionFrom(req) {
  const token = parseCookies(req.headers.cookie).cd_session;
  if (!token) return null;
  const row = q.session.get(token);
  if (!row) return null;
  if (row.expires < Date.now()) { q.deleteSession.run(token); return null; }
  return row;
}

const app = express();
if (TRUST_PROXY) app.set('trust proxy', true);
app.use(express.json({ limit: '256kb' }));
app.disable('x-powered-by');

const clientIp = (req) => String(req.ip || req.socket.remoteAddress || '').replace('::ffff:', '');

function requireAuth(req, res, next) {
  const session = sessionFrom(req);
  if (!session) return res.status(401).json({ error: 'not authenticated' });
  req.actor = session.actor;
  next();
}

// Small fixed-window throttle so the login form cannot be brute-forced.
const loginAttempts = new Map();
function throttled(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, until: 0 };
  if (entry.until > now) return true;
  if (now - (entry.stamp || 0) > 15 * 60 * 1000) entry.count = 0;
  entry.stamp = now;
  entry.count += 1;
  if (entry.count > 10) { entry.until = now + 15 * 60 * 1000; entry.count = 0; }
  loginAttempts.set(ip, entry);
  return false;
}

app.post('/api/login', (req, res) => {
  const ip = clientIp(req);
  if (throttled(ip)) {
    audit({ actor: String(req.body?.username || '?'), ip, action: 'auth.throttled', result: 'error' });
    return res.status(429).json({ error: 'too many attempts, try again in 15 minutes' });
  }
  const { username, password } = req.body || {};
  const ok = username === ADMIN_USER && password && passwordMatches(password);
  if (!ok) {
    audit({ actor: String(username || '?'), ip, action: 'auth.login', result: 'denied' });
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  q.insertSession.run(token, ADMIN_USER, Date.now() + SESSION_TTL_MS);
  res.setHeader('Set-Cookie',
    `cd_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}` +
    (SECURE_COOKIES ? '; Secure' : ''));
  audit({ actor: ADMIN_USER, ip, action: 'auth.login', detail: 'session opened' });
  res.json({ user: ADMIN_USER });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = parseCookies(req.headers.cookie).cd_session;
  q.deleteSession.run(token);
  audit({ actor: req.actor, ip: clientIp(req), action: 'auth.logout' });
  res.setHeader('Set-Cookie', 'cd_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const session = sessionFrom(req);
  if (!session) return res.status(401).json({ error: 'not authenticated' });
  res.json({ user: session.actor, pollSeconds: POLL_MS / 1000, retentionHours: RETENTION_HOURS });
});

// ------------------------------------------------------------------ API ---

const publicHost = (row) => {
  const state = live.get(row.id) || {};
  return {
    id: row.id, name: row.name, hostname: row.hostname, port: row.port,
    username: row.username, role: row.role, provider: row.provider,
    online: state.online === true,
    checkedAt: state.at || null,
    error: state.error || null,
    sample: state.sample ? { ...state.sample, info: state.sample.info } : null,
  };
};

app.get('/api/hosts', requireAuth, (req, res) => {
  res.json(q.allHosts.all().map(publicHost));
});

app.post('/api/hosts', requireAuth, (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  const hostname = String(b.hostname || '').trim();
  const password = String(b.password || '');
  if (!name || !hostname || !password) {
    return res.status(400).json({ error: 'name, hostname and password are required' });
  }
  const row = {
    name,
    hostname,
    port: Number(b.port) || 22,
    username: String(b.username || 'root').trim() || 'root',
    secret: encrypt(password),
    role: ['master', 'worker', 'standalone'].includes(b.role) ? b.role : 'standalone',
    provider: String(b.provider || '').trim(),
    created_at: Date.now(),
  };
  const info = q.insertHost.run(row);
  audit({ actor: req.actor, ip: clientIp(req), action: 'host.create',
          host_id: info.lastInsertRowid, host_name: name,
          detail: `${row.username}@${hostname}:${row.port} role=${row.role}` });
  pollHost(q.host.get(info.lastInsertRowid)).catch(() => {});
  res.json({ id: info.lastInsertRowid });
});

app.delete('/api/hosts/:id', requireAuth, (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  dropConnection(row.id);
  live.delete(row.id);
  previous.delete(row.id);
  q.deleteHost.run(row.id);
  audit({ actor: req.actor, ip: clientIp(req), action: 'host.delete',
          host_id: row.id, host_name: row.name, detail: row.hostname });
  res.json({ ok: true });
});

app.post('/api/hosts/:id/test', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  try {
    const r = await sshExec(row, 'echo clusterdash-ok', 15000);
    const ok = r.stdout.includes('clusterdash-ok');
    audit({ actor: req.actor, ip: clientIp(req), action: 'host.test',
            host_id: row.id, host_name: row.name, result: ok ? 'ok' : 'error' });
    res.json({ ok });
  } catch (err) {
    dropConnection(row.id);
    audit({ actor: req.actor, ip: clientIp(req), action: 'host.test', host_id: row.id,
            host_name: row.name, detail: String(err.message || err), result: 'error' });
    res.status(502).json({ ok: false, error: String(err.message || err) });
  }
});

app.get('/api/hosts/:id/metrics', requireAuth, (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  const minutes = Math.min(Number(req.query.minutes) || 60, RETENTION_HOURS * 60);
  res.json(q.metricsSince.all(row.id, Date.now() - minutes * 60 * 1000));
});

app.get('/api/hosts/:id/services', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  try {
    // --all so stopped and failed units show up too, not just running ones.
    const r = await sshExec(row,
      'systemctl list-units --type=service --all --no-legend --no-pager --plain 2>/dev/null | head -n 120');
    const services = r.stdout.split('\n').filter(Boolean).map((line) => {
      // Failed units can carry a leading bullet even with --plain.
      const parts = line.replace(/^[\s●*]+/, '').trim().split(/\s+/);
      return {
        unit: parts[0],
        load: parts[1] || '',
        active: parts[2] || '',   // active | inactive | failed | activating
        sub: parts[3] || '',      // running | dead | exited | failed
        description: parts.slice(4).join(' '),
      };
    }).filter((s) => s.unit && s.unit.endsWith('.service') && s.load !== 'not-found');

    // Anything broken or running first; inert units last.
    const rank = (s) => (s.active === 'failed' ? 0 : s.sub === 'running' ? 1 : 2);
    services.sort((a, b) => rank(a) - rank(b) || a.unit.localeCompare(b.unit));
    res.json(services);
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

// ------------------------------------------------------------ kubernetes ---

// Kubernetes object names are DNS subdomains; validating them keeps every value
// below out of shell-metacharacter territory.
const K8S_NAME = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/;
const K8S_CONTAINER = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;

// Find a usable kubeconfig: kubeadm, k3s, then root's own. Without this,
// `kubectl` over a non-login SSH exec channel often has no config at all.
const KUBECTL = `
for c in "$HOME/.kube/config" /etc/kubernetes/admin.conf /etc/rancher/k3s/k3s.yaml; do
  [ -f "$c" ] && export KUBECONFIG="$c" && break
done
command -v kubectl >/dev/null 2>&1 || { echo "__NO_KUBECTL__"; exit 0; }
`.trim();

async function kubectl(row, args, timeoutMs = 25000) {
  const r = await sshExec(row, `${KUBECTL}\nkubectl ${args} 2>&1`, timeoutMs);
  const out = r.stdout.trim();
  if (out.includes('__NO_KUBECTL__')) {
    const err = new Error('kubectl not found on this host');
    err.kind = 'no-kubectl';
    throw err;
  }
  return out;
}

function parseJsonOutput(text, what) {
  const start = text.indexOf('{');
  if (start === -1) throw new Error(`${what}: ${text.slice(0, 300) || 'no output'}`);
  try {
    return JSON.parse(text.slice(start));
  } catch {
    throw new Error(`${what}: ${text.slice(0, 300)}`);
  }
}

const age = (iso) => {
  if (!iso) return '';
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
};

// Cluster-level: nodes plus the namespace list that drives the UI selector.
app.get('/api/hosts/:id/k8s', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  try {
    const out = await kubectl(row, 'get nodes,namespaces -o json');
    const doc = parseJsonOutput(out, 'kubectl get nodes,namespaces');
    const items = doc.items || [];
    const nodes = items.filter((i) => i.kind === 'Node' || i.status?.nodeInfo).map((n) => {
      const ready = (n.status?.conditions || []).find((c) => c.type === 'Ready');
      const roles = Object.keys(n.metadata?.labels || {})
        .filter((k) => k.startsWith('node-role.kubernetes.io/'))
        .map((k) => k.split('/')[1]).filter(Boolean);
      return {
        name: n.metadata?.name,
        ready: ready?.status === 'True',
        status: ready?.status === 'True' ? 'Ready' : (ready?.reason || 'NotReady'),
        roles: roles.length ? roles.join(', ') : 'worker',
        version: n.status?.nodeInfo?.kubeletVersion || '',
        age: age(n.metadata?.creationTimestamp),
      };
    });
    const namespaces = items
      .filter((i) => i.kind === 'Namespace' || (!i.status?.nodeInfo && i.status?.phase))
      .map((n) => n.metadata?.name).filter(Boolean).sort();
    res.json({ nodes, namespaces });
  } catch (err) {
    res.status(err.kind === 'no-kubectl' ? 404 : 502).json({ error: String(err.message || err) });
  }
});

// Namespace-level: pods (with their containers) and deployments in one trip.
app.get('/api/hosts/:id/k8s/workloads', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  const ns = String(req.query.ns || '');
  const scope = ns === '*' ? '--all-namespaces' : (K8S_NAME.test(ns) ? `-n ${ns}` : null);
  if (!scope) return res.status(400).json({ error: 'invalid namespace' });

  try {
    const out = await kubectl(row,
      `get pods ${scope} -o json; echo "@@SPLIT@@"; kubectl get deployments ${scope} -o json`);
    const [podPart, deployPart] = out.split('@@SPLIT@@');
    const podDoc = parseJsonOutput(podPart, 'kubectl get pods');
    const depDoc = parseJsonOutput(deployPart || '', 'kubectl get deployments');

    const pods = (podDoc.items || []).map((p) => {
      const statuses = p.status?.containerStatuses || [];
      const ready = statuses.filter((c) => c.ready).length;
      const restarts = statuses.reduce((a, c) => a + (c.restartCount || 0), 0);
      // A pod can be "Running" while a container inside it is crash-looping.
      const waiting = statuses.map((c) => c.state?.waiting?.reason).filter(Boolean);
      return {
        name: p.metadata?.name,
        namespace: p.metadata?.namespace,
        phase: waiting[0] || p.status?.phase || 'Unknown',
        healthy: p.status?.phase === 'Running' && !waiting.length && ready === statuses.length && statuses.length > 0,
        ready: `${ready}/${statuses.length || (p.spec?.containers || []).length}`,
        restarts,
        node: p.spec?.nodeName || '',
        age: age(p.metadata?.creationTimestamp),
        containers: (p.spec?.containers || []).map((c) => c.name),
      };
    }).sort((a, b) => Number(a.healthy) - Number(b.healthy) || a.name.localeCompare(b.name));

    const deployments = (depDoc.items || []).map((d) => {
      const desired = d.spec?.replicas ?? 0;
      const ready = d.status?.readyReplicas ?? 0;
      return {
        name: d.metadata?.name,
        namespace: d.metadata?.namespace,
        ready: `${ready}/${desired}`,
        healthy: desired > 0 && ready === desired,
        upToDate: d.status?.updatedReplicas ?? 0,
        available: d.status?.availableReplicas ?? 0,
        age: age(d.metadata?.creationTimestamp),
      };
    }).sort((a, b) => Number(a.healthy) - Number(b.healthy) || a.name.localeCompare(b.name));

    res.json({ pods, deployments });
  } catch (err) {
    res.status(err.kind === 'no-kubectl' ? 404 : 502).json({ error: String(err.message || err) });
  }
});

app.get('/api/hosts/:id/k8s/logs', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  const ns = String(req.query.ns || '');
  const pod = String(req.query.pod || '');
  const container = String(req.query.container || '');
  const tail = Math.min(Math.max(Number(req.query.tail) || 200, 1), 2000);

  if (!K8S_NAME.test(ns)) return res.status(400).json({ error: 'invalid namespace' });
  if (!K8S_NAME.test(pod)) return res.status(400).json({ error: 'invalid pod name' });
  if (container && !K8S_CONTAINER.test(container)) {
    return res.status(400).json({ error: 'invalid container name' });
  }

  try {
    const logs = await kubectl(row,
      `logs ${pod} -n ${ns}${container ? ` -c ${container}` : ''} --tail=${tail} --timestamps`, 30000);
    audit({ actor: req.actor, ip: clientIp(req), action: 'k8s.logs', host_id: row.id,
            host_name: row.name, detail: `${ns}/${pod}${container ? `:${container}` : ''} tail=${tail}` });
    res.json({ logs });
  } catch (err) {
    res.status(err.kind === 'no-kubectl' ? 404 : 502).json({ error: String(err.message || err) });
  }
});

// Whitelisted lifecycle operations. Nothing here interpolates raw user input
// except a service unit name, which is validated against a strict pattern.
const UNIT_PATTERN = /^[A-Za-z0-9@:._-]{1,80}\.service$/;

// No poweroff action: a VPS that is fully off cannot be started again over SSH,
// so the only way back is the provider's panel. Reboot is the safe equivalent.
const ACTIONS = {
  reboot: () => "nohup sh -c 'sleep 1; systemctl reboot || reboot' >/dev/null 2>&1 & echo scheduled",
  'service.restart': (u) => `systemctl restart ${u} && systemctl is-active ${u}`,
  'service.stop': (u) => `systemctl stop ${u}; systemctl is-active ${u} || true`,
  'service.start': (u) => `systemctl start ${u} && systemctl is-active ${u}`,
};

app.post('/api/hosts/:id/action', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  const action = String(req.body?.action || '');
  const unit = String(req.body?.unit || '');
  const build = ACTIONS[action];
  if (!build) return res.status(400).json({ error: 'unknown action' });
  if (action.startsWith('service.') && !UNIT_PATTERN.test(unit)) {
    return res.status(400).json({ error: 'invalid service unit name' });
  }

  const base = { actor: req.actor, ip: clientIp(req), action, host_id: row.id, host_name: row.name };
  try {
    const r = await sshExec(row, build(unit), 30000);
    const output = (r.stdout + r.stderr).trim().slice(0, 2000);
    audit({ ...base, detail: `${unit ? unit + ' — ' : ''}${output || 'no output'}`.slice(0, 500),
            result: r.code === 0 ? 'ok' : 'error' });
    if (action === 'reboot') {
      // The box is going away; drop the pooled socket so we redial cleanly.
      setTimeout(() => dropConnection(row.id), 500);
    }
    res.json({ ok: r.code === 0, output });
  } catch (err) {
    dropConnection(row.id);
    audit({ ...base, detail: String(err.message || err), result: 'error' });
    res.status(502).json({ ok: false, error: String(err.message || err) });
  }
});

app.get('/api/hosts/:id/k8s/events', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  const ns = String(req.query.ns || '');
  const scope = ns === '*' ? '--all-namespaces' : (K8S_NAME.test(ns) ? `-n ${ns}` : null);
  if (!scope) return res.status(400).json({ error: 'invalid namespace' });
  try {
    const out = await kubectl(row, `get events ${scope} --sort-by=.lastTimestamp -o json`);
    const doc = parseJsonOutput(out, 'kubectl get events');
    const events = (doc.items || []).slice(-80).reverse().map((e) => ({
      type: e.type || '',
      reason: e.reason || '',
      object: `${e.involvedObject?.kind || ''}/${e.involvedObject?.name || ''}`,
      namespace: e.metadata?.namespace || '',
      message: (e.message || '').slice(0, 400),
      count: e.count || 1,
      age: age(e.lastTimestamp || e.eventTime || e.metadata?.creationTimestamp),
    }));
    res.json(events);
  } catch (err) {
    res.status(err.kind === 'no-kubectl' ? 404 : 502).json({ error: String(err.message || err) });
  }
});

// Write actions on workloads. Deliberately limited to restart and scale: both
// are reversible, unlike deleting a resource.
app.post('/api/hosts/:id/k8s/deployment', requireAuth, async (req, res) => {
  const row = q.host.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such host' });
  const { action, name, namespace } = req.body || {};
  const replicas = Number(req.body?.replicas);

  if (!K8S_NAME.test(String(name || ''))) return res.status(400).json({ error: 'invalid deployment name' });
  if (!K8S_NAME.test(String(namespace || ''))) return res.status(400).json({ error: 'invalid namespace' });

  let command;
  if (action === 'restart') {
    command = `rollout restart deployment/${name} -n ${namespace}`;
  } else if (action === 'scale') {
    if (!Number.isInteger(replicas) || replicas < 0 || replicas > 100) {
      return res.status(400).json({ error: 'replicas must be an integer between 0 and 100' });
    }
    command = `scale deployment/${name} -n ${namespace} --replicas=${replicas}`;
  } else {
    return res.status(400).json({ error: 'unknown action' });
  }

  const base = { actor: req.actor, ip: clientIp(req), action: `k8s.${action}`,
                 host_id: row.id, host_name: row.name };
  try {
    const out = await kubectl(row, command, 30000);
    audit({ ...base, detail: `${namespace}/${name}${action === 'scale' ? ` -> ${replicas}` : ''}: ${out}`.slice(0, 400) });
    res.json({ ok: true, output: out });
  } catch (err) {
    audit({ ...base, detail: String(err.message || err), result: 'error' });
    res.status(502).json({ ok: false, error: String(err.message || err) });
  }
});

// ---------------------------------------------------------- http monitors ---

app.get('/api/checks', requireAuth, (req, res) => {
  const since = Date.now() - 24 * 3600 * 1000;
  res.json(q.allChecks.all().map((c) => {
    const rows = q.checkResultsSince.all(c.id, since);
    const last = rows.length ? rows[rows.length - 1] : null;
    const up = rows.filter((r) => r.ok).length;
    const withMs = rows.filter((r) => r.ms != null);
    return {
      ...c,
      enabled: !!c.enabled,
      up: last ? !!last.ok : null,
      status: last ? last.status : null,
      ms: last ? last.ms : null,
      error: last ? last.error : '',
      tlsDays: last ? last.tls_days : null,
      uptime24h: rows.length ? pctOf(up, rows.length) : null,
      avgMs: withMs.length ? withMs.reduce((a, r) => a + r.ms, 0) / withMs.length : null,
      history: rows.slice(-120).map((r) => ({ ts: r.ts, ok: !!r.ok, ms: r.ms })),
    };
  }));
});

app.post('/api/checks', requireAuth, (req, res) => {
  const name = String(req.body?.name || '').trim();
  const url = String(req.body?.url || '').trim();
  if (!name || !url) return res.status(400).json({ error: 'name and url are required' });
  let parsed;
  try { parsed = new URL(url); } catch { return res.status(400).json({ error: 'invalid URL' }); }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).json({ error: 'URL must be http or https' });
  }
  const info = q.insertCheck.run({
    name, url,
    expect_status: Number(req.body?.expect_status) || 200,
    keyword: String(req.body?.keyword || '').slice(0, 200),
    created_at: Date.now(),
  });
  audit({ actor: req.actor, ip: clientIp(req), action: 'check.create', detail: `${name} ${url}` });
  runCheck(q.check.get(info.lastInsertRowid)).catch(() => {});
  res.json({ id: info.lastInsertRowid });
});

app.delete('/api/checks/:id', requireAuth, (req, res) => {
  const row = q.check.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such check' });
  q.deleteCheck.run(row.id);
  audit({ actor: req.actor, ip: clientIp(req), action: 'check.delete', detail: `${row.name} ${row.url}` });
  res.json({ ok: true });
});

app.post('/api/checks/:id/toggle', requireAuth, (req, res) => {
  const row = q.check.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such check' });
  q.toggleCheck.run(row.enabled ? 0 : 1, row.id);
  audit({ actor: req.actor, ip: clientIp(req), action: 'check.toggle',
          detail: `${row.name} -> ${row.enabled ? 'paused' : 'enabled'}` });
  res.json({ ok: true });
});

// ---------------------------------------------------- alerts & messaging ---

app.get('/api/alerts', requireAuth, (req, res) => {
  res.json(q.recentAlerts.all(Math.min(Number(req.query.limit) || 100, 500)));
});

app.get('/api/notify/status', requireAuth, (req, res) => {
  res.json({
    provider: WHATSAPP_PROVIDER,
    configured: notifierConfigured(),
    dailyReport: DAILY_REPORT_ENABLED && notifierConfigured(),
    dailyReportHour: DAILY_REPORT_HOUR,
    thresholds: {
      disk: ALERT_DISK_PCT, memory: ALERT_MEM_PCT, cpu: ALERT_CPU_PCT,
      cpuSustainMinutes: ALERT_CPU_SUSTAIN_MIN, latencyMs: ALERT_LATENCY_MS,
      tlsDays: ALERT_TLS_DAYS, cooldownMinutes: ALERT_COOLDOWN_MS / 60000,
    },
  });
});

// Sending a real WhatsApp message is an outward-facing act, so it only ever
// happens when the operator explicitly asks for it here.
app.post('/api/notify/test', requireAuth, async (req, res) => {
  if (!notifierConfigured()) return res.status(400).json({ error: 'no provider configured' });
  try {
    await deliver(`✅ *ClusterDash test message*\nSent by ${req.actor} at ${new Date().toLocaleString()}.\nAlerts and daily reports will arrive here.`);
    audit({ actor: req.actor, ip: clientIp(req), action: 'notify.test', detail: WHATSAPP_PROVIDER });
    res.json({ ok: true });
  } catch (err) {
    audit({ actor: req.actor, ip: clientIp(req), action: 'notify.test',
            detail: String(err.message || err), result: 'error' });
    res.status(502).json({ error: String(err.message || err) });
  }
});

app.post('/api/notify/report', requireAuth, async (req, res) => {
  if (!notifierConfigured()) return res.status(400).json({ error: 'no provider configured' });
  const text = composeDailyReport();
  try {
    await deliver(text);
    audit({ actor: req.actor, ip: clientIp(req), action: 'report.manual', detail: 'sent on demand' });
    res.json({ ok: true, preview: text });
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

app.get('/api/notify/report/preview', requireAuth, (req, res) => {
  res.json({ preview: composeDailyReport() });
});

// ------------------------------------------------------ console recordings ---

app.get('/api/recordings', requireAuth, (req, res) => {
  res.json(q.consoleSessions.all(Math.min(Number(req.query.limit) || 100, 500)));
});

app.get('/api/recordings/:id', requireAuth, (req, res) => {
  const row = q.consoleSession.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'no such recording' });
  const file = recordingPath(row.id);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'transcript no longer on disk' });
  audit({ actor: req.actor, ip: clientIp(req), action: 'recording.view',
          host_id: row.host_id, host_name: row.host_name, detail: row.id });
  res.json({ ...row, transcript: fs.readFileSync(file, 'utf8').slice(-500000) });
});

app.get('/api/audit', requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 2000);
  const hostId = req.query.host ? Number(req.query.host) : null;
  const rows = hostId
    ? db.prepare('SELECT * FROM audit WHERE host_id = ? ORDER BY ts DESC LIMIT ?').all(hostId, limit)
    : db.prepare('SELECT * FROM audit ORDER BY ts DESC LIMIT ?').all(limit);
  res.json(rows);
});

app.get('/api/audit.csv', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM audit ORDER BY ts DESC LIMIT 20000').all();
  const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const body = ['timestamp,actor,ip,action,host,detail,result']
    .concat(rows.map((r) => [
      new Date(r.ts).toISOString(), r.actor, r.ip, r.action, r.host_name, r.detail, r.result,
    ].map(escape).join(',')))
    .join('\n');
  audit({ actor: req.actor, ip: clientIp(req), action: 'audit.export', detail: `${rows.length} rows` });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="clusterdash-audit.csv"');
  res.send(body);
});

// --------------------------------------------------------------- statics ---

app.use('/vendor/xterm.css', express.static(require.resolve('@xterm/xterm/css/xterm.css')));
app.use('/vendor/xterm.js', express.static(require.resolve('@xterm/xterm/lib/xterm.js')));
app.use('/vendor/xterm-fit.js', express.static(require.resolve('@xterm/addon-fit/lib/addon-fit.js')));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

// ------------------------------------------------------ websocket console ---

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const recordingPath = (id) => path.join(RECORD_DIR, `${id}.log`);

function pruneRecordings() {
  const cutoff = Date.now() - RECORD_RETENTION_DAYS * 24 * 3600 * 1000;
  for (const row of db.prepare('SELECT id FROM console_sessions WHERE started < ?').all(cutoff)) {
    try { fs.unlinkSync(recordingPath(row.id)); } catch { /* already gone */ }
  }
  q.pruneConsole.run(cutoff);
}

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/ws/terminal') return socket.destroy();
  const session = sessionFrom(req);
  if (!session) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return socket.destroy();
  }
  const row = q.host.get(url.searchParams.get('host'));
  if (!row) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    return socket.destroy();
  }

  // Optional pod-exec mode: same terminal component, different remote command.
  const pod = url.searchParams.get('pod') || '';
  const ns = url.searchParams.get('ns') || '';
  const container = url.searchParams.get('container') || '';
  if (pod && (!K8S_NAME.test(pod) || !K8S_NAME.test(ns) || (container && !K8S_CONTAINER.test(container)))) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    return socket.destroy();
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    openTerminal(ws, row, session.actor,
      String(req.socket.remoteAddress || '').replace('::ffff:', ''),
      pod ? { pod, ns, container } : null);
  });
});

function openTerminal(ws, row, actor, ip, exec) {
  const send = (text) => { if (ws.readyState === ws.OPEN) ws.send(text); };
  const started = Date.now();
  const sessionId = crypto.randomUUID();
  const target = exec ? `${exec.ns}/${exec.pod}${exec.container ? `:${exec.container}` : ''}` : `${row.username}@${row.hostname}`;
  const kind = exec ? 'kubectl-exec' : 'ssh';

  audit({ actor, ip, action: 'console.open', host_id: row.id, host_name: row.name,
          detail: `${kind} ${target}` });

  // Full transcript to disk so the audit trail records what was done, not just
  // that a session happened.
  let recorder = null;
  let recorded = 0;
  if (RECORD_CONSOLE) {
    q.insertConsole.run({ id: sessionId, host_id: row.id, host_name: row.name,
                          actor, kind, started });
    recorder = fs.createWriteStream(recordingPath(sessionId), { flags: 'a' });
    recorder.write(`=== ClusterDash console ${sessionId}\n`
      + `=== ${kind} ${target} as ${actor} from ${ip}\n`
      + `=== started ${new Date(started).toISOString()}\n\n`);
  }
  const record = (chunk) => {
    if (!recorder) return;
    recorded += Buffer.byteLength(chunk);
    recorder.write(chunk);
  };

  // A dedicated connection per console: a hung interactive shell must never
  // block the metrics poller sharing the pooled client.
  const client = new Client();
  let shell = null;

  client.on('ready', () => {
    const onStream = (err, stream) => {
      if (err) { send(`\r\n\x1b[31msession failed: ${err.message}\x1b[0m\r\n`); return ws.close(); }
      shell = stream;
      stream.on('data', (d) => { const s = d.toString('utf8'); send(s); record(s); });
      stream.stderr.on('data', (d) => { const s = d.toString('utf8'); send(s); record(s); });
      stream.on('close', () => ws.close());
    };

    if (exec) {
      const containerFlag = exec.container ? ` -c ${exec.container}` : '';
      // sh -c so the kubeconfig discovery prelude applies to the exec too.
      client.exec(
        `${KUBECTL}\nkubectl exec -it ${exec.pod} -n ${exec.ns}${containerFlag} -- sh -c 'command -v bash >/dev/null && exec bash || exec sh'`,
        { pty: { term: 'xterm-256color', cols: 100, rows: 30 } }, onStream);
    } else {
      client.shell({ term: 'xterm-256color', cols: 100, rows: 30 }, onStream);
    }
  });
  client.on('error', (err) => {
    send(`\r\n\x1b[31mconnection failed: ${err.message}\x1b[0m\r\n`);
    ws.close();
  });
  client.connect({
    host: row.hostname, port: row.port, username: row.username,
    password: decrypt(row.secret), readyTimeout: 15000, keepaliveInterval: 20000,
  });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (!shell) return;
    if (msg.t === 'd') shell.write(msg.d);
    else if (msg.t === 'r' && shell.setWindow) shell.setWindow(msg.rows, msg.cols, 0, 0);
  });

  ws.on('close', () => {
    try { client.end(); } catch { /* already gone */ }
    if (recorder) {
      recorder.end(`\n\n=== ended ${new Date().toISOString()}\n`);
      q.endConsole.run(Date.now(), recorded, sessionId);
    }
    audit({ actor, ip, action: 'console.close', host_id: row.id, host_name: row.name,
            detail: `${kind} ${target} — lasted ${Math.round((Date.now() - started) / 1000)}s`
              + (RECORD_CONSOLE ? `, transcript ${sessionId}` : '') });
  });
}

// Requiring this file (rather than running it) gives you the internals without
// binding a port, so the alerting and report logic can be tested directly
// instead of against a copy that can drift out of step.
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`ClusterDash listening on http://0.0.0.0:${PORT}`);
    console.log(`  data dir      ${DATA_DIR}`);
    console.log(`  poll interval ${POLL_MS / 1000}s   retention ${RETENTION_HOURS}h`);
    console.log(`  notifications ${notifierConfigured() ? WHATSAPP_PROVIDER : 'disabled'}`
      + `${DAILY_REPORT_ENABLED && notifierConfigured() ? ` · daily report at ${DAILY_REPORT_HOUR}:00` : ''}`);
    audit({ action: 'server.start', detail: `port ${PORT}` });
  });
} else {
  for (const timer of SCHEDULERS) timer.unref();
}

module.exports = {
  db, q, app, server,
  raise, clear, evaluateHostAlerts, composeDailyReport, downStreak, live,
  encrypt, decrypt, parseProbe, splitSections, humanBytes,
  deliver, notifierConfigured,
};
