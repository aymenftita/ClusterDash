# ClusterDash

A Cockpit-style dashboard for a small VPS fleet — **manage**, **audit** and **open a
shell on** your servers from one web UI.

Built for this setup:

| Host | Provider | Role |
|---|---|---|
| 1 | Hostinger | k8s master |
| 2 | Hostinger | k8s worker |
| 3 | Hostinger | k8s worker |
| 4 | Contabo | standalone — *runs this dashboard* |

## Why it is not Cockpit

Cockpit installs an agent on every machine and gives each one its own web port.
ClusterDash is **agentless**: it holds SSH credentials for your hosts and talks to
them over plain SSH. Nothing is installed on your k8s nodes, so it cannot
interfere with the cluster, and there is exactly one thing to deploy.

## What it does

- **Manage** — reboot, shut down, and start/stop/restart systemd services.
  Every operation is whitelisted server-side; a service name is validated against
  a strict pattern before it is ever placed in a command line.
- **Open** — a real interactive shell in the browser (xterm.js over a websocket
  bridged to an SSH PTY). Each console gets its own SSH connection so a hung
  shell can never stall metrics collection.
- **Audit** — an append-only trail of every login (including failures), lifecycle
  action, console session, and host going unreachable. Filterable per host,
  exportable to CSV.
- **Watch** — CPU, memory, disk, swap, load, network throughput, uptime and top
  processes for each host, sampled over SSH every 15 s and kept for 48 h.

## Architecture

One container. One SQLite file. No agents, no message bus, no Prometheus.

```
browser ──HTTP/WS──> ClusterDash (VPS 4) ──SSH:22──> master, worker-1, worker-2
                          │
                     /data/clusterdash.db   hosts · metrics · audit · sessions
```

| File | Role |
|---|---|
| `server.js` | Entire backend: auth, crypto, SQLite, SSH pool, poller, REST API, websocket console |
| `public/index.html` | Markup |
| `public/app.js` | UI, charts, terminal client |
| `public/style.css` | Both themes |
| `Dockerfile`, `docker-compose.yml` | Deployment |

The metrics probe is a single SSH round trip per host per poll, reading
`/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/net/dev` and `df`. CPU
percentage and network throughput are computed as deltas against the previous
sample, so the first reading after startup shows 0 by definition.

---

## Deploy on the standalone VPS

### 1. Install Docker (once)

```bash
curl -fsSL https://get.docker.com | sh
```

### 2. Copy the project up

From this machine:

```bash
scp -r ClusterDash root@<vps4-ip>:/opt/clusterdash
```

### 3. Configure

```bash
cd /opt/clusterdash
cp .env.example .env
openssl rand -base64 48        # paste the output as MASTER_KEY
nano .env                      # set ADMIN_PASSWORD and MASTER_KEY
```

`ADMIN_PASSWORD` is the only thing standing between the internet and root on all
four servers. Make it long and unique.

`MASTER_KEY` encrypts the stored SSH passwords (AES-256-GCM). Losing it does not
lose the database — you just re-enter each host password.

### 4. Start

```bash
docker compose up -d --build
docker compose logs -f
```

Open `http://<vps4-ip>:8080`, sign in, go to the **Hosts** tab, and add your four
servers. Each one is connection-tested as you add it.

### 5. Put HTTPS in front of it (do this before real use)

Without TLS your dashboard password and every keystroke in the web console
travel in clear text. With a DNS A record pointing at VPS 4:

```bash
# in docker-compose.yml change the app's port mapping to  "127.0.0.1:8080:8080"
echo "DOMAIN=dash.example.com" >> .env
echo "SECURE_COOKIES=1"        >> .env
echo "TRUST_PROXY=1"           >> .env
docker compose --profile tls up -d
```

Caddy obtains and renews a Let's Encrypt certificate automatically. Ports 80 and
443 must be open.

If you would rather not expose it at all, bind to localhost only and reach it
through an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 root@<vps4-ip>
```

---

## Security notes

- Host passwords are encrypted at rest with AES-256-GCM; the key lives only in
  `.env`, never in the database.
- Session cookies are `HttpOnly` + `SameSite=Lax`, and `Secure` once
  `SECURE_COOKIES=1`.
- Login is rate-limited to 10 attempts per IP per 15 minutes; every failure is
  audited.
- Only whitelisted actions can be executed. There is no free-text command
  endpoint — arbitrary commands are possible only through the console, which is
  itself audited on open and close.
- **Never commit `.env` or the `data/` directory.**

## Operations

```bash
docker compose logs -f          # follow
docker compose restart          # restart
docker compose up -d --build    # apply code changes
sqlite3 data/clusterdash.db "select count(*) from audit;"
```

Back up `data/clusterdash.db` (or the whole `data/` directory) — it holds your
host list, metric history and the audit trail.

Tunables in `.env`: `POLL_INTERVAL_SECONDS` (default 15) and `RETENTION_HOURS`
(default 48). At 15 s across 4 hosts the database grows by roughly 1 MB per day
before pruning.

## Accessibility & charts

Series colours come from a palette validated for colour-vision deficiency —
worst adjacent-pair separation ΔE 9.1 (light) and 8.4 (dark), against a target of
8. A host keeps its assigned colour permanently, so removing one never repaints
the others. Status is always an icon plus a word, never colour alone, and the
fleet chart offers a table view because two light-mode series sit below 3:1
contrast against the surface.

## Known limits

- A fully powered-off VPS cannot be started from here — nothing is listening on
  SSH. Use the Contabo or Hostinger panel for that. Adding true power control
  means wiring in their provider APIs.
- Password auth only for now. Key-based auth is a small change in the two
  `client.connect(...)` calls in `server.js` (swap `password` for `privateKey`).
