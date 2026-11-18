# 🍯 ssh-honeypot

> A tiny SSH honeypot with a live web dashboard, written in Python. 🐍
> It pretends to be a vulnerable server, lets "attackers" in, and **logs everything they try**. 🕵️

![python](https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white)
![status](https://img.shields.io/badge/status-learning%20project-orange)
![license](https://img.shields.io/badge/license-MIT-green)

---

## 🤔 What is a honeypot?

A **honeypot** is a fake system built to be attacked. Real bots scan the whole internet for SSH
servers and try common passwords. This tool catches those attempts so you can **see what attackers
actually do**: which usernames and passwords they guess, and which commands they run. 🎣

## ✨ Features

- 🔐 Fake SSH server (using `paramiko`) that logs username, password, client software and IP
- 🐚 Fake shell for weak logins (like `root:123456`). It **only prints fake output**
- 📝 Logs every command typed (great for spotting malware download attempts like `wget http://...`)
- 📊 Live web dashboard: top usernames, passwords, IPs, attempts per hour, recent commands
- 🎮 `simulate.py` lets you play the attacker against your own honeypot to test it
- 🗺️ **GeoIP**: shows which countries attacks come from (cached locally)
- 🧠 **MITRE ATT&CK tagging**: commands are mapped to techniques like `T1105 Ingress Tool Transfer`
- 🔔 **Alerts**: optional Discord / Telegram message when someone tries to download malware
- 📄 **`report.py`**: generates a ready-to-publish Markdown report (top passwords, countries, ATT&CK table, defanged malware URLs)
- 🗄️ Everything stored in a simple SQLite file

## 🛡️ Safety (please read!)

- ✅ **Nothing the attacker types is ever executed.** Commands are matched against a small fake list.
- ✅ The dashboard shows attacker input with `textContent` (not `innerHTML`) so a malicious
  username can't inject code into your page.
- ⚠️ Run it inside a **VM** or on a throwaway cloud server, never on a machine with important data.
- ⚠️ If you expose it to the internet, move your *real* SSH to another port first.
- ⚠️ Keep the dashboard on `127.0.0.1` (default).
- ⚖️ Only run it on networks and machines you own or are allowed to use.

## 🛠️ Install

```bash
git clone https://github.com/<your-username>/ssh-honeypot.git
cd ssh-honeypot
pip install -r requirements.txt
```

## 🎮 How to use it

Open **3 terminals**:

```bash
# 1) start the honeypot (port 2222, no admin rights needed)
python honeypot.py --port 2222

# 2) start the dashboard, then open http://127.0.0.1:8765
python dashboard.py --port 8765

# 3) be the attacker! 😈
python simulate.py --rounds 20
# or by hand:  ssh root@127.0.0.1 -p 2222   (password: 123456)
```

### ⚙️ Options

| Option | Meaning |
|--------|---------|
| `--port` | Port the honeypot listens on (default 2222) |
| `--accept weak` | Let in only common weak logins (default) |
| `--accept all` | Let everyone into the fake shell |
| `--accept none` | Deny everything, just collect passwords |
| `--db` | Database file (default `honeypot.db`) |

## 🔔 Alerts (optional)

Set these environment variables before starting `honeypot.py` (PowerShell example):

```powershell
$env:DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
# or Telegram:
$env:TELEGRAM_BOT_TOKEN = "123456:ABC..."
$env:TELEGRAM_CHAT_ID = "your_chat_id"
python honeypot.py --port 2222
```

You get a message when an attacker types `wget`, `curl` or a URL. Alerts are rate-limited (1 per 5 seconds).

## 📄 Make your report

```bash
python report.py            # writes report.md from honeypot.db
```

URLs in the report are **defanged** (`hxxp://evil[.]com`) so nobody clicks them by accident.

## 🗺️ GeoIP privacy note

The dashboard looks up attacker IPs on the free `ip-api.com` service (cached, ~45 lookups/min).
Local/private IPs are never sent. Turn it off with `python dashboard.py --no-geo`.

## 🌐 Public dashboard (safe mode)

The normal dashboard shows full IPs and passwords, so keep it private (SSH tunnel).
To share a live view, run the **public mode**:

```bash
python dashboard.py --public --no-geo --port 8080
```

Public mode:
- 🙈 masks source IPs (`1.2.x.x`) and hides passwords
- 🔗 defangs URLs in commands (`hxxp://evil[.]com`)
- 🚦 rate-limits visitors (60 requests/min per IP) and caches results for 5s
- 🛡️ sends strict security headers (CSP, no framing)
- Read-only: there is no way to change anything from the page

Run the private one (`127.0.0.1:8765`) and public one (`0.0.0.0:8080`) side by side.

## 🌍 Want real attackers?

Run it on a cheap VPS and forward public port **22 → 2222** (after moving your real SSH to another port).
Bots usually show up within hours. 📈

## 🧠 Beginner cheat sheet

- **Port 22** is the normal SSH port. Bots scan it constantly.
- **Brute force** = trying lots of passwords automatically.
- **Honeypot** = a trap system. Anything that touches it is suspicious by definition.
- **SQLite** = a database stored in a single file, no server needed.

## 📖 What I learned building this

- How the SSH protocol handshake and auth flow work (via `paramiko`) 🔬
- Handling many connections with threads 🧵
- Logging to SQLite safely from multiple threads 🗄️
- Why you must never trust attacker-controlled text (XSS!) ⚠️

## ⚠️ Limitations (v0.1)

- Fake shell only knows a handful of commands
- GeoIP is country-level only (no map yet)
- MITRE tags are simple regex heuristics
- Only password auth is logged (no key auth)
- Tested locally; real-world behavior may surprise me 🐛

## 🗺️ Roadmap

- [x] GeoIP country stats 🗺️ (world map still to do)
- [x] MITRE ATT&CK tagging
- [x] Discord / Telegram alerts
- [x] Markdown report generator
- [ ] Log SSH public keys that bots try
- [ ] Save files attackers try to download (in a safe sandbox)
- [ ] Export reports to CSV/JSON
- [ ] Docker image 🐳

## 📄 License

MIT
