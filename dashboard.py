#!/usr/bin/env python3
"""
dashboard.py - live web dashboard for honeypot.db (stdlib only).

Run:   python dashboard.py --port 8765      then open http://127.0.0.1:8765
Keep it on 127.0.0.1 unless you really know what you are doing.
"""
import argparse, json, re, sqlite3, threading, time
import geo, mitre
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = "honeypot.db"
PUBLIC = False

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Honeypot Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--acc:#58a6ff;--bad:#f85149;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 ui-monospace,Consolas,monospace;padding:20px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--dim);margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;overflow:hidden}
.card h2{font-size:13px;color:var(--dim);margin:0 0 10px;text-transform:uppercase;letter-spacing:.06em}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
.big{font-size:28px;color:var(--acc)}.lbl{color:var(--dim);font-size:12px}
.row{display:flex;align-items:center;gap:8px;margin:4px 0}
.name{flex:0 0 40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{flex:1;background:#21262d;height:10px;border-radius:5px;overflow:hidden}.fill{height:100%;background:var(--acc)}
.cnt{flex:0 0 40px;text-align:right;color:var(--dim)}
.line{padding:3px 0;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.t{color:var(--dim)}.bad{color:var(--bad)}.ok{color:var(--ok)}
.hours{display:flex;align-items:flex-end;gap:3px;height:90px}.hours div{flex:1;background:var(--acc);min-height:2px;border-radius:2px 2px 0 0}
@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<h1>🍯 SSH Honeypot Dashboard</h1><div class="sub">auto-refreshes every 5s &middot; <span id="upd"></span></div>
<div class="stats">
 <div class="card"><div class="big" id="total">0</div><div class="lbl">login attempts</div></div>
 <div class="card"><div class="big" id="ips">0</div><div class="lbl">unique IPs</div></div>
 <div class="card"><div class="big" id="acc">0</div><div class="lbl">let into fake shell</div></div>
 <div class="card"><div class="big" id="cmds">0</div><div class="lbl">commands typed</div></div>
</div>
<div class="grid">
 <div class="card"><h2>Top usernames</h2><div id="users"></div></div>
 <div class="card"><h2>Top passwords</h2><div id="pws"></div></div>
 <div class="card"><h2>Top source IPs</h2><div id="topips"></div></div>
 <div class="card"><h2>Top countries</h2><div id="countries"></div></div>
 <div class="card"><h2>MITRE ATT&amp;CK techniques</h2><div id="mitre"></div></div>
 <div class="card"><h2>Attempts, last 24h (oldest &rarr; newest)</h2><div class="hours" id="hours"></div></div>
 <div class="card"><h2>Recent commands</h2><div id="rcmds"></div></div>
 <div class="card"><h2>Recent logins</h2><div id="ratt"></div></div>
</div>
<script>
// Attacker-controlled text is ALWAYS inserted with textContent (never innerHTML) to avoid XSS.
const $=id=>document.getElementById(id);
function bars(id,rows){const el=$(id);el.textContent="";const max=Math.max(1,...rows.map(r=>r[1]));
 rows.forEach(r=>{const d=document.createElement("div");d.className="row";
  const n=document.createElement("span");n.className="name";n.textContent=r[0]===""?"(empty)":r[0];n.title=n.textContent;
  const b=document.createElement("span");b.className="bar";const f=document.createElement("span");f.className="fill";f.style.display="block";f.style.width=(100*r[1]/max)+"%";b.appendChild(f);
  const c=document.createElement("span");c.className="cnt";c.textContent=r[1];d.append(n,b,c);el.appendChild(d);});}
function lines(id,rows){const el=$(id);el.textContent="";rows.forEach(txt=>{const d=document.createElement("div");d.className="line";
 const t=document.createElement("span");t.className="t";t.textContent=txt[0]+" ";const m=document.createElement("span");if(txt[2])m.className=txt[2];m.textContent=txt[1];d.append(t,m);el.appendChild(d);});}
const hm=ts=>new Date(ts*1000).toLocaleTimeString();
async function tick(){try{const s=await (await fetch("/api/stats")).json();
 $("total").textContent=s.total;$("ips").textContent=s.unique_ips;$("acc").textContent=s.accepted;$("cmds").textContent=s.commands;
 bars("users",s.top_users);bars("pws",s.top_passwords);bars("topips",s.top_ips);bars("countries",s.countries);bars("mitre",s.mitre);
 const h=$("hours");h.textContent="";const buckets=Array(24).fill(0);s.hourly.forEach(r=>{if(r[0]>=0&&r[0]<24)buckets[23-r[0]]=r[1]});
 const mx=Math.max(1,...buckets);buckets.forEach(v=>{const d=document.createElement("div");d.style.height=(100*v/mx)+"%";d.title=v+" attempts";h.appendChild(d)});
 lines("rcmds",s.recent_commands.map(r=>[hm(r[0]),r[1]+" "+r[2]+"$ "+r[3]]));
 lines("ratt",s.recent_attempts.map(r=>[hm(r[0]),r[1]+"  "+r[2]+" : "+r[3]+(r[4]?"  ACCEPTED":""),r[4]?"ok":""]));
 $("upd").textContent="updated "+new Date().toLocaleTimeString();}catch(e){$("upd").textContent="waiting for data...";}}
tick();setInterval(tick,5000);
</script></body></html>"""


PUBLIC_PAGE = PAGE.replace(
    '<div class="sub">auto-refreshes every 5s',
    '<div class="sub">PUBLIC read-only view: IPs masked, passwords hidden &middot; auto-refreshes every 5s', 1)


# ---------- public-mode sanitising ----------
def mask_ip(ip):
    if ":" in ip:
        return ":".join(ip.split(":")[:2]) + "::x"
    p = ip.split(".")
    return ".".join(p[:2] + ["x", "x"]) if len(p) == 4 else "x"


def defang_text(text):
    text = re.sub(r"https?://\S+", lambda m: m.group().replace("http", "hxxp", 1).replace(".", "[.]"), text)
    return re.sub(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", r"\1[.]\2[.]\3[.]\4", text)


def sanitize(s):
    s = dict(s)
    s["top_ips"] = [[mask_ip(r[0]), r[1]] for r in s["top_ips"]]
    s["top_passwords"] = [r for r in s["top_passwords"] if r[1] >= 2]   # hide one-off passwords
    s["recent_commands"] = [[r[0], mask_ip(r[1]), r[2], defang_text(r[3])] for r in s["recent_commands"]]
    s["recent_attempts"] = [[r[0], mask_ip(r[1]), r[2], "***", r[4]] for r in s["recent_attempts"]]
    return s


_cache = {"t": 0.0, "v": None}
_cache_lock = threading.Lock()
_hits = {}
_hits_lock = threading.Lock()


def allow(ip, limit=60, window=60):
    """Tiny per-IP rate limit for public mode."""
    now = time.time()
    with _hits_lock:
        recent = [t for t in _hits.get(ip, []) if now - t < window]
        if len(recent) >= limit:
            _hits[ip] = recent
            return False
        recent.append(now)
        _hits[ip] = recent
        if len(_hits) > 5000:
            _hits.clear()
        return True


def stats():
    """Cached for 5s so many visitors can't hammer the database."""
    with _cache_lock:
        if _cache["v"] is None or time.time() - _cache["t"] > 5:
            s = _stats()
            _cache["v"] = sanitize(s) if PUBLIC else s
            _cache["t"] = time.time()
        return _cache["v"]


def _stats():
    empty = dict(total=0, unique_ips=0, accepted=0, commands=0, top_users=[], top_passwords=[],
                 top_ips=[], recent_commands=[], recent_attempts=[], hourly=[], countries=[], mitre=[])
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    except sqlite3.Error:
        return empty
    try:
        q = lambda sql, a=(): [list(r) for r in con.execute(sql, a).fetchall()]
        now = time.time()
        try:
            countries = q("SELECT g.country,COUNT(*) c FROM attempts a JOIN geo g ON a.ip=g.ip "
                          "GROUP BY g.country ORDER BY c DESC LIMIT 10")
        except sqlite3.Error:
            countries = []  # geo table not created yet
        counts = {}
        for (cmd,) in con.execute("SELECT command FROM commands ORDER BY id DESC LIMIT 5000"):
            for tid, name, _tactic in mitre.classify(cmd):
                counts[f"{tid} {name}"] = counts.get(f"{tid} {name}", 0) + 1
        total_attempts = q("SELECT COUNT(*) FROM attempts")[0][0]
        if total_attempts:
            counts[f"{mitre.BRUTE[0]} {mitre.BRUTE[1]}"] = total_attempts
        mitre_rows = [[k, v] for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:10]]
        return {
            "countries": countries,
            "mitre": mitre_rows,
            "total": total_attempts,
            "unique_ips": q("SELECT COUNT(DISTINCT ip) FROM attempts")[0][0],
            "accepted": q("SELECT COUNT(*) FROM attempts WHERE accepted=1")[0][0],
            "commands": q("SELECT COUNT(*) FROM commands")[0][0],
            "top_users": q("SELECT username,COUNT(*) c FROM attempts GROUP BY username ORDER BY c DESC LIMIT 10"),
            "top_passwords": q("SELECT password,COUNT(*) c FROM attempts GROUP BY password ORDER BY c DESC LIMIT 10"),
            "top_ips": q("SELECT ip,COUNT(*) c FROM attempts GROUP BY ip ORDER BY c DESC LIMIT 10"),
            "recent_commands": q("SELECT ts,ip,username,command FROM commands ORDER BY id DESC LIMIT 15"),
            "recent_attempts": q("SELECT ts,ip,username,password,accepted FROM attempts ORDER BY id DESC LIMIT 15"),
            "hourly": q("SELECT CAST((?-ts)/3600 AS INT) h, COUNT(*) FROM attempts WHERE ts>? GROUP BY h",
                        (now, now - 86400)),
        }
    except sqlite3.Error:
        return empty
    finally:
        con.close()


class Handler(BaseHTTPRequestHandler):
    timeout = 10  # drop slow clients

    def do_GET(self):
        if PUBLIC and not allow(self.client_address[0]):
            self.send_error(429)
            return
        if self.path == "/api/stats":
            body, ctype = json.dumps(stats()).encode(), "application/json"
        elif self.path in ("/", "/index.html"):
            body, ctype = (PUBLIC_PAGE if PUBLIC else PAGE).encode(), "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def geo_worker():
    while True:
        try:
            geo.resolve_pending(DB, limit=20)
        except Exception:
            pass
        time.sleep(30)


def main():
    global DB, PUBLIC
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=DB)
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-geo", action="store_true", help="never send IPs to ip-api.com")
    p.add_argument("--public", action="store_true",
                   help="safe public mode: masks IPs, hides passwords, rate-limits, listens on 0.0.0.0")
    a = p.parse_args()
    DB = a.db
    PUBLIC = a.public
    a.host = a.host or ("0.0.0.0" if a.public else "127.0.0.1")
    if not a.no_geo:
        threading.Thread(target=geo_worker, daemon=True).start()
    print(f"[*] dashboard on http://{a.host}:{a.port}  (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()
