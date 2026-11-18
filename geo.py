"""
geo.py - IP -> country lookup with a local cache (stdlib only).

PRIVACY NOTE: this sends attacker IPs to the free ip-api.com service
(45 requests/min, non-commercial use). Disable with `dashboard.py --no-geo`.
Private/local IPs are never sent.
"""
import ipaddress, json, sqlite3, time, urllib.request

API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon"


def ensure_table(con):
    con.execute("""CREATE TABLE IF NOT EXISTS geo (
        ip TEXT PRIMARY KEY, country TEXT, code TEXT, city TEXT, lat REAL, lon REAL)""")
    con.commit()


def lookup(ip):
    with urllib.request.urlopen(API.format(ip=ip), timeout=8) as r:
        d = json.load(r)
    if d.get("status") != "success":
        return None
    return (d.get("country"), d.get("countryCode"), d.get("city"), d.get("lat"), d.get("lon"))


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def resolve_pending(db_path, limit=20, lookup_fn=lookup, delay=1.5):
    """Resolve up to `limit` IPs that are in attempts but not yet cached."""
    con = sqlite3.connect(db_path, timeout=10)
    try:
        ensure_table(con)
        ips = [r[0] for r in con.execute(
            "SELECT DISTINCT ip FROM attempts WHERE ip NOT IN (SELECT ip FROM geo) LIMIT ?", (limit * 3,))]
        done = 0
        for ip in ips:
            if done >= limit:
                break
            if not is_public(ip):
                con.execute("INSERT OR REPLACE INTO geo VALUES(?,?,?,?,?,?)", (ip, "Private/Local", "--", "", 0, 0))
                con.commit()
                continue
            try:
                res = lookup_fn(ip)
            except Exception:
                break  # network problem or rate limit; try again next round
            con.execute("INSERT OR REPLACE INTO geo VALUES(?,?,?,?,?,?)",
                        (ip, *(res or ("Unknown", "??", "", 0, 0))))
            con.commit()
            done += 1
            time.sleep(delay)
        return done
    finally:
        con.close()
