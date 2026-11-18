#!/usr/bin/env python3
"""
report.py - turn honeypot.db into a Markdown report for your write-up.

Run:   python report.py                 -> report.md
       python report.py --db honeypot.db --out my_report.md
"""
import argparse, datetime as dt, re, sqlite3
import mitre


def defang(url):
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def bar(n, mx, width=30):
    return "#" * max(1, round(width * n / mx)) if mx else ""


def table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |")
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="honeypot.db")
    p.add_argument("--out", default="report.md")
    a = p.parse_args()
    con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    q = lambda sql, args=(): con.execute(sql, args).fetchall()

    total = q("SELECT COUNT(*) FROM attempts")[0][0]
    if not total:
        raise SystemExit("No data in the database yet.")
    first, last = q("SELECT MIN(ts), MAX(ts) FROM attempts")[0]
    days = max(1, (last - first) / 86400)
    fmt = lambda t: dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
    ips = q("SELECT COUNT(DISTINCT ip) FROM attempts")[0][0]
    accepted = q("SELECT COUNT(*) FROM attempts WHERE accepted=1")[0][0]
    cmds = q("SELECT ts, ip, username, command FROM commands ORDER BY id")

    L = [f"# Honeypot report", "",
         f"Period: **{fmt(first)}** to **{fmt(last)}** ({days:.1f} days)", "",
         "## Summary", "",
         f"- Login attempts: **{total}** (about {total / days:.0f} per day)",
         f"- Unique source IPs: **{ips}**",
         f"- Logins accepted into the fake shell: **{accepted}**",
         f"- Commands typed in the fake shell: **{len(cmds)}**", ""]

    L += ["## Top usernames", "", table(q("SELECT username,COUNT(*) FROM attempts GROUP BY 1 ORDER BY 2 DESC LIMIT 10"), ["username", "attempts"]), ""]
    L += ["## Top passwords", "", table(q("SELECT password,COUNT(*) FROM attempts GROUP BY 1 ORDER BY 2 DESC LIMIT 10"), ["password", "attempts"]), ""]
    L += ["## Top source IPs", "", table(q("SELECT ip,COUNT(*) FROM attempts GROUP BY 1 ORDER BY 2 DESC LIMIT 10"), ["ip", "attempts"]), ""]
    L += ["## Top SSH client versions", "", table(q("SELECT client,COUNT(*) FROM attempts GROUP BY 1 ORDER BY 2 DESC LIMIT 8"), ["client", "attempts"]), ""]

    try:
        rows = q("SELECT g.country,COUNT(*) c FROM attempts a JOIN geo g ON a.ip=g.ip GROUP BY 1 ORDER BY c DESC LIMIT 10")
        if rows:
            L += ["## Top countries (by IP geolocation)", "", table(rows, ["country", "attempts"]), ""]
    except sqlite3.Error:
        pass

    # MITRE ATT&CK
    tech, tactic_of = {}, {}
    for _, _, _, c in cmds:
        for tid, name, tactic in mitre.classify(c):
            tech[(tid, name)] = tech.get((tid, name), 0) + 1
            tactic_of[(tid, name)] = tactic
    tech[(mitre.BRUTE[0], mitre.BRUTE[1])] = total
    tactic_of[(mitre.BRUTE[0], mitre.BRUTE[1])] = mitre.BRUTE[2]
    rows = [(t, n, tactic_of[(t, n)], c) for (t, n), c in sorted(tech.items(), key=lambda kv: -kv[1])]
    L += ["## MITRE ATT&CK techniques observed", "",
          "Heuristic mapping of commands; treat as a guide, not a verdict.", "",
          table(rows, ["id", "technique", "tactic", "count"]), ""]

    # Download attempts (defanged!)
    urls = {}
    for _, ip, _, c in cmds:
        for u in re.findall(r"https?://[^\s'\"|;&]+", c):
            urls.setdefault(u, set()).add(ip)
    if urls:
        L += ["## Download attempts (URLs defanged, do not open them)", "",
              table([(defang(u), len(v)) for u, v in sorted(urls.items(), key=lambda kv: -len(kv[1]))[:20]],
                    ["url", "distinct IPs"]), ""]

    top_cmds = q("SELECT command,COUNT(*) FROM commands GROUP BY 1 ORDER BY 2 DESC LIMIT 10")
    if top_cmds:
        L += ["## Most common commands", "", table(top_cmds, ["command", "count"]), ""]

    daily = q("SELECT date(ts,'unixepoch','localtime') d, COUNT(*) FROM attempts GROUP BY d ORDER BY d")
    mx = max(c for _, c in daily)
    L += ["## Attempts per day", "", "```"] + [f"{d}  {bar(c, mx):<30} {c}" for d, c in daily] + ["```", ""]

    open(a.out, "w", encoding="utf-8").write("\n".join(L))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
