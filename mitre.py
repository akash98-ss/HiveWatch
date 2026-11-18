"""
mitre.py - map attacker commands to MITRE ATT&CK techniques (simple regex rules).
These are heuristics: a hint about attacker behaviour, not a verdict.
"""
import re

# (regex, technique id, technique name, tactic)
RULES = [
    (r"\b(wget|curl|tftp|ftpget)\b",                    "T1105",     "Ingress Tool Transfer",          "Command and Control"),
    (r"\|\s*(ba)?sh\b|\bsh\s+\S+\.sh\b|\bbash\s+-c\b",  "T1059.004", "Unix Shell",                     "Execution"),
    (r"\bchmod\b",                                      "T1222.002", "File Permissions Modification",  "Defense Evasion"),
    (r"\b(whoami|id|w|who|last)\b",                     "T1033",     "System Owner/User Discovery",    "Discovery"),
    (r"\b(uname|hostname|lscpu|nproc|free|uptime)\b|/proc/(cpuinfo|meminfo)|/etc/os-release",
                                                        "T1082",     "System Information Discovery",   "Discovery"),
    (r"/etc/passwd|\bgetent\s+passwd",                  "T1087.001", "Local Account Discovery",        "Discovery"),
    (r"\bps\b|\btop\b",                                 "T1057",     "Process Discovery",              "Discovery"),
    (r"\b(ifconfig|netstat|ss|route)\b|\bip\s+(a|addr|route)\b",
                                                        "T1016",     "System Network Configuration Discovery", "Discovery"),
    (r"\b(ls|find|locate|dir)\b",                       "T1083",     "File and Directory Discovery",   "Discovery"),
    (r"/etc/shadow",                                    "T1003.008", "/etc/passwd and /etc/shadow",    "Credential Access"),
    (r"authorized_keys|\.ssh/",                         "T1098.004", "SSH Authorized Keys",            "Persistence"),
    (r"\bcrontab\b|/etc/cron",                          "T1053.003", "Cron",                           "Persistence"),
    (r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0|\brm\s+-rf?\b", "T1070.003", "Clear Command History / Cleanup", "Defense Evasion"),
]
_COMPILED = [(re.compile(rx, re.I), tid, name, tactic) for rx, tid, name, tactic in RULES]
BRUTE = ("T1110.001", "Password Guessing", "Credential Access")


def classify(command):
    """Return a list of (technique_id, name, tactic) matched by one command line."""
    hits, seen = [], set()
    for rx, tid, name, tactic in _COMPILED:
        if rx.search(command) and tid not in seen:
            seen.add(tid)
            hits.append((tid, name, tactic))
    return hits


def is_download(command):
    return bool(re.search(r"\b(wget|curl|tftp|ftpget)\b|https?://", command, re.I))
