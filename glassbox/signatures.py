"""Layer 1 — curated high-confidence signatures + benign allowlist + MITRE map.

Signatures run on the NORMALIZED text (so obfuscation is already stripped).
Each maps directly to a MITRE technique+tactic, which the story engine reuses.
LOLBin names are a WEAK feature only (admins use them) — never an auto-flag.

MITRE map curated from the high-signal techniques in the brief; extend freely.
The runtime stays offline (no network) for speed + reliability.
"""
import re

# kill-chain order (MITRE ATT&CK enterprise tactics, attack progression)
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

# (name, regex, technique_id, technique_name, tactic, base_score)
# base_score ~0.9+ => confident malicious. Compiled case-insensitive.
_SIG_DEFS = [
    # --- Impact / ransomware ---
    (r"vssadmin\s+delete\s+shadows", "T1490", "Inhibit System Recovery", "Impact", 0.97),
    (r"wmic\s+shadowcopy\s+delete", "T1490", "Inhibit System Recovery", "Impact", 0.97),
    (r"bcdedit\s+/set\s+\{?default\}?\s+recoveryenabled\s+no", "T1490", "Inhibit System Recovery", "Impact", 0.95),
    (r"cipher\s+/w:", "T1485", "Data Destruction", "Impact", 0.9),
    # --- Impact / crypto miner ---
    (r"xmrig|--donate-level|stratum\+tcp|minexmr|pool\.\S+:\d+", "T1496", "Resource Hijacking", "Impact", 0.95),
    # --- Credential Access ---
    (r"comsvcs\.dll.*minidump", "T1003.001", "LSASS Memory", "Credential Access", 0.97),
    (r"reg\s+save\s+hklm\\sam", "T1003.002", "Security Account Manager", "Credential Access", 0.95),
    (r"mimikatz|sekurlsa::logonpasswords", "T1003", "OS Credential Dumping", "Credential Access", 0.97),
    (r"cat\s+/etc/shadow", "T1003.008", "/etc/passwd and /etc/shadow", "Credential Access", 0.9),
    (r"cp\s+~?/?\.?\S*\.aws/credentials", "T1552.001", "Credentials In Files", "Credential Access", 0.88),
    # --- Execution (encoded/fileless) ---
    (r"-e(nc(odedcommand)?|c)\s+[a-z0-9+/=]{20,}", "T1059.001", "PowerShell", "Execution", 0.92),
    (r"iex\s*\(.*downloadstring", "T1059.001", "PowerShell", "Execution", 0.93),
    (r"new-object\s+net\.webclient", "T1059.001", "PowerShell", "Execution", 0.85),
    (r"certutil(\.exe)?.*-urlcache.*-f|certutil(\.exe)?.*-decode", "T1105", "Ingress Tool Transfer", "Command and Control", 0.9),
    (r"mshta(\.exe)?\s+(javascript:|vbscript:|http)", "T1218.005", "Mshta", "Defense Evasion", 0.9),
    (r"regsvr32(\.exe)?.*scrobj\.dll|regsvr32(\.exe)?\s+/i:http", "T1218.010", "Regsvr32", "Defense Evasion", 0.9),
    (r"rundll32(\.exe)?\s+javascript:", "T1218.011", "Rundll32", "Defense Evasion", 0.88),
    (r"(bash|sh)\s+-c\s+[\"']?\$\(\s*(curl|wget)", "T1059.004", "Unix Shell", "Execution", 0.9),
    (r"(curl|wget)\s+\S+\s*\|\s*(sh|bash|python3?)", "T1059.004", "Unix Shell", "Execution", 0.9),
    (r"python3?\s+-c\s+['\"]?import\s+os.*system", "T1059.006", "Python", "Execution", 0.85),
    # --- Persistence ---
    (r"schtasks\s+/create", "T1053.005", "Scheduled Task", "Persistence", 0.85),
    (r"reg\s+add\s+hk(cu|lm)\\software\\microsoft\\windows\\currentversion\\run", "T1547.001", "Registry Run Keys", "Persistence", 0.88),
    (r"new-service\s+-name", "T1543.003", "Windows Service", "Persistence", 0.82),
    (r"crontab\s+-|/etc/cron", "T1053.003", "Cron", "Persistence", 0.8),
    (r">>\s*~?/?\.bashrc|>>\s*~?/?\.ssh/authorized_keys", "T1546.004|T1098.004", "Unix Shell Config / SSH Keys", "Persistence", 0.85),
    (r"systemctl\s+enable\s+\S+\.service", "T1543.002", "Systemd Service", "Persistence", 0.72),
    (r"/dev/tcp/\d", "T1059", "Reverse Shell", "Execution", 0.9),
    (r"nc(\.exe)?\s+.*-e\s+(/bin/(ba)?sh|cmd)", "T1059", "Netcat Reverse Shell", "Execution", 0.9),
    # --- Privilege Escalation ---
    (r"fodhelper(\.exe)?", "T1548.002", "Bypass UAC (fodhelper)", "Privilege Escalation", 0.85),
    (r"reg\s+add\s+hkcu\\software\\classes\\ms-settings", "T1548.002", "Bypass UAC", "Privilege Escalation", 0.85),
    (r"find\s+/\s+-perm\s+-4000", "T1548.001", "SUID Hunt", "Privilege Escalation", 0.7),
    (r"chmod\s+u\+s\s+/bin", "T1548.001", "SUID Abuse", "Privilege Escalation", 0.82),
    # --- Defense Evasion ---
    (r"set-mppreference\s+-disablerealtimemonitoring", "T1562.001", "Disable AV", "Defense Evasion", 0.93),
    (r"wevtutil\s+cl|clear-eventlog", "T1070.001", "Clear Windows Event Logs", "Defense Evasion", 0.9),
    (r"history\s+-c|export\s+histfile=/dev/null", "T1070.003", "Clear Command History", "Defense Evasion", 0.82),
    (r"rm\s+-rf\s+/var/log", "T1070.002", "Clear Linux Logs", "Defense Evasion", 0.85),
    (r"chattr\s+\+i\s+/etc/passwd", "T1222.002", "Linux File Permissions", "Defense Evasion", 0.8),
    # --- Lateral Movement ---
    (r"psexec(\.exe)?\s+\\\\", "T1021.002", "SMB/PsExec", "Lateral Movement", 0.9),
    (r"wmic\s+/node:\S+\s+process\s+call\s+create", "T1047", "WMI Lateral", "Lateral Movement", 0.9),
    (r"enter-pssession\s+-computername", "T1021.006", "WinRM/PSRemoting", "Lateral Movement", 0.85),
    (r"ssh\s+-o\s+stricthostkeychecking=no\s+\S+\s+['\"].*(curl|wget|sh)", "T1021.004", "SSH Lateral", "Lateral Movement", 0.85),
    # --- Collection / Exfiltration ---
    (r"compress-archive\s+-path", "T1560.001", "Archive Collected Data", "Collection", 0.7),
    (r"tar\s+c?z?f\s+\S+\s+/home", "T1560.001", "Archive Collected Data", "Collection", 0.68),
    (r"invoke-webrequest.*-method\s+post.*-infile|invoke-restmethod.*-infile", "T1041", "Exfil Over C2", "Exfiltration", 0.85),
    (r"curl\s+.*-f\s+['\"]?\w+=@|curl\s+--upload-file", "T1041", "Exfil Over HTTP", "Exfiltration", 0.82),
    (r"rclone\s+copy\s+\S+\s+\S+:", "T1567.002", "Exfil to Cloud", "Exfiltration", 0.85),
]

SIGNATURES = [
    (re.compile(rx, re.I), tid, tname, tac, sc)
    for (rx, tid, tname, tac, sc) in _SIG_DEFS
]

# Discovery commands: individually benign-looking. Density+sequence is the signal,
# so these are tagged but NOT auto-flagged — they get a cross-row density boost.
DISCOVERY = re.compile(
    r"\b(whoami|net\s+user|net\s+group|net\s+localgroup|systeminfo|tasklist|nltest|"
    r"\bid\b|uname\s+-a|hostname|ps\s+aux|ps\s+-ef|netstat|ss\s+-|ifconfig|ip\s+a\b|"
    r"arp\s+-a|cat\s+/etc/passwd|env\b|printenv|sudo\s+-l)\b", re.I)
DISCOVERY_TECH = ("T1087/T1082/T1057", "System/Account/Process Discovery", "Discovery")

# LOLBin names — WEAK feature only (admins use these). Never auto-flag.
LOLBINS = re.compile(
    r"\b(certutil|mshta|rundll32|regsvr32|bitsadmin|wmic|vssadmin|msbuild|"
    r"installutil|cscript|wscript|curl|wget|tar|dd|nc|ncat|awk|xxd|base64)\b", re.I)

# Benign allowlist: the WHOLE command must look like a known-good template.
# Used to actively SUPPRESS false positives. Combined with: low entropy + not obfuscated.
BENIGN_ALLOW = [
    re.compile(p, re.I) for p in [
        r"^(sudo\s+)?apt(-get)?\s+(update|upgrade|install|list)\b",
        r"^(sudo\s+)?yum\s+(install|update)\b",
        r"^git\s+(pull|clone|push|status|commit|fetch|checkout|add|log|diff)\b",
        r"^kubectl\s+(get|describe|logs|apply|rollout)\b",
        r"^docker\s+(ps|images|build|pull|logs|compose)\b",
        r"^(npm|yarn|pnpm)\s+(install|run|ci|test|build)\b",
        r"^pip3?\s+install\b",
        r"^(ls|cd|pwd|cat|echo|mkdir|cp|mv|touch|grep|less|tail|head)\b.{0,80}$",
        r"^systemctl\s+(status|restart|start|stop)\b",
        r"^terraform\s+(plan|apply|init|validate)\b",
        r"^brew\s+(install|update|upgrade)\b",
        r"^python3?\s+\S+\.py\b",
        r"^node\s+\S+\.js\b",
        r"^make\b",
        r"^ssh\s+\S+@\S+$",
    ]
]


def match_signatures(norm_text: str):
    """Return list of (technique_id, technique_name, tactic, score) hits."""
    hits = []
    for rx, tid, tname, tac, sc in SIGNATURES:
        if rx.search(norm_text):
            hits.append((tid, tname, tac, sc))
    return hits


def is_allowlisted(norm_text: str) -> bool:
    return any(rx.search(norm_text) for rx in BENIGN_ALLOW)


def is_discovery(norm_text: str) -> bool:
    return bool(DISCOVERY.search(norm_text))


def has_lolbin(norm_text: str) -> bool:
    return bool(LOLBINS.search(norm_text))
