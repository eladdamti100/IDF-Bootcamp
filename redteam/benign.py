"""Realistic benign background commands.

The benign noise must look like a real dev/ops/CI host so the 20 malicious
rows don't stand out. Commands are parameterized over the *same* context
(users, paths) used by the malicious chain, so style/paths match.
"""

from __future__ import annotations

import random

# Each entry: (process_name, command_line_template). Templates may use the
# shared context placeholders (e.g. {luser}, {lhome}) so benign and malicious
# rows share an environment. {svc}, {pkg}, {repo}, {branch}, {n} are filled
# per-row from the small vocab below.
_LINUX = [
    ("bash", "ls -la {lhome}"),
    ("bash", "cd {lhome}/{repo} && ls"),
    ("git", "git pull origin {branch}"),
    ("git", "git status"),
    ("git", "git log --oneline -n 10"),
    ("git", "git checkout {branch}"),
    ("git", "git commit -am 'fix: {svc} retry logic'"),
    ("npm", "npm ci --no-audit"),
    ("npm", "npm run build"),
    ("npm", "npm test -- --runInBand"),
    ("python3", "python3 /opt/app/manage.py migrate"),
    ("python3", "python3 -m pytest tests/ -q"),
    ("pip3", "pip3 install -r requirements.txt"),
    ("docker", "docker ps -a"),
    ("docker", "docker build -t {svc}:{n} ."),
    ("docker", "docker compose up -d {svc}"),
    ("docker", "docker logs --tail 100 {svc}"),
    ("kubectl", "kubectl get pods -n production"),
    ("kubectl", "kubectl rollout status deploy/{svc}"),
    ("kubectl", "kubectl logs deploy/{svc} --tail 50"),
    ("systemctl", "systemctl status {svc}"),
    ("systemctl", "systemctl restart {svc}"),
    ("journalctl", "journalctl -u {svc} --since '10 min ago'"),
    ("apt-get", "apt-get install -y {pkg}"),
    ("tar", "tar czf /backups/{svc}-{n}.tgz /var/lib/{svc}"),
    ("curl", "curl -s http://localhost:8080/health"),
    ("curl", "curl -fsS https://api.github.com/repos/{repo}/commits | head"),
    ("psql", "psql -h db -U {luser} -c 'SELECT count(*) FROM orders;'"),
    ("redis-cli", "redis-cli ping"),
    ("grep", "grep -r 'TODO' {lhome}/{repo}/src"),
    ("find", "find {lhome}/{repo} -name '*.log' -mtime +7"),
    ("ssh", "ssh {luser}@build-{n} uptime"),
    ("scp", "scp report.csv {luser}@reports:/srv/reports/"),
    ("rsync", "rsync -az {lhome}/{repo}/dist/ /var/www/{svc}/"),
    ("make", "make lint"),
    ("go", "go build ./..."),
    ("node", "node scripts/seed.js"),
    ("aws", "aws s3 ls s3://{svc}-artifacts/"),
    ("terraform", "terraform plan -out tfplan"),
    ("htop", "htop -d 5"),
    ("df", "df -h"),
    ("free", "free -m"),
    ("uptime", "uptime"),
    ("ps", "ps aux --sort=-%mem | head"),
]

_WINDOWS = [
    ("powershell.exe", "Get-ChildItem C:\\Users\\{wuser}\\Documents"),
    ("powershell.exe", "Get-Service | Where-Object Status -eq Running"),
    ("powershell.exe", "Get-Process | Sort-Object CPU -Descending | Select -First 10"),
    ("powershell.exe", "Test-Connection -Count 2 db-{n}"),
    ("powershell.exe", "Get-EventLog -LogName Application -Newest 20"),
    ("powershell.exe", "Restart-Service -Name {svc}"),
    ("git.exe", "git pull origin {branch}"),
    ("git.exe", "git status"),
    ("git.exe", "git commit -am 'chore: bump {pkg}'"),
    ("dotnet.exe", "dotnet build {repo}.sln -c Release"),
    ("dotnet.exe", "dotnet test"),
    ("msbuild.exe", "msbuild /t:Rebuild /p:Configuration=Release"),
    ("docker.exe", "docker ps -a"),
    ("docker.exe", "docker build -t {svc}:{n} ."),
    ("kubectl.exe", "kubectl get pods -n production"),
    ("sqlcmd.exe", "sqlcmd -S db -d {svc} -Q \"SELECT COUNT(*) FROM dbo.Orders\""),
    ("choco.exe", "choco install {pkg} -y"),
    ("nuget.exe", "nuget restore {repo}.sln"),
    ("net.exe", "net use Z: \\\\fileserver\\share"),
    ("ipconfig.exe", "ipconfig /all"),
    ("tasklist.exe", "tasklist /fo table"),
    ("sc.exe", "sc query {svc}"),
    ("robocopy.exe", "robocopy C:\\build\\dist \\\\web\\{svc} /MIR /NFL"),
    ("curl.exe", "curl.exe -s http://localhost:5000/health"),
    ("python.exe", "python -m pytest tests\\ -q"),
    ("pip.exe", "pip install -r requirements.txt"),
    ("explorer.exe", "explorer C:\\Users\\{wuser}\\Downloads"),
    ("where.exe", "where python"),
    ("systeminfo.exe", "systeminfo"),
]

_SVCS = ["nginx", "api-gateway", "payments", "auth-svc", "worker", "redis", "postgres", "search"]
_PKGS = ["jq", "htop", "ripgrep", "nodejs", "openjdk-17-jdk", "python3-pip", "git-lfs"]
_REPOS = ["web-app", "platform", "billing-service", "infra", "data-pipeline", "mobile-api"]
_BRANCHES = ["main", "develop", "release/2.4", "feature/checkout", "hotfix/login"]


def generate(os_name: str, ctx: dict[str, str], count: int, seed: int) -> list[dict]:
    """Produce ``count`` benign rows, deterministically for a given seed."""
    rng = random.Random(seed ^ 0xBE19)
    pool = _LINUX if os_name == "linux" else _WINDOWS
    rows: list[dict] = []
    seen: set[str] = set()
    attempts = 0
    while len(rows) < count and attempts < count * 50:
        attempts += 1
        proc, tmpl = rng.choice(pool)
        fields = dict(ctx)
        fields.update(
            svc=rng.choice(_SVCS),
            pkg=rng.choice(_PKGS),
            repo=rng.choice(_REPOS),
            branch=rng.choice(_BRANCHES),
            n=rng.randint(1, 99),
        )
        cmd = tmpl.format(**fields)
        if cmd in seen:
            continue
        seen.add(cmd)
        rows.append({
            "process_name": proc,
            "command_line": cmd,
            "label": "benign",
            "phase": "",
            "rationale": "",
        })
    return rows
