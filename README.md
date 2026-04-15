# secguard

3-level security guard for AI coding agents. Catches leaked credentials and blocks destructive shell commands before they execute.

Built for [Claude Code](https://claude.ai/code) hooks, works anywhere: CI pipelines, git pre-commit, standalone CLI.

## What it does

Two guards, three levels of detection each.

**Secrets scanning.** Catches credentials before they leak into logs, tool output, or cloud APIs. 68 regex patterns: AWS access keys (`AKIA*`), Stripe (`sk_live_*`, `pk_live_*`), GitHub PATs (`ghp_*`, `github_pat_*`), Anthropic/OpenAI API keys, Slack tokens, JWTs, private key blocks, database connection strings (postgres, mysql, mongodb, redis), SendGrid, Twilio, npm/PyPI tokens, generic `password=`/`secret=` assignments. Keyword pre-filter skips regex when no relevant substring exists (fast on large inputs). High-entropy token detection (Shannon entropy >= 3.5 bits/char, 16+ chars) picks up things regex misses. Optional ML classifier as final pass.

**Destructive command guard.** Blocks commands that delete data, rewrite history, or bypass safety checks. Three phases run in order; first match wins:

*Phase 0: Policy allowlist.* Some operations are always safe. Process management (`kill`, `pkill`), `git push` without `--force`, read-only kubectl (`get`, `describe`, `logs`), DB client connections (`psql`). Compound commands (`&&`, `||`, `;`, `|`) are split and every part must pass independently.

*Phase 1: Heuristic rules.* 40+ patterns, zero latency:
- Git: `checkout .`, `clean`, `reset --hard`, `push --force`, `branch -D`, `rebase`, `stash drop/clear`
- Filesystem: `rm -rf` (with configurable safe paths for build dirs), `rm -r`, `find -delete`, `shred`
- SQL: `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`
- Docker: `system prune`, `volume prune`
- Remote exec: `curl | bash`, `wget | sh`
- Hook bypass: `--no-verify`
- HTTP DELETE to non-localhost URLs (curl, httpie)
- SaaS CLIs (22 tools: aws, gcloud, stripe, firebase, vercel, netlify, heroku, fly, supabase, planetscale, etc.) with destructive subcommands (`delete`, `remove`, `destroy`, `purge`, `terminate`)
- GitHub CLI: only truly destructive ops (`gh repo delete`, `gh release delete`); `gh pr close` passes through

`rm -rf build`, `rm -rf node_modules`, `rm -rf target/debug` are safe by default. Configurable via `GuardConfig`.

*Phase 2: ML brain.* Qwen3.5-2B-Q8 GGUF model classifies commands the heuristics don't cover. Catches things like `terraform destroy -auto-approve`, `redis-cli FLUSHALL`, `ansible-playbook teardown.yml`. 85% confidence threshold. Optional; falls back to heuristic-only when absent.

## How to use it

Four modes, same binary.

**Claude Code hook** (`secguard init --global`). Registers as a PreToolUse hook. Guard checks every Bash command before execution; secrets-scan redacts credentials from Bash/Edit/Write/Agent/MCP tool input. Blocked commands get `permissionDecision: "ask"` so the user sees the warning and decides.

**Standalone CLI.** Pipe a command into `secguard guard`, pipe text into `secguard scan`. Exit code 0 = safe, 1 = problem found. Works in scripts, Makefiles, anywhere.

**Git pre-commit.** Run `secguard scan --dir .` in a pre-commit hook. Catches credentials before they reach the repo.

**CI/CD.** Same `secguard scan --dir ./src --format json` in your pipeline. JSON output includes file, line number, rule ID. Non-zero exit fails the build.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/diana-random1st/secguard/main/install.sh | sh
```

Detects OS/arch, downloads the right binary, installs to `/usr/local/bin`.

Or manually pick your platform:

```bash
# macOS Apple Silicon
curl -sL https://github.com/diana-random1st/secguard/releases/latest/download/secguard-aarch64-apple-darwin.tar.gz | tar xz
sudo mv secguard /usr/local/bin/

# macOS Intel
curl -sL https://github.com/diana-random1st/secguard/releases/latest/download/secguard-x86_64-apple-darwin.tar.gz | tar xz
sudo mv secguard /usr/local/bin/

# Linux x64
curl -sL https://github.com/diana-random1st/secguard/releases/latest/download/secguard-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv secguard /usr/local/bin/
```

From source:

```bash
cargo install --path crates/secguard-cli
```

## Setup for Claude Code

```bash
secguard init --global
```

Writes two PreToolUse hooks to `~/.claude/settings.json`:
- **guard** on Bash — checks commands before execution
- **secrets-scan** on Bash/Edit/Write/Agent/MCP — redacts credentials from tool input

If the ML model isn't installed, `init` will offer to download it.

Project-level install (without `--global`) writes to `.claude/settings.json` in the current directory.

## ML model (optional)

```bash
secguard model
```

Downloads `secguard-guard.gguf` (774MB, Qwen3.5-2B-Q8) from HuggingFace to `~/.secguard/models/`. The guard works fine without it; the model catches edge cases that heuristics don't cover.

## Standalone usage

```bash
# Check a command
echo "rm -rf /" | secguard guard
# exit 1: DESTRUCTIVE: rm -rf (recursive force delete)

echo "cargo test --all" | secguard guard
# exit 0: safe

# Scan for secrets
cat .env | secguard scan

# Scan a directory
secguard scan --dir ./src

# JSON output
secguard scan --dir ./src --format json
```

## Architecture

```
secguard-brain     GGUF inference engine (llama.cpp, optional Metal GPU)
secguard-secrets   68 regex patterns + entropy detection + ML fallback
secguard-guard     policy allowlist + 40 heuristic rules + ML classifier
secguard-cli       CLI binary, Claude Code hook protocol
```

Default build (`cargo install secguard-cli`) includes L1 (regex) and L2 (heuristic) only. Zero native dependencies.

For ML support: `cargo install secguard-cli --features ml,metal`

## Feature flags

| Flag | What it adds |
|------|-------------|
| `ml` | GGUF brain classifier for secrets + guard |
| `metal` | Apple Silicon GPU acceleration for inference |

## Author

Built by [@random1st](https://t.me/toxic_ai_random1st) — Telegram channel about AI agents, local models, and building tools that actually work.

## License

Apache 2.0 + Commons Clause — free to use, modify, fork; not for resale as a product or service.
