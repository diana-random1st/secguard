# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [0.5.0]

### Added

- **Strict block mode** for the Claude Code target. The hook now exits with code `2` on destructive verdicts instead of emitting a JSON `ask` response. Reason: Claude's `bypassPermissions` mode ignores hook JSON decisions but honours `exit(2)`, so the old behaviour left secguard toothless in accept-all mode. Toggle off with `strict_block = false` in `~/.config/secguard/config.toml` or `SECGUARD_STRICT=0` per-invocation. Codex and Gemini targets are unaffected.
- **User config file** at `~/.config/secguard/config.toml` (override path via `SECGUARD_CONFIG`). Recognised fields: `safe_kill_targets`, `safe_command_prefixes`, `strict_block`. Parse errors fall back to defaults with a stderr warning; never panics.
- **`secguard guard suggest`** subcommand. Reads `~/.secguard/telemetry.jsonl`, picks brain-only `destructive` verdicts (the false-positive candidates the deterministic rules didn't catch), groups by command prefix, prints the top-N with a paste-ready `safe_command_prefixes = [...]` block. Flags: `--top N` (default 20), `--min-count N` (default 3).

### Changed

- **Wider built-in policy allowlist** in `policy.rs`. Newly covered safe-by-policy commands:
  - `gws ` (Google Workspace CLI) — all subcommands.
  - `diana ` — all subcommands except those containing `rm `/`delete`.
  - `psql ` and `psql -` (DB client connections).
  - `terraform` read-only subcommands: `plan`, `show`, `output`, `validate`, `state list`, `state show`, `fmt`, `version`. Mutating subcommands (`apply`, `destroy`, `taint`, `import`) stay subject to heuristic + brain phases.
  - `brew` non-destructive subcommands: `install`, `upgrade`, `list`, `info`, `search`, `update`, `outdated`, `tap`, `leaves`. `uninstall` and `cleanup` are excluded.
  - Package-manager read/build/install subcommands for `cargo`, `npm`, `bun`, `yarn`, `pnpm`, `pip`, `uv`: `build`, `check`, `test`, `install`, `ci`, `add`, `sync`, `run`, `list`, `show`, `info`, `search`, `version`, `--help`. Destructive subcommands (`clean`, `uninstall`) are excluded.

### Compatibility

- Existing `~/.config/secguard/config.toml` files without `strict_block` get the new default (`true`). To preserve pre-0.5 UX explicitly, add `strict_block = false`.
- No changes to the destructive-verdict criteria — strict mode only changes *how* the block is delivered to Claude Code, not *what* is blocked.
