//! Self-update subcommand.
//!
//! Checks GitHub Releases for a newer tag and either prints status, writes a
//! marker for background checks, or downloads + atomically replaces the
//! current binary.
//!
//! State files under `~/.secguard/`:
//!   - `.update-last-check`  — unix timestamp of last check (hot-path throttle)
//!   - `.update-available`   — tag_name of a newer release, read by hook path
//!   - `.update-tmp/`        — scratch dir for the download+extract staging

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const GITHUB_API: &str =
    "https://api.github.com/repos/diana-random1st/secguard/releases/latest";
const USER_AGENT: &str = "secguard-cli";
pub const CHECK_INTERVAL_SECS: u64 = 7 * 86_400; // 7 days

pub fn cache_dir() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".secguard"))
}

fn detect_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        _ => None,
    }
}

fn version_tuple(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches('v');
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

fn is_newer(remote: &str, local: &str) -> bool {
    match (version_tuple(remote), version_tuple(local)) {
        (Some(r), Some(l)) => r > l,
        _ => false,
    }
}

struct LatestRelease {
    tag: String,
    asset_url: String,
}

fn fetch_latest() -> anyhow::Result<LatestRelease> {
    let out = Command::new("curl")
        .args([
            "-sfL",
            "-H",
            "Accept: application/vnd.github+json",
            "-A",
            USER_AGENT,
            GITHUB_API,
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("GitHub API fetch failed");
    }
    let body: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let tag = body
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no tag_name in release response"))?
        .to_string();
    let target = detect_target()
        .ok_or_else(|| anyhow::anyhow!("unsupported target for auto-update"))?;
    let asset_url = body
        .get("assets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("no assets array"))?
        .iter()
        .find(|a| {
            a.get("name")
                .and_then(|n| n.as_str())
                .map(|n| n.contains(target))
                .unwrap_or(false)
        })
        .and_then(|a| a.get("browser_download_url"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no release asset for target {target}"))?
        .to_string();
    Ok(LatestRelease { tag, asset_url })
}

/// Write the timestamp so the next check is throttled.
fn touch_last_check() {
    let Some(dir) = cache_dir() else { return };
    let _ = fs::create_dir_all(&dir);
    if let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let _ = fs::write(dir.join(".update-last-check"), d.as_secs().to_string());
    }
}

fn write_available_marker(tag: &str) -> anyhow::Result<()> {
    let dir = cache_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(".update-available"), tag)?;
    Ok(())
}

fn clear_available_marker() {
    if let Some(dir) = cache_dir() {
        let _ = fs::remove_file(dir.join(".update-available"));
    }
}

fn download_and_replace(asset_url: &str) -> anyhow::Result<()> {
    let current_exe = std::env::current_exe()?;
    let base_dir = cache_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    let tmp = base_dir.join(".update-tmp");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;

    let tar_path = tmp.join("release.tar.gz");
    let status = Command::new("curl")
        .args(["-fL", "-o"])
        .arg(&tar_path)
        .arg(asset_url)
        .status()?;
    if !status.success() {
        anyhow::bail!("download failed for {asset_url}");
    }

    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(&tar_path)
        .arg("-C")
        .arg(&tmp)
        .status()?;
    if !status.success() {
        anyhow::bail!("tar extract failed");
    }

    let extracted = tmp.join("secguard");
    if !extracted.exists() {
        anyhow::bail!("secguard binary not found in archive");
    }

    // Stage next to the current binary, then atomic rename. This handles the
    // "Text file busy" case on Linux where you cannot overwrite a running
    // executable with a plain copy — but rename(2) detaches the inode.
    let staged = sibling(&current_exe, ".new")?;
    fs::copy(&extracted, &staged)?;
    let mut perms = fs::metadata(&staged)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&staged, perms)?;
    fs::rename(&staged, &current_exe)?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(())
}

fn sibling(p: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let name = p
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("no file name: {}", p.display()))?
        .to_string_lossy();
    Ok(p.with_file_name(format!("{name}{suffix}")))
}

/// Run `secguard update` in its chosen mode.
pub fn run(check_only: bool, background: bool) -> anyhow::Result<()> {
    touch_last_check();

    let local = env!("CARGO_PKG_VERSION");
    let latest = match fetch_latest() {
        Ok(r) => r,
        Err(e) => {
            if background {
                return Ok(());
            }
            return Err(e);
        }
    };

    if !is_newer(&latest.tag, local) {
        if !background {
            eprintln!("secguard v{local} is up to date (latest: {})", latest.tag);
        }
        clear_available_marker();
        return Ok(());
    }

    if background {
        let _ = write_available_marker(&latest.tag);
        return Ok(());
    }

    if check_only {
        eprintln!(
            "secguard v{local} → {} available\n  {}",
            latest.tag, latest.asset_url
        );
        let _ = write_available_marker(&latest.tag);
        return Ok(());
    }

    eprintln!(
        "Updating secguard v{local} → {}\n  {}",
        latest.tag, latest.asset_url
    );
    download_and_replace(&latest.asset_url)?;
    clear_available_marker();
    eprintln!("Updated. New binary at {}", std::env::current_exe()?.display());
    Ok(())
}

/// Called from the hot hook path. Emits a single stderr line if a marker is
/// present. Microseconds of stat+read; zero network.
pub fn notify_if_available() {
    let Some(dir) = cache_dir() else { return };
    let marker = dir.join(".update-available");
    if let Ok(tag) = fs::read_to_string(&marker) {
        let tag = tag.trim();
        if !tag.is_empty() {
            let local = env!("CARGO_PKG_VERSION");
            if is_newer(tag, local) {
                let _ = writeln!(
                    std::io::stderr(),
                    "[secguard] update available: {tag} (current v{local}) — run `secguard update`"
                );
            } else {
                // Marker is stale (we already match or exceed). Clean up.
                let _ = fs::remove_file(&marker);
            }
        }
    }
}

/// Called from the hot hook path. If the last check is older than
/// `CHECK_INTERVAL_SECS`, fork a detached `secguard update --background` and
/// return immediately. Writes the timestamp up front so concurrent hooks don't
/// fan out multiple checks.
pub fn maybe_background_check() {
    let Some(dir) = cache_dir() else { return };
    let last_check = dir.join(".update-last-check");
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return,
    };
    let stale = match fs::read_to_string(&last_check) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map(|t| now.saturating_sub(t) > CHECK_INTERVAL_SECS)
            .unwrap_or(true),
        Err(_) => true,
    };
    if !stale {
        return;
    }
    // Reserve the timestamp slot early to prevent fan-out from parallel hooks.
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(&last_check, now.to_string());

    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = Command::new(exe)
        .args(["update", "--background"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        assert_eq!(version_tuple("v0.3.0"), Some((0, 3, 0)));
        assert_eq!(version_tuple("1.2.3"), Some((1, 2, 3)));
        assert_eq!(version_tuple("v0.3"), None);
        assert_eq!(version_tuple("garbage"), None);
    }

    #[test]
    fn newer_comparisons() {
        assert!(is_newer("v0.3.1", "0.3.0"));
        assert!(is_newer("v1.0.0", "0.9.99"));
        assert!(!is_newer("v0.3.0", "0.3.0"));
        assert!(!is_newer("v0.2.5", "0.3.0"));
    }
}
