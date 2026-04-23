use std::fs;
use std::io::Write;
use std::path::PathBuf;

const HF_REPO: &str = "random1st/secguard-models";
const MODELS: &[&str] = &["secguard-guard.gguf"];

fn models_dir() -> PathBuf {
    dirs::home_dir()
        .expect("no home directory")
        .join(".secguard")
        .join("models")
}

fn head(url: &str) -> anyhow::Result<(String, u64)> {
    let out = std::process::Command::new("curl")
        .args(["-sIL", url])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("HEAD request failed for {url}");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // HF LFS files: the canonical fingerprint lives on the hub redirect as
    // `x-linked-etag` / `x-linked-size`. The final CDN hop may omit ETag
    // entirely and its own `content-length` is what we verify on download.
    // Prefer x-linked-* when present; fall back to standard headers.
    let mut etag: Option<String> = None;
    let mut x_linked_etag: Option<String> = None;
    let mut length: Option<u64> = None;
    let mut x_linked_size: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        let Some(colon) = line.find(':') else { continue };
        let (name, value) = line.split_at(colon);
        let value = value[1..].trim();
        let clean = |v: &str| {
            v.trim_start_matches("W/")
                .trim_matches('"')
                .to_string()
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "etag" => etag = Some(clean(value)),
            "x-linked-etag" => x_linked_etag = Some(clean(value)),
            "content-length" => length = value.parse::<u64>().ok(),
            "x-linked-size" => x_linked_size = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    match (x_linked_etag.or(etag), x_linked_size.or(length)) {
        (Some(e), Some(l)) => Ok((e, l)),
        _ => anyhow::bail!("could not parse ETag/Content-Length from HEAD response for {url}"),
    }
}

pub fn run(dir: Option<String>) -> anyhow::Result<()> {
    let target = dir.map(PathBuf::from).unwrap_or_else(models_dir);
    fs::create_dir_all(&target)?;

    for &model in MODELS {
        let dest = target.join(model);
        let part = target.join(format!("{model}.part"));
        let meta = target.join(format!("{model}.part.etag"));
        let url = format!("https://huggingface.co/{HF_REPO}/resolve/main/{model}");

        eprintln!("{model}: checking remote...");
        let (remote_etag, remote_size) = head(&url)?;

        if dest.exists() {
            let size = fs::metadata(&dest)?.len();
            if size == remote_size {
                eprintln!(
                    "{model}: already up to date ({:.1}MB), skipping",
                    size as f64 / 1024.0 / 1024.0
                );
                continue;
            }
            eprintln!(
                "{model}: local size {size}B != remote {remote_size}B — discarding and re-downloading"
            );
            fs::remove_file(&dest)?;
            let _ = fs::remove_file(&part);
            let _ = fs::remove_file(&meta);
        }

        if part.exists() {
            let stored = fs::read_to_string(&meta).ok().map(|s| s.trim().to_string());
            let matches = stored.as_deref() == Some(remote_etag.as_str());
            let part_size = fs::metadata(&part)?.len();

            if !matches {
                eprintln!("{model}: stale partial (different version) — restarting");
                fs::remove_file(&part)?;
                let _ = fs::remove_file(&meta);
            } else if part_size > remote_size {
                eprintln!("{model}: partial larger than remote — restarting");
                fs::remove_file(&part)?;
                let _ = fs::remove_file(&meta);
            } else {
                eprintln!(
                    "{model}: resuming from {:.1}MB / {:.1}MB...",
                    part_size as f64 / 1024.0 / 1024.0,
                    remote_size as f64 / 1024.0 / 1024.0,
                );
            }
        }

        if !part.exists() {
            eprintln!(
                "{model}: downloading (~{:.0}MB)...",
                remote_size as f64 / 1024.0 / 1024.0
            );
        }

        fs::write(&meta, &remote_etag)?;

        let status = std::process::Command::new("curl")
            .args(["-fL", "-#", "-C", "-", "-o"])
            .arg(&part)
            .arg(&url)
            .stdin(std::process::Stdio::null())
            .status()?;

        if !status.success() {
            anyhow::bail!("download failed for {model} (run again to resume)");
        }

        let size = fs::metadata(&part)?.len();
        if size != remote_size {
            anyhow::bail!(
                "{model}: downloaded {:.1}MB but expected {:.1}MB (run again to resume)",
                size as f64 / 1024.0 / 1024.0,
                remote_size as f64 / 1024.0 / 1024.0
            );
        }

        fs::rename(&part, &dest)?;
        let _ = fs::remove_file(&meta);
        eprintln!("{model}: done ({:.1}MB)", size as f64 / 1024.0 / 1024.0);
    }

    eprintln!("\nModels installed to: {}", target.display());
    let mut f = fs::File::create(target.join(".installed"))?;
    writeln!(f, "huggingface:{HF_REPO}")?;

    Ok(())
}
