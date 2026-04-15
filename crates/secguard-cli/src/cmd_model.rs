use std::fs;
use std::io::Write;
use std::path::PathBuf;

const HF_REPO: &str = "random1st/secguard-models";
const MODELS: &[(&str, u64)] = &[("secguard-guard.gguf", 811_614_688)];

fn models_dir() -> PathBuf {
    dirs::home_dir()
        .expect("no home directory")
        .join(".secguard")
        .join("models")
}

pub fn run(dir: Option<String>) -> anyhow::Result<()> {
    let target = dir.map(PathBuf::from).unwrap_or_else(models_dir);
    fs::create_dir_all(&target)?;

    for &(model, expected_size) in MODELS {
        let dest = target.join(model);
        let part = target.join(format!("{model}.part"));

        // Skip if complete file exists with correct size
        if dest.exists() {
            let size = fs::metadata(&dest)?.len();
            if size >= expected_size {
                eprintln!(
                    "{model}: already exists ({:.1}MB), skipping",
                    size as f64 / 1024.0 / 1024.0
                );
                continue;
            }
            // Incomplete — move to .part for resume
            fs::rename(&dest, &part)?;
            eprintln!("{model}: incomplete download found, resuming...");
        }

        let url = format!("https://huggingface.co/{HF_REPO}/resolve/main/{model}");

        if part.exists() {
            let part_size = fs::metadata(&part)?.len();
            eprintln!(
                "{model}: resuming from {:.1}MB / {:.1}MB...",
                part_size as f64 / 1024.0 / 1024.0,
                expected_size as f64 / 1024.0 / 1024.0
            );
        } else {
            eprintln!(
                "{model}: downloading (~{:.0}MB)...",
                expected_size as f64 / 1024.0 / 1024.0
            );
        }

        let status = std::process::Command::new("curl")
            .args(["-fL", "-#", "-C", "-", "-o"])
            .arg(&part)
            .arg(&url)
            .stdin(std::process::Stdio::null())
            .status()?;

        if !status.success() {
            // Keep .part for next resume attempt
            anyhow::bail!("download failed for {model} (run again to resume)");
        }

        let size = fs::metadata(&part)?.len();
        if size < expected_size {
            anyhow::bail!(
                "{model}: downloaded {:.1}MB but expected {:.1}MB (run again to resume)",
                size as f64 / 1024.0 / 1024.0,
                expected_size as f64 / 1024.0 / 1024.0
            );
        }

        // Atomic rename .part -> final
        fs::rename(&part, &dest)?;
        eprintln!("{model}: done ({:.1}MB)", size as f64 / 1024.0 / 1024.0);
    }

    eprintln!("\nModels installed to: {}", target.display());
    let mut f = fs::File::create(target.join(".installed"))?;
    writeln!(f, "huggingface:{HF_REPO}")?;

    Ok(())
}
