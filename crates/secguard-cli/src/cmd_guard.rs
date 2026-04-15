use std::io::Read;

pub fn run(command: Option<String>) -> anyhow::Result<()> {
    let cmd = match command {
        Some(c) => c,
        None => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            input.trim().to_string()
        }
    };

    if cmd.is_empty() {
        anyhow::bail!("no command provided");
    }

    match secguard_guard::check(&cmd) {
        secguard_guard::Verdict::Safe => {
            eprintln!("safe: {cmd}");
            std::process::exit(0);
        }
        secguard_guard::Verdict::Destructive(reason) => {
            eprintln!("DESTRUCTIVE: {reason}");
            std::process::exit(1);
        }
    }
}
