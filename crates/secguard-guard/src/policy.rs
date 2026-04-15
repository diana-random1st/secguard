//! Policy allowlist: operations that are always safe.

pub fn is_safe_by_policy(cmd: &str) -> bool {
    let parts: Vec<&str> = cmd
        .split("&&")
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split(';'))
        .flat_map(|s| s.split('|'))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() {
        return false;
    }

    parts.iter().all(|part| is_single_command_safe(part))
}

fn is_single_command_safe(cmd: &str) -> bool {
    if cmd.contains("pkill") || cmd.contains("killall") || cmd.starts_with("kill ") {
        return true;
    }
    if cmd.starts_with("git push")
        && !cmd.contains("--force")
        && !cmd.contains("-f ")
        && !cmd.contains("-f\n")
    {
        return true;
    }
    if cmd.starts_with("kubectl ") {
        let safe_ops = [
            "get ",
            "describe ",
            "logs ",
            "port-forward ",
            "top ",
            "config ",
            "version",
            "api-resources",
            "explain ",
        ];
        return safe_ops.iter().any(|s| cmd.contains(s));
    }
    if cmd.starts_with("psql ") || cmd.contains("psql -") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_git_push() {
        assert!(is_safe_by_policy("git push origin main"));
    }

    #[test]
    fn unsafe_force_push() {
        assert!(!is_safe_by_policy("git push --force origin main"));
    }

    #[test]
    fn safe_kubectl_get() {
        assert!(is_safe_by_policy("kubectl get pods"));
    }

    #[test]
    fn safe_compound() {
        assert!(is_safe_by_policy(
            "git push origin main && kubectl get pods"
        ));
    }

    #[test]
    fn safe_kill() {
        assert!(is_safe_by_policy("pkill node"));
        assert!(is_safe_by_policy("kill 12345"));
    }
}
