//! Policy allowlist: operations that are always safe.

use crate::config::GuardConfig;

pub fn is_safe_by_policy(cmd: &str, config: &GuardConfig) -> bool {
    let parts = split_command_parts(cmd);

    if parts.is_empty() {
        return false;
    }

    parts
        .iter()
        .all(|part| is_single_command_safe(part, config))
}

pub(crate) fn split_command_parts(cmd: &str) -> Vec<&str> {
    cmd.split("&&")
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split(';'))
        .flat_map(|s| s.split('|'))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_single_command_safe(cmd: &str, config: &GuardConfig) -> bool {
    if is_safe_kill_command(cmd, config) {
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
    false
}

pub(crate) fn is_kill_command(cmd: &str) -> bool {
    cmd.split_whitespace()
        .next()
        .is_some_and(|program| matches!(program, "pkill" | "killall" | "kill"))
}

pub(crate) fn is_safe_kill_command(cmd: &str, config: &GuardConfig) -> bool {
    let mut tokens = cmd.split_whitespace();
    let Some(program) = tokens.next() else {
        return false;
    };

    if !matches!(program, "pkill" | "killall") {
        return false;
    }

    tokens
        .filter(|token| !token.starts_with('-'))
        .any(|target| config.safe_kill_targets.iter().any(|safe| target == safe))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GuardConfig {
        GuardConfig::default()
    }

    #[test]
    fn safe_git_push() {
        assert!(is_safe_by_policy("git push origin main", &cfg()));
    }

    #[test]
    fn unsafe_force_push() {
        assert!(!is_safe_by_policy("git push --force origin main", &cfg()));
    }

    #[test]
    fn safe_kubectl_get() {
        assert!(is_safe_by_policy("kubectl get pods", &cfg()));
    }

    #[test]
    fn safe_compound() {
        assert!(is_safe_by_policy(
            "git push origin main && kubectl get pods",
            &cfg()
        ));
    }

    #[test]
    fn safe_kill() {
        assert!(is_safe_by_policy("pkill node", &cfg()));
        assert!(is_safe_by_policy("killall python", &cfg()));
        assert!(!is_safe_by_policy("pkill postgres", &cfg()));
        assert!(!is_safe_by_policy("kill 12345", &cfg()));
    }

    #[test]
    fn psql_is_not_policy_safe() {
        assert!(!is_safe_by_policy("psql -c 'select 1'", &cfg()));
    }
}
