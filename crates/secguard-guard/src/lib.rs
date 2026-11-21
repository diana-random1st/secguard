//! Destructive command detection.
//!
//! Classify shell actions against lockdown, configured policy, and heuristic rules.

pub mod ast;
pub mod autostash;
pub mod config;
pub mod deobfuscate;
pub mod findings;
pub mod heuristic;
pub mod injection;
pub mod lockdown;
pub mod matcher;
pub mod policy;
pub mod rm;
pub mod rule_id;
pub mod rules;
pub mod scoring;

#[cfg(feature = "ml")]
mod brain;

pub use config::GuardConfig;
pub use rule_id::RuleId;
pub use scoring::{Action, Decision};

use rule_id::RuleProtection;
use std::path::Path;

/// Result of guard classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Command is safe to execute.
    Safe,
    /// Command is destructive — includes human-readable reason.
    Destructive(String),
}

/// Which phase produced the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    Policy,
    Heuristic,
    /// Brain returned destructive with confidence >= threshold.
    Brain,
    /// Brain ran, label was safe.
    BrainSafe,
    /// Brain returned destructive but confidence < threshold — treated as safe.
    BrainLowConfidence,
    /// Model file missing or init failed.
    BrainNotLoaded,
    /// Model loaded but produced a token outside the valid label set.
    BrainMalformed,
    /// ML feature not compiled in; heuristic/policy did not trigger.
    Default,
}

/// Verdict with source information for telemetry.
#[derive(Debug, Clone)]
pub struct VerdictDetail {
    pub verdict: Verdict,
    pub source: VerdictSource,
    /// ML confidence score (0.0–1.0), only set when source is Brain.
    pub confidence: Option<f32>,
    /// Machine-readable rule identifier — populated when a rule fires.
    /// `None` when no rule matched (Safe by default), when the verdict came
    /// from the policy allowlist, or when the brain produced a Safe label.
    pub rule_id: Option<RuleId>,
    /// Id of an explicit allow or deny policy rule. Explicit denies cannot be exempted.
    pub policy_rule_id: Option<String>,
    /// Blast × reversibility action. Derived from the firing
    /// rule's [`RuleId::score`] through the config-resolved policy matrix.
    /// Safe verdicts are always [`Action::Allow`]; destructive verdicts with
    /// no `rule_id` (explicit config denies, fail-open) are [`Action::Block`].
    pub action: Action,
    /// Whether policy evaluation could reach a determinate decision.
    pub determinate: bool,
}

impl VerdictDetail {
    /// True when a trusted host may request an exact-action human approval.
    ///
    /// The severity matrix sets the default action independently. Eligibility
    /// alone grants no permission, and explicit denies remain final.
    pub fn can_approve(&self) -> bool {
        self.determinate
            && self
                .rule_id
                .is_some_and(|rule| rule.protection() == RuleProtection::ApprovalEligible)
    }
}

impl VerdictDetail {
    /// Construct a detail, deriving `action` from the verdict + rule.
    /// Single source of truth for the verdict → action mapping.
    fn new(
        verdict: Verdict,
        source: VerdictSource,
        confidence: Option<f32>,
        rule_id: Option<RuleId>,
        config: &GuardConfig,
    ) -> Self {
        let protection = rule_id.map(RuleId::protection);
        let action = match (&verdict, rule_id) {
            (Verdict::Safe, _) => Action::Allow,
            (Verdict::Destructive(_), Some(r))
                if protection == Some(RuleProtection::ApprovalEligible) =>
            {
                config.scoring.action_for(r.score())
            }
            (Verdict::Destructive(_), Some(_)) => Action::Block,
            // Explicit config denies and asymmetric fail-open carry no rule
            // id; they are fail-safe blocks by construction.
            (Verdict::Destructive(_), None) => Action::Block,
        };
        Self {
            verdict,
            source,
            confidence,
            rule_id,
            policy_rule_id: None,
            action,
            determinate: protection != Some(RuleProtection::Unresolved),
        }
    }

    fn unavailable(reason: &str, config: &GuardConfig) -> Self {
        let mut detail = Self::new(
            Verdict::Destructive(reason.into()),
            VerdictSource::Policy,
            None,
            None,
            config,
        );
        detail.determinate = false;
        detail
    }
}

/// Classify a shell command through all enabled phases.
pub fn check(cmd: &str) -> Verdict {
    check_detailed(cmd, &GuardConfig::default()).verdict
}

/// Classify with custom configuration.
pub fn check_with_config(cmd: &str, config: &GuardConfig) -> Verdict {
    check_detailed(cmd, config).verdict
}

/// Classify a command with its policy or heuristic source.
///
/// Lockdown, explicit denies, and hard or unresolved rules take precedence
/// over configured allows. When several ordinary rules match, the strongest
/// action wins. A malformed input containing a destructive keyword is blocked.
// @s5d:component comp.embedded-policy-parity
pub fn check_detailed(cmd: &str, config: &GuardConfig) -> VerdictDetail {
    check_detailed_inner(cmd, config, None, None)
}

/// Classify shell text relative to the exact, host-resolved working directory.
pub fn check_detailed_in_dir(cmd: &str, config: &GuardConfig, cwd: &Path) -> VerdictDetail {
    let Some(cwd) = command_dir(cwd) else {
        return VerdictDetail::unavailable("guard requires an absolute working directory", config);
    };
    check_detailed_inner(cmd, config, Some(cwd), None)
}

fn command_dir(cwd: &Path) -> Option<&str> {
    cwd.is_absolute().then(|| cwd.to_str()).flatten()
}

/// Recheck an action against all rules other than its matched, exemptible rule.
///
/// This diagnostic does not authorize execution or validate an approval. The
/// trusted host must bind the human-approved rule to the exact action and
/// context, then consume the unexpired approval atomically before execution.
pub fn check_detailed_exempting(
    cmd: &str,
    config: &GuardConfig,
    exempt_code: &str,
) -> VerdictDetail {
    recheck(cmd, config, None, exempt_code)
}

/// Recheck with the same host-resolved working directory as the initial decision.
pub fn check_detailed_exempting_in_dir(
    cmd: &str,
    config: &GuardConfig,
    cwd: &Path,
    exempt_code: &str,
) -> VerdictDetail {
    let Some(cwd) = command_dir(cwd) else {
        return VerdictDetail::unavailable("guard requires an absolute working directory", config);
    };
    recheck(cmd, config, Some(cwd), exempt_code)
}

fn recheck(cmd: &str, config: &GuardConfig, cwd: Option<&str>, exempt_code: &str) -> VerdictDetail {
    let original = check_detailed_inner(cmd, config, cwd, None);
    match original.rule_id {
        Some(rule) if original.can_approve() && rule.as_code() == exempt_code => {
            check_detailed_inner(cmd, config, cwd, Some(rule))
        }
        _ => original,
    }
}

fn check_detailed_inner(
    cmd: &str,
    config: &GuardConfig,
    cwd: Option<&str>,
    exempt: Option<RuleId>,
) -> VerdictDetail {
    let parsed = ast::parse_with_cwd(cmd, cwd);
    // Phase 0: lockdown egress. Runs before the policy allowlist on purpose —
    // a user-defined safe_command_prefixes entry must not be able to open a
    // hole in a mode whose whole point is that nothing leaves.
    if config.lockdown.enabled {
        for ec in &parsed.commands {
            if ec.span != ast::SpanKind::Executed {
                continue;
            }
            if let Some((rule_id, reason)) = lockdown::is_lockdown_egress_command(ec) {
                let full_reason = format!(
                    "{reason}\n{deny_msg}",
                    deny_msg = lockdown::LOCKDOWN_DENY_MSG
                );
                log::warn!("[lockdown] {full_reason}");
                return VerdictDetail::new(
                    Verdict::Destructive(full_reason),
                    VerdictSource::Heuristic,
                    None,
                    Some(rule_id),
                    config,
                );
            }
        }
    }

    let Ok(lists) = config::try_build_rule_lists(config) else {
        return VerdictDetail::unavailable("guard policy contains an invalid rule", config);
    };
    for (scope, rules) in [
        ("command", &lists.deny.commands),
        ("secret", &lists.deny.secrets),
    ] {
        if let matcher::Decision::Deny { rule_id, .. } = matcher::evaluate(cmd, rules, &[]) {
            return policy_deny(scope, rule_id, config);
        }
    }

    if parsed.had_error
        && (config.lockdown.enabled
            || cwd.is_some()
            || exempt.is_some()
            || has_trigger_keyword(cmd))
    {
        return VerdictDetail::unavailable("guard could not parse the action", config);
    }
    let raw_allow_eligible = parsed.raw_allow_eligible;
    let commands = parsed.commands;
    let had_parse_issue = parsed.had_error;

    // Granting guard permission is human-only. Runs before every allow path
    // (config allows, the `diana ...` policy shortcut) and is never exempt.
    if let Some((rule_id, reason)) =
        rules::classify_self_approval(&commands, config, cwd.is_some() || config.lockdown.enabled)
    {
        return VerdictDetail::new(
            Verdict::Destructive(reason),
            VerdictSource::Heuristic,
            None,
            Some(rule_id),
            config,
        );
    }

    for ec in &commands {
        if let Some(rule_id) = rules::classify_configured_path_deny(ec, &lists.deny.paths) {
            return policy_deny("path", rule_id, config);
        }
    }

    let hits: Vec<_> = commands
        .iter()
        .flat_map(|command| rules::classify_matches(command, config, exempt))
        .collect();
    // An allow rule can waive ordinary heuristics. Hard protections and
    // unresolved execution take precedence over all allow paths.
    if let Some((rule_id, reason)) = hits
        .iter()
        .find(|(rule, _)| rule.protection() == RuleProtection::HardDeny)
        .or_else(|| {
            hits.iter()
                .find(|(rule, _)| rule.protection() == RuleProtection::Unresolved)
        })
    {
        return VerdictDetail::new(
            Verdict::Destructive(reason.clone()),
            VerdictSource::Heuristic,
            None,
            Some(*rule_id),
            config,
        );
    }

    if (cwd.is_some() || exempt.is_some() || config.lockdown.enabled)
        && commands
            .iter()
            .any(|command| command.head() == Some("__shell_unmodeled__"))
    {
        return VerdictDetail::unavailable("guard could not model the shell action", config);
    }

    // A config allow rule matches the raw string, so it may only vouch for a
    // single simple command: `command_prefix "git status"` must not wave
    // through `git status && rm -rf ~`. Compound, piped, substituted or
    // unparseable input goes through the per-command rules instead.
    if raw_allow_eligible && !had_parse_issue {
        match matcher::evaluate(cmd, &[], &lists.allow.commands) {
            matcher::Decision::Allow { rule_id, .. } => {
                let mut detail =
                    VerdictDetail::new(Verdict::Safe, VerdictSource::Policy, None, None, config);
                detail.policy_rule_id = Some(rule_id);
                return detail;
            }
            matcher::Decision::Deny { .. } | matcher::Decision::NoMatch => {}
        }
    }

    if raw_allow_eligible && !had_parse_issue && policy::is_safe_by_policy(cmd, config) {
        return VerdictDetail::new(Verdict::Safe, VerdictSource::Policy, None, None, config);
    }

    let hits = hits.into_iter().map(|(rule_id, reason)| {
        VerdictDetail::new(
            Verdict::Destructive(reason),
            VerdictSource::Heuristic,
            None,
            Some(rule_id),
            config,
        )
    });
    // Pick the strongest decision, preserving the first hit on ties.
    if let Some(detail) = hits.reduce(|first, next| {
        if next.action > first.action {
            next
        } else {
            first
        }
    }) {
        return detail;
    }

    #[cfg(feature = "ml")]
    {
        let mut detail = match brain::classify(cmd) {
            brain::BrainOutcome::Destructive { reason, confidence } => VerdictDetail::new(
                Verdict::Destructive(reason),
                VerdictSource::Brain,
                Some(confidence),
                Some(RuleId::Brain),
                config,
            ),
            brain::BrainOutcome::LowConfidence { confidence } => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainLowConfidence,
                Some(confidence),
                None,
                config,
            ),
            brain::BrainOutcome::Safe { confidence } => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainSafe,
                Some(confidence),
                None,
                config,
            ),
            brain::BrainOutcome::NotLoaded => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainNotLoaded,
                None,
                None,
                config,
            ),
            brain::BrainOutcome::MalformedOutput => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainMalformed,
                None,
                None,
                config,
            ),
        };
        if (cwd.is_some() || exempt.is_some())
            && matches!(
                detail.source,
                VerdictSource::BrainLowConfidence
                    | VerdictSource::BrainNotLoaded
                    | VerdictSource::BrainMalformed
            )
        {
            detail.determinate = false;
            detail.action = Action::Block;
            detail.verdict = Verdict::Destructive("guard classifier is unavailable".into());
        }
        return detail;
    }

    #[allow(unreachable_code)]
    VerdictDetail::new(Verdict::Safe, VerdictSource::Default, None, None, config)
}

fn policy_deny(scope: &str, rule_id: String, config: &GuardConfig) -> VerdictDetail {
    let mut detail = VerdictDetail::new(
        Verdict::Destructive(format!("config deny {scope} rule {rule_id}")),
        VerdictSource::Policy,
        None,
        None,
        config,
    );
    detail.policy_rule_id = Some(rule_id);
    detail
}

/// Quick substring scan for destructive trigger keywords. Used by the
/// asymmetric-fail-open path: a malformed command that mentions any of
/// these words is escalated to ask, while malformed-but-benign input is
/// left to the shell's own syntax check.
fn has_trigger_keyword(cmd: &str) -> bool {
    const TRIGGERS: &[&str] = &[
        "rm",
        "unlink",
        "rmdir",
        "shred",
        "drop",
        "truncate",
        "delete",
        "destroy",
        "purge",
        "terminate",
        "force",
        "reset",
        "rebase",
        "amend",
        "uninstall",
        "filter-branch",
        "filter-repo",
        "FLUSHALL",
        "FLUSHDB",
        "SHUTDOWN",
        "dropDatabase",
        "deleteMany",
        "eval",
        "sudo",
    ];
    TRIGGERS.iter().any(|t| cmd.contains(t))
}
/// Test-visible alias for [`check_detailed`], used by the `lockdown` module's
/// tests. Keeps the name short there without a `pub use` re-export in the
/// crate root.
#[cfg(test)]
pub fn lib_check_detailed_with_lockdown(cmd: &str, config: &GuardConfig) -> VerdictDetail {
    check_detailed(cmd, config)
}
