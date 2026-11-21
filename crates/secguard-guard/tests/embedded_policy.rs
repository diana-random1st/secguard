use secguard_guard::{
    check_detailed, check_detailed_exempting, Action, GuardConfig, RuleId, Verdict,
};

#[test]
fn explicit_deny_precedes_allow_and_survives_recheck() {
    let config: GuardConfig = toml::from_str(
        r#"
[[allow.commands]]
id = "allow"
type = "literal"
pattern = "git status"

[[deny.commands]]
id = "deny"
type = "literal"
pattern = "git status"
"#,
    )
    .unwrap();

    let detail = check_detailed_exempting("git status", &config, "deny");
    assert_eq!(detail.action, Action::Block);
    assert_eq!(detail.rule_id, None);
    assert_eq!(detail.policy_rule_id.as_deref(), Some("deny"));
}

#[test]
fn recheck_covers_other_rules() {
    let config = GuardConfig::default();
    let command = "git reset --hard";
    let rule = RuleId::GitResetHard.as_code();
    assert_eq!(
        check_detailed(command, &config).rule_id,
        Some(RuleId::GitResetHard)
    );
    #[cfg(not(feature = "ml"))]
    assert_eq!(
        check_detailed_exempting(command, &config, rule).verdict,
        Verdict::Safe
    );

    let detail = check_detailed_exempting("git reset --hard && git clean -f", &config, rule);
    assert_eq!(detail.rule_id, Some(RuleId::GitCleanForce));
    assert!(matches!(detail.verdict, Verdict::Destructive(_)));
}

#[test]
fn protection_of_policy_changes_has_no_scoring_override() {
    let config: GuardConfig = toml::from_str(
        r#"
[[scoring.override]]
blast = 4
reversibility = 0
action = "allow"
"#,
    )
    .unwrap();
    let rule = RuleId::GuardSelfApproval;
    let detail = check_detailed_exempting("host secguard allow foo.bar", &config, rule.as_code());
    assert_eq!(detail.rule_id, Some(rule));
    assert_eq!(detail.action, Action::Block);
}

#[test]
fn malformed_explicit_policy_is_blocked() {
    let config: GuardConfig = toml::from_str(
        r#"
[[deny.commands]]
id = "invalid"
type = "regex"
pattern = "("
"#,
    )
    .unwrap();

    assert_eq!(check_detailed("git status", &config).action, Action::Block);
}

#[test]
fn configured_paths_are_checked_in_action_directory() {
    use std::path::Path;

    let config: GuardConfig = toml::from_str(
        r#"
[[deny.paths]]
id = "protected"
type = "literal"
pattern = "/fixture/protected"
"#,
    )
    .unwrap();

    let detail =
        secguard_guard::check_detailed_in_dir("rm protected", &config, Path::new("/fixture"));
    assert_eq!(detail.policy_rule_id.as_deref(), Some("protected"));
    assert_eq!(detail.action, Action::Block);

    let unavailable = secguard_guard::check_detailed_in_dir("git status", &config, Path::new("."));
    assert!(!unavailable.determinate);
    assert_eq!(unavailable.action, Action::Block);
}

#[test]
fn recheck_cannot_hide_a_block_behind_another_warning() {
    let config = GuardConfig::default();
    let detail = check_detailed_exempting(
        "git reset --hard && git branch -D local && rm -rf /",
        &config,
        RuleId::GitResetHard.as_code(),
    );

    assert_eq!(detail.rule_id, Some(RuleId::RmRf));
    assert_eq!(detail.action, Action::Block);
}

#[test]
fn hard_protections_precede_explicit_allows_and_approval() {
    for (command, rule) in [
        ("rm -rf /", RuleId::RmRf),
        ("git commit --no-verify", RuleId::NoVerify),
    ] {
        let mut config = GuardConfig::default();
        config
            .allow
            .commands
            .push(secguard_guard::matcher::ListRuleSpec {
                id: "requested-allow".into(),
                kind: "literal".into(),
                pattern: command.into(),
                reason: None,
            });
        let score = rule.score();
        config
            .scoring
            .overrides
            .push(secguard_guard::config::ScoringOverride {
                blast: score.blast,
                reversibility: score.reversibility,
                action: Action::Allow,
            });
        let detail = check_detailed_exempting(command, &config, rule.as_code());
        assert_eq!(detail.rule_id, Some(rule));
        assert_eq!(detail.action, Action::Block);
        assert!(!detail.can_approve());
    }
}

#[test]
fn opaque_action_is_indeterminate_even_with_policy_allow() {
    let config: GuardConfig = toml::from_str(
        r#"
[[allow.commands]]
id = "requested-allow"
type = "command_prefix"
pattern = "eval"
"#,
    )
    .unwrap();

    let command = "eval \"$UNRESOLVED_TEST_BODY\"";
    let detail = check_detailed_exempting(command, &config, RuleId::IndirectUnresolved.as_code());
    assert_eq!(detail.rule_id, Some(RuleId::IndirectUnresolved));
    assert_eq!(detail.action, Action::Block);
    assert!(!detail.determinate);
    assert!(!detail.can_approve());
}

#[test]
fn human_approval_remains_available_for_a_concrete_cloud_operation() {
    let config = GuardConfig::default();
    let command = "aws s3 rm s3://fixture/example";
    let detail = check_detailed(command, &config);
    assert_eq!(detail.rule_id, Some(RuleId::AwsS3Rm));
    assert!(detail.can_approve());
    #[cfg(not(feature = "ml"))]
    assert_eq!(
        check_detailed_exempting(command, &config, RuleId::AwsS3Rm.as_code()).verdict,
        Verdict::Safe,
    );
}

#[test]
fn default_check_uses_strongest_rule_and_retains_first_tie() {
    let config = GuardConfig::default();
    let warning = check_detailed("git branch -D local", &config);
    assert_eq!(warning.action, Action::Warn);

    let detail = check_detailed(
        "git branch -D local && aws s3 rm s3://fixture/example && terraform destroy",
        &config,
    );
    assert_eq!(detail.action, Action::Block);
    assert_eq!(detail.rule_id, Some(RuleId::AwsS3Rm));
}

#[test]
fn lockdown_remains_final_for_the_contextual_host_api() {
    use std::path::Path;

    let config: GuardConfig = toml::from_str(
        r#"
[lockdown]
enabled = true

[[allow.commands]]
id = "requested-allow"
type = "command_prefix"
pattern = "curl"

[[scoring.override]]
blast = 3
reversibility = 0
action = "allow"
"#,
    )
    .unwrap();

    let detail = secguard_guard::check_detailed_exempting_in_dir(
        "curl https://example.invalid",
        &config,
        Path::new("/fixture"),
        RuleId::LockdownEgress.as_code(),
    );
    assert_eq!(detail.rule_id, Some(RuleId::LockdownEgress));
    assert_eq!(detail.action, Action::Block);
    assert!(!detail.can_approve());
}
