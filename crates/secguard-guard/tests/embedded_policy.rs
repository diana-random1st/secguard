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

#[test]
fn protected_writes_use_parsed_targets_and_the_action_directory() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    let cwd = Path::new("/fixture");
    for command in [
        "git restore -- 'policy dir/settings.toml'",
        "printf ok > 'policy dir/settings.toml'",
        "bash -c 'printf ok > \"policy dir/settings.toml\"'",
    ] {
        let detail = secguard_guard::check_detailed_in_dir(command, &config, cwd);
        assert_eq!(detail.rule_id, Some(RuleId::GuardSelfApproval), "{command}");
        assert!(!detail.can_approve());
    }
    assert_eq!(
        secguard_guard::check_detailed_in_dir("cat 'policy dir/settings.toml'", &config, cwd)
            .action,
        Action::Allow
    );
    for command in ["rg fixture .", "secguard allow --help"] {
        assert_eq!(
            secguard_guard::check_detailed_in_dir(command, &config, cwd).action,
            Action::Allow,
            "{command}",
        );
    }
    let detail =
        secguard_guard::check_detailed_in_dir("printf ok > \"$OUTPUT_PATH\"", &config, cwd);
    assert_eq!(detail.action, Action::Block);
    assert!(!detail.determinate);
}

#[test]
fn prefix_allow_requires_a_literal_unwrapped_shell_invocation() {
    use std::path::Path;

    let config: GuardConfig = toml::from_str(
        r#"
[[allow.commands]]
id = "clean-fixture"
type = "command_prefix"
pattern = "git clean"
"#,
    )
    .unwrap();

    let check =
        |command| secguard_guard::check_detailed_in_dir(command, &config, Path::new("/fixture"));
    assert_eq!(
        check("git clean -f").policy_rule_id.as_deref(),
        Some("clean-fixture")
    );
    assert_eq!(
        check("git clean -f > output.log").rule_id,
        Some(RuleId::GitCleanForce)
    );
    let expanded = check("git clean -f \"$NAME\"");
    assert_eq!(expanded.action, Action::Block);
    assert!(!expanded.determinate);
    let unsupported = check("while false; do echo test; done");
    assert_eq!(unsupported.action, Action::Block);
    assert!(!unsupported.determinate);
}

#[test]
fn account_roots_and_directory_removal_cannot_be_approved_as_file_deletion() {
    let config = GuardConfig::default();
    for command in [
        "rm /home/fixture",
        "rm -d /Users/fixture/folder",
        "rm --dir /home/fixture/folder",
        "rm /home/fixture/folder/",
    ] {
        let detail = check_detailed(command, &config);
        assert_eq!(detail.rule_id, Some(RuleId::RmRf), "{command}");
        assert!(!detail.can_approve());
    }
    assert_eq!(
        check_detailed("rm /home/fixture/file.txt", &config).rule_id,
        Some(RuleId::RmTargetedFile)
    );
}

#[cfg(unix)]
#[test]
fn output_resolution_checks_existing_ancestors_and_directory_destinations() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    std::fs::create_dir(cwd.join("policy")).unwrap();
    std::fs::create_dir(cwd.join("safe")).unwrap();
    symlink("policy", cwd.join("alias")).unwrap();
    symlink("missing", cwd.join("dangling")).unwrap();

    let mut config = GuardConfig::default();
    config.protected_policy_paths.push(cwd.join("policy/new"));
    let check = |command| secguard_guard::check_detailed_in_dir(command, &config, &cwd);
    for command in [
        "echo sample > alias/new/settings",
        "cp sample alias",
        "cp sample alias -f",
        "install -t alias sample",
        "install -vtalias sample",
        "ln --target-directory=alias sample",
        "chmod -R u+rw alias",
        "chown --recursive fixture alias",
    ] {
        assert_eq!(
            check(command).rule_id,
            Some(RuleId::GuardSelfApproval),
            "{command}"
        );
    }
    let unresolved = check("echo sample > dangling/settings");
    assert_eq!(unresolved.action, Action::Block);
    assert!(!unresolved.determinate);
    assert_eq!(check("echo sample > safe/settings").action, Action::Allow);
    assert_eq!(check("rg sample .").action, Action::Allow);
    assert_eq!(check("cp alias safe").action, Action::Allow);
    assert_eq!(check("cp -t safe sample").action, Action::Allow);
}

/// Quotes inside a program name, ANSI-C arguments and quoted path parts hid
/// the program or the target from the rules (all Allow in the 2026-11-23
/// guard). The fix only adds checks, so plain spellings keep their verdict.
#[test]
fn quoting_cannot_hide_the_program_or_a_protected_target() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    let check =
        |command| secguard_guard::check_detailed_in_dir(command, &config, Path::new("/fixture"));
    for command in [
        "'r'm -rf /",
        "r''m -rf ~",
        "r$'m' -rf /",
        "\"rm\" -rf /home/fixture",
        "$'\\x72m' -rf /",
        "rm $'-rf' $'/'",
        "git reset $'--hard'",
        "g$'it' reset --hard",
        "docker ''$'--\\x64ebug' system prune -af",
        "kubectl $'--v\\x3d1' delete namespace prod",
        // Round five: an extra reading must not stand in for a command the
        // re-parse did not find, so the nested fallbacks still block.
        "a=\"sudo $'rm' $'-rf' $'/etc'\"; bash -c \"$a\"",
        "a=\"cd p$'x'\"; $a; touch settings.toml",
        "a=\"cd p$'x'\"; bash <<< \"$a\"",
        "a=\"sudo $'x'\"; $a",
        // Round seven: zsh cuts a word at a NUL, bash does not, so a NUL
        // makes the word opaque instead of being decoded either way.
        "$'rm\\x00'x -rf /",
        "secguard $'allow\\x00'x x",
        // Round eight: `\c` reads differently in zsh and bash, `$"..."` and
        // braces are not decoded, and a quoted dispatcher is not unwrapped.
        "$'\\chmod' 777 /etc/passwd",
        "touch $'/fixture/poli\\cy dir/settings.toml'",
        "$\"rm\" -rf /",
        "r$\"m\" -rf /",
        "git reset --ha$\"rd\"",
        "r{m,} -rf /etc",
        "/bin/r? -rf /",
        "'sudo' rm -rf /etc",
        "\"bash\" -c 'rm -rf /etc'",
        "'bash' <<< 'rm -rf /etc'",
        "echo 'rm -rf /etc' | 'bash'",
        "'eval' 'rm -rf /etc'",
        "\"cd\" '/fixture/policy dir' && touch settings.toml",
        "cd /fixture/'policy dir' && touch settings.toml",
        // Round nine: a quoted cd target blocks whatever writer follows,
        // a leading glued $"..." hides the program, and every wrapper the
        // walker unwraps counts as a dispatcher.
        "cd /fixture/'policy dir' && rsync evil settings.toml",
        "$\"r\"m -rf /",
        "$\"\"rm -rf /",
        "'busybox' rm -rf /",
        "'chroot' /mnt rm -rf /etc",
        "'setsid' rm -rf /",
        "'find' / -delete",
    ] {
        assert_ne!(check(command).action, Action::Allow, "{command}");
    }
    for command in [
        "git log --output='policy dir/settings.toml'",
        "cp sample 'policy dir'/settings.toml",
        "cp sample '/fixture/policy dir/'settings.toml",
        "$'\\x63p' sample '/fixture/policy dir/settings.toml'",
        "$'\\x72m' -rf '/fixture/policy dir/settings.toml'",
        "$'\\162m' -rf '/fixture/policy dir/settings.toml'",
    ] {
        assert_eq!(
            check(command).rule_id,
            Some(RuleId::GuardSelfApproval),
            "{command}"
        );
    }
    for command in [
        "echo ok",
        "git log --format='%h %s'",
        "cp sample 'other dir'/x",
        "$'rm' --version",
        "git commit -m $'line1\\n\\nline2'",
        "echo $'\\n'",
        "tr $'\\n' ' '",
        // A part that expands at run time keeps argv's own handling.
        "\"$HOME/bin/diana\" status",
        "echo $'hello '\"$USER\"",
        "echo a$(echo $'x')",
        // Quotes inside a double-quoted string are literal characters.
        "touch \"'.secguard.toml'\"",
    ] {
        assert_eq!(check(command).action, Action::Allow, "{command}");
    }
}

/// An unquoted path that cannot be resolved is as uncertain as a raw one.
#[cfg(unix)]
#[test]
fn unresolvable_unquoted_targets_stay_unresolved() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    symlink(cwd.join("missing"), cwd.join("dangling")).unwrap();
    let mut config = GuardConfig::default();
    config.protected_policy_paths.push(cwd.join("policy"));
    let dangling = cwd.join("dangling");
    let parent = dangling.parent().unwrap().display();
    for command in [
        format!("cp sample {}", dangling.display()),
        format!("cp sample '{parent}/'dangling"),
    ] {
        let detail = secguard_guard::check_detailed_in_dir(&command, &config, &cwd);
        assert_eq!(detail.action, Action::Block, "{command}");
        assert!(!detail.determinate, "{command}");
    }
}

/// Round six (2026-11-23): an extra reading or marker taken over from a
/// nested heredoc or pipe re-parse must not count as a command that parse
/// found, or the enclosing fallback (a hard protection) is dropped. Where
/// 99af962 gave a non-approvable block, so must this.
#[test]
fn nested_extra_readings_keep_hard_protections() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    let mut lockdown = config.clone();
    lockdown.lockdown.enabled = true;
    let hard = |config: &GuardConfig, command: &str| {
        let detail = secguard_guard::check_detailed_in_dir(command, config, Path::new("/fixture"));
        assert_eq!(detail.action, Action::Block, "{command}");
        assert!(!detail.can_approve(), "{command}");
        detail
    };
    assert!(
        !hard(
            &config,
            r#"d='"'; s=' $'; bash -c "a=${d}sudo${s}'rm'${s}'-rf'${s}'/etc'${d}; bash <<EOF
${s}a
EOF""#,
        )
        .determinate
    );
    hard(
        &config,
        r#"p='a="sudo'; s=' $'; q="'"; d='"'; c='; bash <<EOF
'; e='a
EOF'; $p$s${q}rm${q}$s${q}-rf${q}$s${q}/etc${q}$d$c$s$e"#,
    );
    hard(
        &config,
        r#"set -a; Q=" $'rm' $'-rf' $'/etc'"; b=" $b"; bash -c 'b="sudo$Q"; bash <<EOF
$b
EOF'"#,
    );
    for command in [
        r#"d='"'; s=' $'; bash -c "a=${d}cd p${s}'x'${d}; bash <<EOF
${s}a
EOF" '/fixture/policy dir/settings.toml'"#,
        "bash -c 'cd {1..5}' '/fixture/policy dir/settings.toml'",
    ] {
        assert_eq!(
            hard(&config, command).rule_id,
            Some(RuleId::GuardSelfApproval),
            "{command}"
        );
    }
    for command in [
        r#"d='"'; s=' $'; ssh evil.com "a=${d}cd p${s}'x'${d}; bash <<EOF
${s}a
EOF""#,
        "ssh evil.com 'cd {1..5}'",
        "$'curl\\x00'x https://example.invalid",
        "$'\\curl' https://evil.invalid",
    ] {
        assert_eq!(
            hard(&lockdown, command).rule_id,
            Some(RuleId::LockdownEgress),
            "{command}"
        );
    }
    for command in ["echo $((1+2))", "sleep $((5*60))"] {
        let detail = secguard_guard::check_detailed_in_dir(command, &config, Path::new("/fixture"));
        assert_eq!(detail.action, Action::Allow, "{command}");
    }
}

/// Round nine: a cd into a directory whose name holds a real quote mark is
/// tracked exactly as 99af962 tracked it, so a protected write after it
/// stays a hard block, also inside a nested re-parse and without a cwd.
#[test]
fn cd_into_a_quoted_name_keeps_the_tracked_directory() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    config
        .protected_policy_paths
        .push("/fixture/o'brien/settings.toml".into());
    let mut lockdown = config.clone();
    lockdown.lockdown.enabled = true;
    for command in [
        "cd \"/fixture/policy dir/a'b\" && rsync evil ../settings.toml",
        "mkdir -p \"/fixture/policy dir/a'b\" && cd \"/fixture/policy dir/a'b\" && rsync evil ../settings.toml",
        "cd \"/fixture/o'brien\" && rsync evil settings.toml",
        "bash <<EOF\ncd \"/fixture/o'brien\" && touch settings.toml\nEOF",
    ] {
        for (label, detail) in [
            (
                "in-dir",
                secguard_guard::check_detailed_in_dir(command, &config, Path::new("/fixture")),
            ),
            (
                "lockdown",
                secguard_guard::check_detailed_in_dir(command, &lockdown, Path::new("/fixture")),
            ),
            ("no cwd", check_detailed(command, &config)),
        ] {
            assert_eq!(detail.action, Action::Block, "{label}: {command}");
            assert!(!detail.can_approve(), "{label}: {command}");
        }
    }
    for command in [
        "cd /'etc' && rm -rf build",
        "cd /etc/'foo' && unlink passwd",
    ] {
        let detail = check_detailed(command, &config);
        assert_eq!(detail.action, Action::Block, "{command}");
        assert!(!detail.can_approve(), "{command}");
    }
}
