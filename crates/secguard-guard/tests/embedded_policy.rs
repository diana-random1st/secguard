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
    // The decoded reading is peeled like argv, so this names the rm -rf
    // /etc inside sudo: a hard deny where 99af962 had an unresolved block.
    hard(
        &config,
        r#"d='"'; s=' $'; bash -c "a=${d}sudo${s}'rm'${s}'-rf'${s}'/etc'${d}; bash <<EOF
${s}a
EOF""#,
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

/// Gaps the quoting rounds left open (2026-11-24); each of these was Allow
/// in e59056a.
#[test]
fn open_gaps_of_the_quoting_rounds_are_closed() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    let hard = |command: &str, cwd: Option<&str>| {
        let detail = match cwd {
            Some(cwd) => secguard_guard::check_detailed_in_dir(command, &config, Path::new(cwd)),
            None => check_detailed(command, &config),
        };
        assert_eq!(detail.action, Action::Block, "{command} in {cwd:?}");
        assert!(!detail.can_approve(), "{command} in {cwd:?}");
    };
    for command in [
        // The decoded reading is peeled like argv.
        "sudo rm $'-rf' $'/'",
        "sudo $'rm' -rf /",
        "timeout 5 rm $'-rf' $'/'",
        "sudo -u root rm $'-rf' $'/etc'",
        "nice rm $'-rf' $'/'",
        // A backslash-newline inside a word.
        "r\\\nm -rf /",
        // zsh runs rm for `=rm`.
        "=rm -rf /",
        "sudo =rm -rf /",
        "xargs =rm -rf < list",
        // Case does not matter on a macOS volume.
        "touch '/fixture/POLICY DIR/settings.toml'",
        "touch '/fixture/policy dir/SETTINGS.toml'",
    ] {
        hard(command, None);
    }
    assert_ne!(
        check_detailed("git reset --ha\\\nrd", &config).action,
        Action::Allow
    );
    // A cd that fails leaves the shell where it was.
    for command in [
        "cd /tmp/missing; touch settings.toml",
        "cd /tmp/missing || touch settings.toml",
        "cd /tmp/missing\ntouch settings.toml",
        "cd /tmp; cd /tmp/missing; touch settings.toml",
        "cd /tmp/missing 2>/dev/null; touch settings.toml",
    ] {
        hard(command, Some("/fixture/policy dir"));
    }
    // Only the first cd succeeds.
    hard(
        "cd '/fixture/policy dir'; cd /tmp/missing; touch settings.toml",
        Some("/fixture"),
    );
}

/// A reading in which a cd failed skips what runs only after it succeeded,
/// and the other readings change nothing for ordinary commands.
#[test]
fn other_readings_add_no_block_to_ordinary_commands() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    for command in [
        "cd /tmp && touch settings.toml",
        "cd /tmp && make && cd /tmp/x && touch settings.toml",
        "cd /tmp && ls; cd /var && ls",
        "echo =rm",
        "git commit -m \"a \\\nb\"",
        "ls \\\n  -la",
        "echo $'hi'",
        "sudo echo $'hi'",
    ] {
        let detail = secguard_guard::check_detailed_in_dir(
            command,
            &config,
            Path::new("/fixture/policy dir"),
        );
        assert_eq!(detail.action, Action::Allow, "{command}");
    }
}

/// Failed-cd readings multiply through nested bodies; past the walk budget
/// the source is unresolved instead of keeping the guard walking.
#[test]
fn nested_cd_readings_stop_at_the_walk_budget() {
    let cds = (0..16)
        .map(|i| format!("cd /d{i}"))
        .collect::<Vec<_>>()
        .join("; ");
    let command = format!("{cds}; bash -c '{cds}; bash -c \"{cds}; ls\"'");
    let detail = check_detailed(&command, &GuardConfig::default());
    assert_eq!(detail.action, Action::Block);
    assert!(!detail.determinate);
}

/// A word the shell may expand, a HOME that may have been rebound before a
/// tilde cd (the 99af962 repros), and git options
/// that can run code stay unresolved; a protected write stays blocked through
/// each new path.
#[test]
fn unknown_words_rebound_home_and_protected_writes_stay_blocked() {
    use std::path::Path;

    let home = std::env::var("HOME").expect("HOME");
    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    config
        .protected_policy_paths
        .push(format!("{home}/secguard-fixture/settings.toml").into());
    for command in [
        "sed -i s/a/b/ $F",
        "cp a *.txt",
        "tee \"$OUT\"",
        "cp a \"b\\$x\"",
        "git -C \"$X\" -c core.pager=x log",
        "git -C \"$X\" --work-tree=/ log",
        "git -C \"$X\" log --output=x",
        // 99af962: HOME rebound in ways the walker does not model.
        "read -r HOME <<< /x; cd ~ && cp evil config.toml",
        "builtin export H\\OME=/x; cd ~ && cp evil config.toml",
        "HOME=/x; cd ~ && touch config.toml",
        "export HOME=/x && cd ~ && touch config.toml",
        "printf -v HOME /x; cd ~ && touch config.toml",
        "print -v HOME /x; cd ~ && touch config.toml",
        "eval 'HO''ME=/x'; cd ~ && touch config.toml",
        "declare HOME=/x; cd ~ && touch config.toml",
        "\\read HOME; cd ~ && touch config.toml",
        "vared HOME; cd ~ && touch config.toml",
        "f() { :; }; cd ~ && touch config.toml",
        "env HO\\ME=/x bash -c 'cd ~ && touch config.toml'",
        "echo 'cd ~ && touch config.toml' | HOME=/x bash",
        // Protected writes through the new paths.
        "sed -i 's/a*/b/' '/fixture/policy dir/settings.toml'",
        "echo x > '/fixture/policy dir/settings.toml'",
        "cd ~/secguard-fixture && touch settings.toml",
        "cd /fixture/'policy dir' && touch settings.toml",
    ] {
        let detail =
            secguard_guard::check_detailed_in_dir(command, &config, Path::new("/tmp/secguard-cwd"));
        assert_eq!(detail.action, Action::Block, "{command}");
        assert!(!detail.can_approve(), "{command}");
    }
}

/// A cd inside a nested shell body that the walker cannot resolve leaves that
/// body's directory unknown. Before, the enclosing directory was put back, so
/// from a subdirectory of the protected one `bash -c 'cd .. && touch
/// settings.toml'` was checked as a write to the subdirectory and allowed.
#[test]
fn an_unresolved_cd_in_a_nested_body_keeps_its_directory_unknown() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    for command in [
        "bash -c 'cd .. && touch settings.toml'",
        "echo 'cd .. && touch settings.toml' | bash",
        "bash <<EOF\ncd .. && touch settings.toml\nEOF",
        "sh -c 'cd ~ && cd .. && touch settings.toml'",
    ] {
        let detail = secguard_guard::check_detailed_in_dir(
            command,
            &config,
            Path::new("/fixture/policy dir/sub"),
        );
        assert_eq!(detail.action, Action::Block, "{command}");
        assert!(!detail.can_approve(), "{command}");
    }
}

/// Found while reviewing a change that relaxed verdicts (round one,
/// 2026-11-25): each of
/// these was Allow in contextual mode on the first version of the change.
#[test]
fn word_literalness_round_one_repros_stay_blocked() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    let mut lockdown = config.clone();
    lockdown.lockdown.enabled = true;
    for command in [
        // F1: a quoted builtin keeps its quote marks in argv.
        "'export' H\\OME='/fixture/policy dir' && cd ~ && touch settings.toml",
        "\"export\" H\\OME='/fixture/policy dir' && cd ~ && touch settings.toml",
        "'printf' -v H\\OME '/fixture/policy dir' && cd ~ && touch settings.toml",
        "echo '/fixture/policy dir' | 'read' -r H\\OME; cd ~ && touch settings.toml",
        "'noglob' export H\\OME='/fixture/policy dir' && cd ~ && touch settings.toml",
        // F2: zsh repeat, [[ ]] arithmetic, bash wait -p.
        "repeat 1 export H\\OME='/fixture/policy dir'; cd ~ && touch settings.toml",
        "[[ 0 -eq HOME=0 ]] && cd ~ && touch settings.toml",
        "wait -p H\\OME; cd ~ && touch settings.toml",
        // F3: a git -C value or argument that splits or expands.
        "git -C $(echo . -c core.fsmonitor=/tmp/evil.sh) status",
        "X='. -c core.fsmonitor=/tmp/evil.sh'; git -C $X status",
        "git -C * status",
        "OUT='--output=/fixture/policy dir/settings.toml'; git -C /tmp log \"$OUT\"",
        "OUT='--output=/fixture/policy dir/settings.toml'; git log \"$OUT\"",
        // F4: git expands pathspec globs itself.
        "git restore 'policy dir/settings.*'",
        "git rm 'policy dir/settings.*'",
        "git restore ':(glob)**/settings.toml'",
        "git checkout -- 'policy dir/settings.*'",
        "git clean -fd 'policy dir/settings.*'",
        // F5: wrappers that substitute or re-evaluate words.
        "echo '/fixture/policy dir/settings.toml' | xargs -I '{}' cp evil '{}'",
        "echo '/fixture/policy dir/settings.toml' | parallel cp evil '{}'",
        "watch touch '$TARGET'",
        // F6: zsh expands $~X, $^X and $=X inside double quotes.
        "X='/fixture/policy dir/settings.toml'; touch \"$~X\"",
        "X='/fixture/policy dir/settings.toml'; echo evil > \"$~X\"",
        "X='/../fixture/policy dir'; cd /tmp/\"$~X\" && touch settings.toml",
        "X='../fixture/policy dir'; cd /tmp/$X && touch settings.toml",
    ] {
        for (label, config) in [("contextual", &config), ("lockdown", &lockdown)] {
            let detail =
                secguard_guard::check_detailed_in_dir(command, config, Path::new("/fixture"));
            assert_eq!(detail.action, Action::Block, "{label}: {command}");
            assert!(!detail.can_approve(), "{label}: {command}");
        }
    }
}

/// Found while reviewing a change that relaxed verdicts (round two,
/// 2026-11-25): parser
/// gaps the change widened, each a real protected write in zsh and bash.
#[test]
fn word_literalness_round_two_repros_stay_blocked() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    for (cwd, command) in [
        // A1: a comment ending in a backslash does not continue; the next
        // line's continuations do.
        (
            "/fixture",
            "# \\\nH\\\nOME='/fixture/policy dir'; cd ~ && touch settings.toml",
        ),
        (
            "/fixture",
            "# \\\nex\\\nport H\\OME='/fixture/policy dir'; cd ~ && touch settings.toml",
        ),
        (
            "/fixture",
            "# \\\ngit -C \"$X\" log --\\\noutput=/fixture/policy\\ dir/settings.toml",
        ),
        (
            "/fixture",
            "# \\\ngit log --\\\noutput=/fixture/policy\\ dir/settings.toml",
        ),
        // A2: tree-sitter splits a quote glued to a backslash word.
        (
            "/fixture",
            "git -C \"$X\" log '--'\\output=/fixture/policy\\ dir/settings.toml",
        ),
        (
            "/fixture",
            "git log '--'\\output=/fixture/policy\\ dir/settings.toml",
        ),
        ("/fixture", "echo x > '/fixture/policy dir/'\\settings.toml"),
        (
            "/fixture",
            "cd '/fixture/policy dir/sub/'\\.. && touch settings.toml",
        ),
        // A3: an escaped cd name still fails like cd.
        (
            "/fixture/policy dir",
            "\\cd ~/nonexistent; touch settings.toml",
        ),
        (
            "/fixture/policy dir",
            "c\\d /nonexistent/'x'; touch settings.toml",
        ),
        (
            "/fixture/policy dir",
            "\\cd /nonexistent; touch settings.toml",
        ),
        // A4: zsh's two-argument cd substitutes in $PWD.
        (
            "/fixture/safe",
            "cd /fixture/safe '/fixture/policy dir' && touch settings.toml",
        ),
    ] {
        let detail = secguard_guard::check_detailed_in_dir(command, &config, Path::new(cwd));
        assert_eq!(detail.action, Action::Block, "{cwd}: {command}");
        assert!(!detail.can_approve(), "{cwd}: {command}");
    }
}

/// Found while reviewing a change that relaxed verdicts (round three,
/// 2026-11-25): each a
/// real protected write or hard deny in zsh or bash.
#[test]
fn word_literalness_round_three_repros_stay_blocked() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    for (cwd, command) in [
        // zsh test -v evaluates the subscript: HOME=7.
        ("/fixture", "ln -s '/fixture/policy dir' 7; test -v 'path[HO''ME=7]'; cd ~ && echo x > settings.toml"),
        // tree-sitter ends $'\\' at the last quote, bash after `\\`.
        ("/fixture", "cd /tmp/$'\\\\';echo x > ''/fixture/policy\\ dir/settings.toml;#'"),
        ("/fixture", "cd /tmp/$'\\\\';rm ''-rf /;#'"),
        ("/fixture", "echo /tmp/$'\\\\';touch ''/fixture/policy\\ dir/settings.toml;#'"),
        // An ANSI-C string glued to a backslash word.
        ("/fixture", "git -C \"$X\" log $'--'\\output=/fixture/policy\\ dir/settings.toml"),
        ("/fixture", "touch $'/fixture/policy dir/settings'\\.toml"),
        // A line starting with an escaped name is its own command.
        ("/fixture", "echo hi\n\\export H\\OME='/fixture/policy dir'\ncd ~ && touch settings.toml"),
        ("/fixture", "echo hi\n\\touch '/fixture/policy dir/settings.toml'"),
        // `#` after an escaped blank is text, not a comment.
        ("/fixture", "echo \\ #; export HOME='/fixture/policy dir'\ncd ~ && touch settings.toml"),
        ("/fixture", "echo \\ #; touch '/fixture/policy dir/settings.toml'"),
        // Substitutions inside $(( )) and ${...} run.
        ("/fixture", "cd /fixture/'safe' $(( $(rm -rf /) ))"),
        ("/fixture", "git -C \"$X\" log $(( $(rm -rf /) ))"),
        ("/fixture", "echo $(( $(rm -rf /) ))"),
        ("/fixture", "echo ${X:-$(rm -rf /)}"),
        // zsh cd OLD NEW with a blank-led NEW.
        ("/fixture/policy/foo", "cd /foo ' dir' && sed -i 's/a*/b/' settings.toml"),
    ] {
        let detail = secguard_guard::check_detailed_in_dir(command, &config, Path::new(cwd));
        assert_eq!(detail.action, Action::Block, "{cwd}: {command}");
        assert!(!detail.can_approve(), "{cwd}: {command}");
    }
    // A backslash-newline the shell keeps, or no continuation at all, adds
    // no reading and no block.
    for command in [
        "echo 'a\\\nb'",
        "# \\\necho hi",
        "echo \\\\\necho hi",
        "cat <<'EOF'\nfoo\\\nbar\nEOF",
        "sleep $((5*60))",
    ] {
        let detail = secguard_guard::check_detailed_in_dir(command, &config, Path::new("/fixture"));
        assert_eq!(detail.action, Action::Allow, "{command}");
    }
}

/// Found while reviewing a change that relaxed verdicts (round four,
/// 2026-11-25): shapes tree-sitter misreads, or zsh features that rebind
/// HOME.
#[test]
fn word_literalness_round_four_repros_stay_blocked() {
    use std::path::Path;

    let mut config = GuardConfig::default();
    config
        .protected_policy_paths
        .push("/fixture/policy dir/settings.toml".into());
    for (cwd, command) in [
        ("/fixture", "ln -s '/fixture/policy dir' 7; : < \"/dev/null$~0[HOME=7]\"; cd ~ && touch settings.toml"),
        ("/fixture", "ln -s '/fixture/policy dir' 7; cd \"/nonexistent/$~0[$(echo HO)ME=7]\"; cd ~ && touch settings.toml"),
        ("/fixture", "ln -s 'policy dir' 'Operation not permitted'; syserror -e H\\OME 1; cd ~ && touch settings.toml"),
        ("/fixture", "sed -i 's/a*/b/' '/fixture/policy'\\ dir/settings.toml"),
        ("/fixture/work/sub", "cd /sub \u{a0} && sed -i 's/a*/b/' settings.toml"),
        ("/fixture/safe", "'c'\\d '/fixture/policy dir' && sed -i 's/a*/b/' settings.toml"),
        ("/fixture", "git -C \"$X\" log \u{b}#; touch '/fixture/policy dir/settings.toml'"),
        ("/fixture", "git -C \"$X\" log < $'\\\\';touch ''/fixture/policy\\ dir/settings.toml;#'"),
    ] {
        let detail = secguard_guard::check_detailed_in_dir(command, &config, Path::new(cwd));
        assert_eq!(detail.action, Action::Block, "{cwd}: {command}");
        assert!(!detail.can_approve(), "{cwd}: {command}");
    }
}
