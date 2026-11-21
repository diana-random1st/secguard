//! End-to-end action mapping (RAN-414, test class 3).
//!
//! Drives the full `check_detailed` pipeline and asserts the resolved
//! `action`, proving the scoring matrix reaches real commands — and that the
//! spread is real (not everything blocks).

use secguard_guard::{check_detailed, Action, GuardConfig};

fn action(cmd: &str) -> Action {
    check_detailed(cmd, &GuardConfig::default()).action
}

#[test]
fn rm_safe_target_allows() {
    // node_modules is a safe-rm pattern → no rule fires → Allow.
    assert_eq!(action("rm -rf node_modules"), Action::Allow);
}

#[test]
fn rm_home_blocks() {
    // $HOME subtree → RmRf (blast 3, reversibility 0) → Block.
    assert_eq!(action("rm -rf $HOME"), Action::Block);
}

#[test]
fn rm_etc_blocks() {
    assert_eq!(action("rm -rf /etc"), Action::Block);
}

#[test]
fn force_push_confirms() {
    // GitForcePush (3, 2) → Confirm — recoverable on the remote, but wide.
    assert_eq!(action("git push --force origin main"), Action::Confirm);
}

#[test]
fn no_verify_is_a_hard_deny() {
    // NoVerify is a hard deny for embedded enforcement: an agent may not skip
    // the repository's safety hooks, whatever its score.
    assert_eq!(action("git commit --no-verify -m x"), Action::Block);
}

#[test]
fn orm_migration_confirms_not_blocks() {
    // The headline false-positive reducer: alembic upgrade was a hard block
    // under the binary model; OrmMigration (2, 2) now resolves to Confirm.
    assert_eq!(action("alembic upgrade head"), Action::Confirm);
}

#[test]
fn safe_command_allows() {
    assert_eq!(action("git status"), Action::Allow);
    assert_eq!(action("cargo test --all"), Action::Allow);
}

#[test]
fn config_override_changes_action() {
    // A user can downgrade a cell for an approval-eligible rule. Move (3, 0)
    // [AwsS3Rm class] from Block to Warn and confirm the pipeline honours it.
    // A hard deny in the same cell (RmRf) ignores the override.
    use secguard_guard::config::{ScoringConfig, ScoringOverride};
    let cfg = GuardConfig {
        scoring: ScoringConfig {
            overrides: vec![ScoringOverride {
                blast: 3,
                reversibility: 0,
                action: Action::Warn,
            }],
        },
        ..Default::default()
    };
    assert_eq!(
        check_detailed("aws s3 rm s3://bucket/tmp/a.tgz", &GuardConfig::default()).action,
        Action::Block
    );
    assert_eq!(
        check_detailed("aws s3 rm s3://bucket/tmp/a.tgz", &cfg).action,
        Action::Warn
    );
    assert_eq!(check_detailed("rm -rf $HOME", &cfg).action, Action::Block);
}
