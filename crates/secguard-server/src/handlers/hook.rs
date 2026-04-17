use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

use crate::metrics::{OutcomeLabels, RuleLabels, VerdictLabels};
use crate::response;
use crate::state::AppState;

pub async fn guard(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tool_name = body.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");

    let Some(text) = response::text_to_check(tool_name, &body) else {
        state
            .metrics
            .guard_requests
            .get_or_create(&VerdictLabels {
                verdict: "skipped".into(),
            })
            .inc();
        return (StatusCode::OK, Json(serde_json::json!({})));
    };

    if text.is_empty() {
        state
            .metrics
            .guard_requests
            .get_or_create(&VerdictLabels {
                verdict: "skipped".into(),
            })
            .inc();
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    let start = std::time::Instant::now();
    let verdict = secguard_guard::check_with_config(&text, &state.guard_config);
    let elapsed = start.elapsed().as_secs_f64();
    state.metrics.guard_duration.observe(elapsed);

    match verdict {
        secguard_guard::Verdict::Destructive(reason) => {
            state
                .metrics
                .guard_requests
                .get_or_create(&VerdictLabels {
                    verdict: "destructive".into(),
                })
                .inc();

            let display = if text.len() > 200 {
                format!("{}...", &text[..197])
            } else {
                text
            };
            let reason_text = format!("\u{26a0}\u{fe0f} Destructive: {reason}\nCommand: {display}");
            let hook_event_name = response::incoming_hook_event_name(&body);
            let json = response::guard_block(state.target, &hook_event_name, &reason_text);
            (StatusCode::OK, Json(json))
        }
        secguard_guard::Verdict::Safe => {
            state
                .metrics
                .guard_requests
                .get_or_create(&VerdictLabels {
                    verdict: "safe".into(),
                })
                .inc();
            (StatusCode::OK, Json(serde_json::json!({})))
        }
    }
}

pub async fn secrets_scan(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut input_clone = body
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let start = std::time::Instant::now();
    let findings = secguard_secrets::redact_value(&mut input_clone, &state.scanner);
    let elapsed = start.elapsed().as_secs_f64();
    state.metrics.secrets_duration.observe(elapsed);

    if findings.is_empty() {
        state
            .metrics
            .secrets_requests
            .get_or_create(&OutcomeLabels {
                outcome: "clean".into(),
            })
            .inc();
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    state
        .metrics
        .secrets_requests
        .get_or_create(&OutcomeLabels {
            outcome: "redacted".into(),
        })
        .inc();

    for finding in &findings {
        state
            .metrics
            .secrets_findings
            .get_or_create(&RuleLabels {
                rule_id: finding.rule_id.clone(),
            })
            .inc();
    }

    let types: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    let unique_types: std::collections::BTreeSet<&str> = types.into_iter().collect();
    let context = format!(
        "[secguard] Redacted {} credential(s). Types: {}",
        findings.len(),
        unique_types.into_iter().collect::<Vec<_>>().join(", ")
    );

    let hook_event_name = response::incoming_hook_event_name(&body);
    let json = response::secrets_redacted(state.target, &hook_event_name, &context, input_clone);
    (StatusCode::OK, Json(json))
}
