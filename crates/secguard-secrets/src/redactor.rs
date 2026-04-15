use serde_json::Value;

use crate::scanner::{Finding, Scanner};

/// Replace detected secrets in text with `[REDACTED:<rule_id>]` markers.
pub fn redact(text: &str, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for f in findings {
        if f.start > last_end {
            result.push_str(&text[last_end..f.start]);
        }
        result.push_str(&format!("[REDACTED:{}]", f.rule_id));
        last_end = f.end;
    }

    if last_end < text.len() {
        result.push_str(&text[last_end..]);
    }

    result
}

/// Recursively scan and redact all string values in a JSON value.
pub fn redact_value(value: &mut Value, scanner: &Scanner) -> Vec<Finding> {
    let mut all_findings = Vec::new();

    match value {
        Value::String(s) => {
            let findings = scanner.scan(s);
            if !findings.is_empty() {
                *s = redact(s, &findings);
                all_findings.extend(findings);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                all_findings.extend(redact_value(val, scanner));
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                all_findings.extend(redact_value(val, scanner));
            }
        }
        _ => {}
    }

    all_findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_preserves_clean_text() {
        let text = "nothing to see here";
        let redacted = redact(text, &[]);
        assert_eq!(redacted, text);
    }

    #[test]
    fn redact_single_secret() {
        let scanner = Scanner::new();
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let text = format!("key={} rest", key);
        let findings = scanner.scan(&text);
        let redacted = redact(&text, &findings);
        assert!(redacted.contains("[REDACTED:aws_access_key]"));
        assert!(redacted.contains("rest"));
    }
}
