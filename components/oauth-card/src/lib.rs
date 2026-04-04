use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Input for resolving OAuth placeholders in an Adaptive Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardResolveInput {
    /// Raw Adaptive Card JSON string containing OAuth placeholders.
    pub adaptive_card: String,
    /// Resolved OAuth authorize URL to inject (must use http or https scheme).
    pub start_url: String,
    /// Teams OAuth connection name (only relevant for Teams-native providers).
    pub teams_connection_name: Option<String>,
    /// Whether the target provider supports native OAuth cards (e.g. Teams).
    pub native_oauth_card: bool,
}

/// Output from resolving OAuth placeholders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardResolveOutput {
    /// Rewritten Adaptive Card JSON string with all placeholders resolved.
    pub resolved_card: String,
    /// Present when the card was downgraded (e.g. Teams placeholder on non-Teams provider).
    pub downgrade: Option<CardDowngrade>,
}

/// Describes a card downgrade applied during resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardDowngrade {
    pub mode: DowngradeMode,
    pub reason: DowngradeReason,
}

/// Why the card was downgraded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DowngradeMode {
    /// Provider does not support native OAuth cards — Teams-specific fields were stripped.
    #[serde(rename = "non_native_fallback")]
    NonNativeFallback,
}

/// Specific reason for the downgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DowngradeReason {
    /// Teams connection name was unavailable or provider is not Teams-native.
    #[serde(rename = "teams_connection_name_unavailable")]
    TeamsConnectionNameUnavailable,
}

#[derive(Debug, Error)]
pub enum CardError {
    #[error("invalid adaptive_card JSON: {0}")]
    InvalidCardJson(String),
    #[error("card serialization failed: {0}")]
    Serialization(String),
    #[error("invalid start_url: {0}")]
    InvalidStartUrl(String),
}

/// Check whether a raw card string contains any OAuth placeholders.
///
/// This is a lightweight pre-flight check that avoids JSON parsing.
/// Use it to skip expensive capability calls when no resolution is needed.
pub fn has_oauth_placeholders(card_str: &str) -> bool {
    card_str.contains("{{oauth.start_url}}")
        || card_str.contains("{{oauth.teams.connectionName}}")
        || card_str.contains("oauth://start")
}

/// Recursively scan a parsed Adaptive Card value for `Action.OpenUrl`
/// actions with `url: "oauth://start"`.
pub fn contains_oauth_start_marker(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let is_open_url = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("Action.OpenUrl"));
            if is_open_url
                && map
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| url == "oauth://start")
            {
                return true;
            }
            map.values().any(contains_oauth_start_marker)
        }
        Value::Array(values) => values.iter().any(contains_oauth_start_marker),
        _ => false,
    }
}

/// Validate that `start_url` uses a safe HTTP(S) scheme.
fn validate_start_url(url: &str) -> Result<(), CardError> {
    if url.trim().is_empty() {
        return Err(CardError::InvalidStartUrl("start_url is empty".into()));
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(CardError::InvalidStartUrl(format!(
            "start_url must use http or https scheme, got: {}",
            url.chars().take(50).collect::<String>()
        )));
    }
    Ok(())
}

/// Resolve all OAuth placeholders in an Adaptive Card.
///
/// Rewrites:
/// - `{{oauth.start_url}}` → `start_url`
/// - `oauth://start` (in `Action.OpenUrl`) → `start_url`
/// - `{{oauth.teams.connectionName}}` → connection name (if native) or removed
///
/// Returns the resolved card string and optional downgrade metadata.
pub fn resolve_card(input: &CardResolveInput) -> Result<CardResolveOutput, CardError> {
    validate_start_url(&input.start_url)?;

    let mut card: Value = serde_json::from_str(&input.adaptive_card)
        .map_err(|err| CardError::InvalidCardJson(err.to_string()))?;

    let had_teams_placeholder = input
        .adaptive_card
        .contains("{{oauth.teams.connectionName}}");

    rewrite_oauth_fields(
        &mut card,
        &input.start_url,
        input.teams_connection_name.as_deref(),
        input.native_oauth_card,
    );

    let resolved_card =
        serde_json::to_string(&card).map_err(|err| CardError::Serialization(err.to_string()))?;

    let downgrade = if had_teams_placeholder
        && (!input.native_oauth_card || input.teams_connection_name.is_none())
    {
        Some(CardDowngrade {
            mode: DowngradeMode::NonNativeFallback,
            reason: DowngradeReason::TeamsConnectionNameUnavailable,
        })
    } else {
        None
    };

    Ok(CardResolveOutput {
        resolved_card,
        downgrade,
    })
}

/// Recursively rewrite OAuth placeholders in a JSON value.
fn rewrite_oauth_fields(
    value: &mut Value,
    start_url: &str,
    teams_connection_name: Option<&str>,
    native_oauth_card: bool,
) {
    match value {
        Value::Object(map) => {
            let is_open_url = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("Action.OpenUrl"));
            let has_oauth_url_marker =
                map.get("url").and_then(Value::as_str) == Some("oauth://start");
            if is_open_url && has_oauth_url_marker {
                map.insert("url".to_string(), Value::String(start_url.to_string()));
            }
            if map.get("connectionName").and_then(Value::as_str)
                == Some("{{oauth.teams.connectionName}}")
            {
                if native_oauth_card && let Some(name) = teams_connection_name {
                    map.insert(
                        "connectionName".to_string(),
                        Value::String(name.to_string()),
                    );
                } else {
                    map.remove("connectionName");
                }
            }
            for entry in map.values_mut() {
                rewrite_oauth_fields(entry, start_url, teams_connection_name, native_oauth_card);
            }
        }
        Value::Array(values) => {
            for entry in values {
                rewrite_oauth_fields(entry, start_url, teams_connection_name, native_oauth_card);
            }
        }
        Value::String(text) => {
            *text = text.replace("{{oauth.start_url}}", start_url);
            if native_oauth_card {
                if let Some(name) = teams_connection_name {
                    *text = text.replace("{{oauth.teams.connectionName}}", name);
                } else {
                    *text = text.replace("{{oauth.teams.connectionName}}", "");
                }
            } else {
                *text = text.replace("{{oauth.teams.connectionName}}", "");
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_teams_native_card() {
        let card = json!({
            "type": "AdaptiveCard",
            "actions": [{
                "type": "Action.OpenUrl",
                "title": "Connect",
                "url": "oauth://start"
            }],
            "connectionName": "{{oauth.teams.connectionName}}"
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/start/session".to_string(),
            teams_connection_name: Some("greentic-oauth".to_string()),
            native_oauth_card: true,
        };

        let output = resolve_card(&input).expect("resolve");
        let resolved: Value = serde_json::from_str(&output.resolved_card).expect("card json");

        assert_eq!(
            resolved.pointer("/actions/0/url").and_then(Value::as_str),
            Some("https://oauth.example/start/session")
        );
        assert_eq!(
            resolved.get("connectionName").and_then(Value::as_str),
            Some("greentic-oauth")
        );
        assert!(output.downgrade.is_none());
    }

    #[test]
    fn downgrades_non_native_provider() {
        let card = json!({
            "type": "AdaptiveCard",
            "actions": [{
                "type": "Action.OpenUrl",
                "title": "Connect",
                "url": "oauth://start"
            }],
            "connectionName": "{{oauth.teams.connectionName}}"
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/start/session".to_string(),
            teams_connection_name: Some("greentic-oauth".to_string()),
            native_oauth_card: false,
        };

        let output = resolve_card(&input).expect("resolve");
        let resolved: Value = serde_json::from_str(&output.resolved_card).expect("card json");

        assert_eq!(
            resolved.pointer("/actions/0/url").and_then(Value::as_str),
            Some("https://oauth.example/start/session")
        );
        assert!(
            resolved.get("connectionName").is_none(),
            "non-native provider should drop teams-only placeholder"
        );
        let downgrade = output.downgrade.expect("downgrade expected");
        assert_eq!(downgrade.mode, DowngradeMode::NonNativeFallback);
        assert_eq!(
            downgrade.reason,
            DowngradeReason::TeamsConnectionNameUnavailable
        );
    }

    #[test]
    fn replaces_template_string_placeholders() {
        let card = json!({
            "type": "AdaptiveCard",
            "body": [{
                "type": "TextBlock",
                "text": "Sign in at {{oauth.start_url}} to continue"
            }]
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/start".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };

        let output = resolve_card(&input).expect("resolve");
        let resolved: Value = serde_json::from_str(&output.resolved_card).expect("card json");

        assert_eq!(
            resolved.pointer("/body/0/text").and_then(Value::as_str),
            Some("Sign in at https://oauth.example/start to continue")
        );
    }

    #[test]
    fn has_oauth_placeholders_detects_markers() {
        assert!(has_oauth_placeholders("some {{oauth.start_url}} text"));
        assert!(has_oauth_placeholders("{{oauth.teams.connectionName}}"));
        assert!(has_oauth_placeholders("url: oauth://start"));
        assert!(!has_oauth_placeholders("no placeholders here"));
    }

    #[test]
    fn contains_oauth_start_marker_finds_nested_action() {
        let card = json!({
            "type": "AdaptiveCard",
            "body": [],
            "actions": [{
                "type": "Action.OpenUrl",
                "url": "oauth://start"
            }]
        });
        assert!(contains_oauth_start_marker(&card));
    }

    #[test]
    fn contains_oauth_start_marker_ignores_non_oauth() {
        let card = json!({
            "type": "AdaptiveCard",
            "actions": [{
                "type": "Action.OpenUrl",
                "url": "https://example.com"
            }]
        });
        assert!(!contains_oauth_start_marker(&card));
    }

    #[test]
    fn no_downgrade_when_no_teams_placeholder() {
        let card = json!({
            "type": "AdaptiveCard",
            "actions": [{
                "type": "Action.OpenUrl",
                "url": "oauth://start"
            }]
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/start".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };

        let output = resolve_card(&input).expect("resolve");
        assert!(output.downgrade.is_none());
    }

    // --- MAJOR-1: URL validation tests ---

    #[test]
    fn rejects_javascript_uri() {
        let card = json!({"type": "AdaptiveCard", "actions": []});
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "javascript:alert(1)".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };
        let err = resolve_card(&input).expect_err("should reject javascript URI");
        assert!(err.to_string().contains("must use http or https scheme"));
    }

    #[test]
    fn rejects_data_uri() {
        let card = json!({"type": "AdaptiveCard", "actions": []});
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "data:text/html,<h1>pwned</h1>".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };
        let err = resolve_card(&input).expect_err("should reject data URI");
        assert!(err.to_string().contains("must use http or https scheme"));
    }

    #[test]
    fn rejects_empty_start_url() {
        let card = json!({"type": "AdaptiveCard", "actions": []});
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };
        let err = resolve_card(&input).expect_err("should reject empty URL");
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn accepts_http_url() {
        let card = json!({"type": "AdaptiveCard", "actions": []});
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "http://localhost:8080/oauth/start".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };
        resolve_card(&input).expect("http should be accepted");
    }

    // --- MEDIUM-4: Edge case tests ---

    #[test]
    fn resolves_deeply_nested_action_in_container() {
        let card = json!({
            "type": "AdaptiveCard",
            "body": [{
                "type": "Container",
                "items": [{
                    "type": "ActionSet",
                    "actions": [{
                        "type": "Action.OpenUrl",
                        "title": "Sign In",
                        "url": "oauth://start"
                    }]
                }]
            }]
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/auth".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };

        let output = resolve_card(&input).expect("resolve");
        let resolved: Value = serde_json::from_str(&output.resolved_card).expect("json");
        assert_eq!(
            resolved
                .pointer("/body/0/items/0/actions/0/url")
                .and_then(Value::as_str),
            Some("https://oauth.example/auth")
        );
    }

    #[test]
    fn resolves_multiple_oauth_actions() {
        let card = json!({
            "type": "AdaptiveCard",
            "actions": [
                { "type": "Action.OpenUrl", "title": "Google", "url": "oauth://start" },
                { "type": "Action.OpenUrl", "title": "Microsoft", "url": "oauth://start" }
            ]
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/auth".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };

        let output = resolve_card(&input).expect("resolve");
        let resolved: Value = serde_json::from_str(&output.resolved_card).expect("json");
        assert_eq!(
            resolved.pointer("/actions/0/url").and_then(Value::as_str),
            Some("https://oauth.example/auth")
        );
        assert_eq!(
            resolved.pointer("/actions/1/url").and_then(Value::as_str),
            Some("https://oauth.example/auth")
        );
    }

    #[test]
    fn resolves_both_template_and_action_placeholders() {
        let card = json!({
            "type": "AdaptiveCard",
            "body": [{
                "type": "TextBlock",
                "text": "Visit {{oauth.start_url}} to sign in"
            }],
            "actions": [{
                "type": "Action.OpenUrl",
                "url": "oauth://start"
            }]
        });
        let input = CardResolveInput {
            adaptive_card: serde_json::to_string(&card).unwrap(),
            start_url: "https://oauth.example/auth".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };

        let output = resolve_card(&input).expect("resolve");
        let resolved: Value = serde_json::from_str(&output.resolved_card).expect("json");
        assert_eq!(
            resolved.pointer("/body/0/text").and_then(Value::as_str),
            Some("Visit https://oauth.example/auth to sign in")
        );
        assert_eq!(
            resolved.pointer("/actions/0/url").and_then(Value::as_str),
            Some("https://oauth.example/auth")
        );
    }

    #[test]
    fn rejects_invalid_card_json() {
        let input = CardResolveInput {
            adaptive_card: "not valid json".to_string(),
            start_url: "https://oauth.example/auth".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };
        let err = resolve_card(&input).expect_err("should reject invalid JSON");
        assert!(err.to_string().contains("invalid adaptive_card JSON"));
    }

    #[test]
    fn handles_card_that_is_json_array() {
        let input = CardResolveInput {
            adaptive_card: "[1, 2, 3]".to_string(),
            start_url: "https://oauth.example/auth".to_string(),
            teams_connection_name: None,
            native_oauth_card: false,
        };
        // Array is valid JSON — resolve_card should succeed without changes.
        let output = resolve_card(&input).expect("resolve");
        assert_eq!(output.resolved_card, "[1,2,3]");
    }
}
