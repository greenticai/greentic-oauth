use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use url::form_urlencoded;

mod bindings {
    wit_bindgen::generate!({
        path: "wit/oidc-ingress",
        world: "callback",
        generate_all
    });
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressRequest {
    pub provider_id: String,
    pub tenant: String,
    pub query_string: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressResult {
    pub ok: bool,
    pub provider_id: String,
    pub tenant: String,
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngressError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("missing query parameter `{0}`")]
    MissingParam(&'static str),
}

pub fn handle_callback(input: IngressRequest) -> Result<IngressResult, IngressError> {
    if input.provider_id.trim().is_empty() {
        return Err(IngressError::MissingField("provider_id"));
    }
    if input.tenant.trim().is_empty() {
        return Err(IngressError::MissingField("tenant"));
    }

    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;

    for (k, v) in form_urlencoded::parse(input.query_string.as_bytes()) {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }

    if error.is_none() && code.is_none() {
        return Err(IngressError::MissingParam("code"));
    }
    if state.is_none() {
        return Err(IngressError::MissingParam("state"));
    }

    Ok(IngressResult {
        ok: error.is_none(),
        provider_id: input.provider_id,
        tenant: input.tenant,
        code,
        state,
        error,
        error_description,
    })
}

pub fn to_runtime_exchange_input(result: &IngressResult, code_verifier: &str) -> Value {
    json!({
        "tenant": result.tenant,
        "code": result.code,
        "code_verifier": code_verifier
    })
}

#[allow(dead_code)]
struct Component;

impl bindings::exports::greentic::oidc_ingress::callback_api::Guest for Component {
    fn handle_callback(
        query_string: String,
        provider_id: String,
        tenant: String,
    ) -> Result<String, String> {
        let result = handle_callback(IngressRequest {
            provider_id,
            tenant,
            query_string,
        })
        .map_err(|err| err.to_string())?;

        serde_json::to_string(&result).map_err(|err| err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
bindings::export!(Component with_types_in bindings);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_success_callback() {
        let result = handle_callback(IngressRequest {
            provider_id: "oidc-generic".into(),
            tenant: "acme".into(),
            query_string: "code=abc123&state=s-1".into(),
        })
        .expect("callback");

        assert!(result.ok);
        assert_eq!(result.code.as_deref(), Some("abc123"));
        assert_eq!(result.state.as_deref(), Some("s-1"));
    }

    #[test]
    fn parses_error_callback() {
        let result = handle_callback(IngressRequest {
            provider_id: "oidc-generic".into(),
            tenant: "acme".into(),
            query_string: "error=access_denied&error_description=user+cancelled&state=s-2".into(),
        })
        .expect("callback");

        assert!(!result.ok);
        assert_eq!(result.error.as_deref(), Some("access_denied"));
    }

    #[test]
    fn rejects_missing_state() {
        let err = handle_callback(IngressRequest {
            provider_id: "oidc-generic".into(),
            tenant: "acme".into(),
            query_string: "code=abc123".into(),
        })
        .expect_err("must fail");

        assert_eq!(err, IngressError::MissingParam("state"));
    }
}
