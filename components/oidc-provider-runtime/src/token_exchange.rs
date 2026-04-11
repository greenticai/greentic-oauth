//! Inline HTTP POST to an OAuth token endpoint using the existing
//! `greentic-interfaces-guest::http_client_v1_1` infrastructure, which is
//! the same path `oidc-provider` already uses for other OAuth operations.

use serde_json::Value;
use url::form_urlencoded;

use crate::RuntimeError;

pub struct ExchangeInput<'a> {
    pub token_url: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
}

#[derive(Debug)]
#[allow(dead_code)] // fields consumed in Task 8 (persist access_token, inject activity)
pub struct ExchangeOutput {
    pub access_token: String,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
}

pub trait HttpClient {
    fn post_form(&self, url: &str, body: &str) -> Result<HttpResponse, String>;
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

pub fn exchange_code(
    client: &dyn HttpClient,
    input: ExchangeInput<'_>,
) -> Result<ExchangeOutput, RuntimeError> {
    let form_body: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", input.code)
        .append_pair("redirect_uri", input.redirect_uri)
        .append_pair("client_id", input.client_id)
        .append_pair("client_secret", input.client_secret)
        .append_pair("code_verifier", input.code_verifier)
        .finish();

    let response = client
        .post_form(input.token_url, &form_body)
        .map_err(|err| RuntimeError::InvalidInput(format!("token endpoint request failed: {err}")))?;

    let body_text = String::from_utf8_lossy(&response.body).to_string();

    // Parse body: JSON or form-encoded
    let parsed = if response
        .content_type
        .as_deref()
        .map(|ct| ct.contains("json"))
        .unwrap_or(false)
        || body_text.trim_start().starts_with('{')
    {
        parse_json_body(&body_text)?
    } else {
        parse_form_body(&body_text)
    };

    if let Some(err) = parsed.error {
        return Err(RuntimeError::InvalidInput(format!(
            "token endpoint error {err}: {}",
            parsed.error_description.unwrap_or_default()
        )));
    }
    if !(200..300).contains(&response.status) {
        return Err(RuntimeError::InvalidInput(format!(
            "token endpoint HTTP {}: {body_text}",
            response.status
        )));
    }
    let access_token = parsed
        .access_token
        .ok_or_else(|| RuntimeError::InvalidInput("token response missing access_token".into()))?;

    Ok(ExchangeOutput {
        access_token,
        token_type: parsed.token_type,
        scope: parsed.scope,
        refresh_token: parsed.refresh_token,
    })
}

#[derive(Default)]
struct ParsedTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_json_body(text: &str) -> Result<ParsedTokenResponse, RuntimeError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|err| RuntimeError::InvalidInput(format!("token JSON parse: {err}")))?;
    Ok(ParsedTokenResponse {
        access_token: value.get("access_token").and_then(Value::as_str).map(str::to_string),
        token_type: value.get("token_type").and_then(Value::as_str).map(str::to_string),
        scope: value.get("scope").and_then(Value::as_str).map(str::to_string),
        refresh_token: value.get("refresh_token").and_then(Value::as_str).map(str::to_string),
        error: value.get("error").and_then(Value::as_str).map(str::to_string),
        error_description: value
            .get("error_description")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn parse_form_body(text: &str) -> ParsedTokenResponse {
    let mut out = ParsedTokenResponse::default();
    for (k, v) in form_urlencoded::parse(text.as_bytes()) {
        match k.as_ref() {
            "access_token" => out.access_token = Some(v.into_owned()),
            "token_type" => out.token_type = Some(v.into_owned()),
            "scope" => out.scope = Some(v.into_owned()),
            "refresh_token" => out.refresh_token = Some(v.into_owned()),
            "error" => out.error = Some(v.into_owned()),
            "error_description" => out.error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockClient {
        response: RefCell<Option<HttpResponse>>,
    }

    impl MockClient {
        fn with(status: u16, content_type: &str, body: &str) -> Self {
            Self {
                response: RefCell::new(Some(HttpResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                    content_type: Some(content_type.to_string()),
                })),
            }
        }
    }

    impl HttpClient for MockClient {
        fn post_form(&self, _url: &str, _body: &str) -> Result<HttpResponse, String> {
            self.response.borrow_mut().take().ok_or("already consumed".to_string())
        }
    }

    fn sample_input() -> ExchangeInput<'static> {
        ExchangeInput {
            token_url: "https://github.com/login/oauth/access_token",
            client_id: "cid",
            client_secret: "csec",
            code: "abc",
            code_verifier: "verifier",
            redirect_uri: "http://127.0.0.1:8090/v1/oauth/callback/github",
        }
    }

    #[test]
    fn exchange_code_parses_json_response() {
        let client = MockClient::with(
            200,
            "application/json",
            r#"{"access_token":"tok123","token_type":"bearer","scope":"repo"}"#,
        );
        let out = exchange_code(&client, sample_input()).unwrap();
        assert_eq!(out.access_token, "tok123");
        assert_eq!(out.token_type.as_deref(), Some("bearer"));
        assert_eq!(out.scope.as_deref(), Some("repo"));
    }

    #[test]
    fn exchange_code_parses_form_encoded_response() {
        let client = MockClient::with(
            200,
            "application/x-www-form-urlencoded",
            "access_token=tok456&token_type=bearer&scope=read",
        );
        let out = exchange_code(&client, sample_input()).unwrap();
        assert_eq!(out.access_token, "tok456");
    }

    #[test]
    fn exchange_code_returns_err_on_http_error() {
        let client = MockClient::with(500, "text/plain", "server error");
        let err = exchange_code(&client, sample_input()).unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => assert!(msg.contains("500")),
            _ => panic!("expected InvalidInput"),
        }
    }

    #[test]
    fn exchange_code_returns_err_on_oauth_error_field() {
        let client = MockClient::with(
            200,
            "application/json",
            r#"{"error":"invalid_grant","error_description":"code expired"}"#,
        );
        let err = exchange_code(&client, sample_input()).unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => {
                assert!(msg.contains("invalid_grant"));
                assert!(msg.contains("code expired"));
            }
            _ => panic!("expected InvalidInput"),
        }
    }

    #[test]
    fn exchange_code_returns_err_when_access_token_missing() {
        let client = MockClient::with(200, "application/json", r#"{"token_type":"bearer"}"#);
        let err = exchange_code(&client, sample_input()).unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => assert!(msg.contains("missing access_token")),
            _ => panic!("expected InvalidInput"),
        }
    }
}
