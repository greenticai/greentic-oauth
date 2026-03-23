use std::collections::BTreeMap;

pub mod extension_manifest;

use oidc_provider::{
    AuthorizeRequest, ExchangeCodeRequest, ExtensionOperation, ExtensionOperationResult,
    HostConfig, OidcComponent, OidcComponentError, OidcProviderConfig, RefreshRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

mod bindings {
    wit_bindgen::generate!({
        path: "wit/oidc-provider-runtime",
        world: "oidc-provider-runtime",
        generate_all
    });
}
use bindings::greentic::secrets_store::secrets_store;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProviderConfig {
    pub provider_id: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_id_key: Option<String>,
    pub client_secret_key: Option<String>,
    pub auth_url: String,
    pub token_url: String,
    pub default_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHostConfig {
    pub public_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEnvelope {
    pub op: String,
    pub input: Value,
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("provider error: {0}")]
    Provider(#[from] OidcComponentError),
}

pub fn dispatch(
    host: RuntimeHostConfig,
    provider: RuntimeProviderConfig,
    envelope: RuntimeEnvelope,
) -> Result<Value, RuntimeError> {
    if matches!(envelope.op.as_str(), "oidc.ingest-http" | "ingest_http") {
        return handle_ingest_http(envelope.input, provider.provider_id.as_str());
    }

    let (client_id, client_secret) = resolve_client_credentials(&provider)?;
    let component = OidcComponent::new(
        HostConfig {
            public_base_url: host.public_base_url,
        },
        OidcProviderConfig {
            provider_id: provider.provider_id,
            client_id,
            client_secret,
            auth_url: provider.auth_url,
            token_url: provider.token_url,
            default_scopes: provider.default_scopes,
        },
    )?;

    let mut execute_http = false;
    let mut redirect_uri_override: Option<String> = None;
    let result = match envelope.op.as_str() {
        "oidc.authorize-url" | "authorize-url" | "oauth.initiate_auth" => {
            let input: AuthorizeInput = serde_json::from_value(envelope.input)
                .map_err(|err| RuntimeError::InvalidInput(err.to_string()))?;
            let op = ExtensionOperation::AuthorizeUrl(AuthorizeRequest {
                tenant: input.tenant,
                state: input.state,
                code_challenge: input.code_challenge,
                scopes: input.scopes,
                extra_auth_params: input.extra_auth_params.unwrap_or_default(),
            });
            component.execute_operation(op)?
        }
        "oidc.exchange-code" | "exchange-code" | "oauth.get_access_token" => {
            let input: ExchangeInput = serde_json::from_value(envelope.input)
                .map_err(|err| RuntimeError::InvalidInput(err.to_string()))?;
            execute_http = input
                .execute_http
                .unwrap_or(matches!(envelope.op.as_str(), "oauth.get_access_token"));
            redirect_uri_override = input.redirect_uri.clone();
            component.execute_operation(ExtensionOperation::ExchangeCode(ExchangeCodeRequest {
                tenant: input.tenant,
                code: input.code,
                code_verifier: input.code_verifier,
            }))?
        }
        "oidc.refresh-token" | "refresh-token" | "oauth.request_resource_token" => {
            let input: RefreshInput = serde_json::from_value(envelope.input)
                .map_err(|err| RuntimeError::InvalidInput(err.to_string()))?;
            execute_http = input.execute_http.unwrap_or(matches!(
                envelope.op.as_str(),
                "oauth.request_resource_token"
            ));
            component.execute_operation(ExtensionOperation::RefreshToken(RefreshRequest {
                refresh_token: input.refresh_token,
                scopes: input.scopes,
            }))?
        }
        other => {
            return Err(RuntimeError::InvalidInput(format!(
                "unsupported op: {other}"
            )));
        }
    };

    if execute_http && let ExtensionOperationResult::HttpRequestPrepared(req) = &result {
        return execute_http_request(req, envelope.op.as_str(), redirect_uri_override.as_deref());
    }

    Ok(match result {
        ExtensionOperationResult::AuthorizeUrlBuilt { url, redirect_uri } => json!({
            "ok": true,
            "op": envelope.op,
            "authorize_url": url,
            "redirect_uri": redirect_uri
        }),
        ExtensionOperationResult::HttpRequestPrepared(req) => json!({
            "ok": true,
            "op": envelope.op,
            "http_request": {
                "method": req.method,
                "url": req.url,
                "headers": req.headers,
                "body_utf8": req.body.and_then(|b| String::from_utf8(b).ok()),
                "options": {
                    "timeout_ms": req.options.timeout_ms,
                    "allow_insecure": req.options.allow_insecure,
                    "follow_redirects": req.options.follow_redirects
                }
            }
        }),
    })
}

fn execute_http_request(
    req: &oidc_provider::HttpRequest,
    op: &str,
    redirect_uri_override: Option<&str>,
) -> Result<Value, RuntimeError> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = with_redirect_uri_override(req, redirect_uri_override);
        let response = oidc_provider::wit_http::send_via_host(&request)
            .map_err(|err| RuntimeError::InvalidInput(format!("http request build failed: {err}")))?
            .map_err(|err| {
                RuntimeError::InvalidInput(format!(
                    "transport error: {} ({})",
                    err.message, err.code
                ))
            })?;

        let status = response.status;
        let body = response.body.unwrap_or_default();
        let payload = parse_token_payload(&body);
        if !(200..300).contains(&status) {
            return Err(RuntimeError::InvalidInput(token_error_message(
                status, &payload,
            )));
        }

        let access_token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                RuntimeError::InvalidInput(format!(
                    "token endpoint response missing access_token: {payload}"
                ))
            })?;

        return Ok(json!({
            "ok": true,
            "op": op,
            "http_status": status,
            "access_token": access_token,
            "refresh_token": payload.get("refresh_token").cloned().unwrap_or(Value::Null),
            "token_type": payload.get("token_type").cloned().unwrap_or(Value::Null),
            "scope": payload.get("scope").cloned().unwrap_or(Value::Null),
            "expires_in": payload.get("expires_in").cloned().unwrap_or(Value::Null),
            "token_response": payload
        }));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        let _ = op;
        let _ = redirect_uri_override;
        Err(RuntimeError::InvalidInput(
            "execute_http is only supported in wasm runtime".to_string(),
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn with_redirect_uri_override(
    req: &oidc_provider::HttpRequest,
    redirect_uri_override: Option<&str>,
) -> oidc_provider::HttpRequest {
    let Some(redirect_uri_override) =
        redirect_uri_override.filter(|value| !value.trim().is_empty())
    else {
        return req.clone();
    };
    let Some(body) = req.body.as_ref() else {
        return req.clone();
    };

    let mut params = url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<Vec<(String, String)>>();
    if params.is_empty() {
        return req.clone();
    }

    let mut found = false;
    for (name, value) in &mut params {
        if name == "redirect_uri" {
            *value = redirect_uri_override.to_string();
            found = true;
            break;
        }
    }
    if !found {
        params.push((
            "redirect_uri".to_string(),
            redirect_uri_override.to_string(),
        ));
    }

    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in params {
        encoded.append_pair(&name, &value);
    }

    let mut patched = req.clone();
    patched.body = Some(encoded.finish().into_bytes());
    patched
}

#[cfg(target_arch = "wasm32")]
fn parse_token_payload(body: &[u8]) -> Value {
    if body.is_empty() {
        return json!({});
    }
    if let Ok(json_value) = serde_json::from_slice::<Value>(body) {
        return json_value;
    }

    let text = String::from_utf8_lossy(body);
    let mut form = serde_json::Map::new();
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        form.insert(key.into_owned(), Value::String(value.into_owned()));
    }
    if form.is_empty() {
        json!({
            "raw": text.to_string()
        })
    } else {
        Value::Object(form)
    }
}

#[cfg(target_arch = "wasm32")]
fn token_error_message(status: u16, payload: &Value) -> String {
    if let Some(description) = payload.get("error_description").and_then(Value::as_str) {
        return format!("token endpoint returned status {status}: {description}");
    }
    if let Some(message) = payload.get("message").and_then(Value::as_str) {
        return format!("token endpoint returned status {status}: {message}");
    }
    if let Some(error) = payload.get("error").and_then(Value::as_str) {
        return format!("token endpoint returned status {status}: {error}");
    }
    format!("token endpoint returned status {status}: {payload}")
}

fn handle_ingest_http(input: Value, default_provider_id: &str) -> Result<Value, RuntimeError> {
    let parsed: IngestHttpInput =
        serde_json::from_value(input).map_err(|err| RuntimeError::InvalidInput(err.to_string()))?;
    let method = parsed.method.unwrap_or_else(|| "GET".to_string());
    let path = parsed.path.unwrap_or_default();
    let query = collect_query_pairs(&path, &parsed.query);

    let state = query.get("state").cloned().unwrap_or_default();
    let code = query.get("code").cloned();
    let error = query.get("error").cloned();
    let error_description = query.get("error_description").cloned();

    let provider_id = parsed
        .provider
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| default_provider_id.to_string());
    let tenant = parsed
        .tenant_hint
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| tenant_from_ingress_path(&path))
        .unwrap_or_else(|| "default".to_string());

    let (status, body_json) =
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("POST") {
            (
                405u16,
                json!({
                    "ok": false,
                    "error": "only GET/POST callbacks are supported",
                    "provider_id": provider_id,
                    "tenant": tenant,
                    "method": method
                }),
            )
        } else if state.is_empty() {
            (
                400u16,
                json!({
                    "ok": false,
                    "error": "missing state query parameter",
                    "provider_id": provider_id,
                    "tenant": tenant
                }),
            )
        } else if code.is_none() && error.is_none() {
            (
                400u16,
                json!({
                    "ok": false,
                    "error": "missing code or error query parameter",
                    "provider_id": provider_id,
                    "tenant": tenant,
                    "state": state
                }),
            )
        } else {
            (
                200u16,
                json!({
                    "ok": error.is_none(),
                    "provider_id": provider_id,
                    "tenant": tenant,
                    "state": state,
                    "code": code,
                    "error": error,
                    "error_description": error_description
                }),
            )
        };

    Ok(json!({
        "http": {
            "status": status,
            "headers": {
                "content-type": "application/json; charset=utf-8",
                "cache-control": "no-store"
            },
            "body_json": body_json
        },
        "events": []
    }))
}

fn collect_query_pairs(path: &str, query: &[(String, String)]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    for (name, value) in query {
        if !name.trim().is_empty() {
            out.insert(name.clone(), value.clone());
        }
    }

    if let Some(raw_query) = path.split_once('?').map(|(_, rhs)| rhs) {
        for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
            if !name.is_empty() {
                out.insert(name.into_owned(), value.into_owned());
            }
        }
    }

    out
}

fn tenant_from_ingress_path(path: &str) -> Option<String> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let segments = path_without_query
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return None;
    }

    if segments[0].eq_ignore_ascii_case("v1") {
        if segments.len() >= 5 && segments[2].eq_ignore_ascii_case("ingress") {
            return Some(segments[4].to_string());
        }
        return None;
    }

    if segments.len() >= 4 && segments[1].eq_ignore_ascii_case("ingress") {
        return Some(segments[3].to_string());
    }

    None
}

fn resolve_client_credentials(
    provider: &RuntimeProviderConfig,
) -> Result<(String, Option<String>), RuntimeError> {
    let client_id = match provider
        .client_id
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        Some(value) => value.to_string(),
        None => {
            let key = provider
                .client_id_key
                .as_ref()
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    RuntimeError::InvalidInput("client_id or client_id_key is required".into())
                })?;
            read_secret_utf8(key)?.ok_or_else(|| {
                RuntimeError::InvalidInput(format!("missing secret for key `{key}`"))
            })?
        }
    };

    let client_secret = match provider
        .client_secret
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        Some(value) => Some(value.to_string()),
        None => {
            if let Some(key) = provider
                .client_secret_key
                .as_ref()
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
            {
                Some(read_secret_utf8(key)?.ok_or_else(|| {
                    RuntimeError::InvalidInput(format!("missing secret for key `{key}`"))
                })?)
            } else {
                None
            }
        }
    };

    Ok((client_id, client_secret))
}

fn read_secret_utf8(key: &str) -> Result<Option<String>, RuntimeError> {
    match secrets_store::get(key) {
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| RuntimeError::InvalidInput(format!("secret `{key}` is not valid utf-8"))),
        Ok(None) => Ok(None),
        Err(err) => Err(RuntimeError::InvalidInput(format!(
            "secrets-store error for `{key}`: {err:?}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AuthorizeInput {
    tenant: String,
    state: String,
    code_challenge: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    extra_auth_params: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExchangeInput {
    tenant: String,
    code: String,
    code_verifier: String,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    execute_http: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RefreshInput {
    refresh_token: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    execute_http: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IngestHttpInput {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    tenant_hint: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    query: Vec<(String, String)>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WitDispatchInput {
    host: RuntimeHostConfig,
    provider: RuntimeProviderConfig,
    input: Value,
}

#[allow(dead_code)]
struct Component;

impl bindings::exports::greentic::provider_schema_core::schema_core_api::Guest for Component {
    fn describe() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "provider_type": "oauth.oidc.generic.executable",
            "capabilities": ["oauth"],
            "ops": ["authorize-url", "exchange-code", "refresh-token", "ingest_http"]
        }))
        .unwrap_or_default()
    }

    fn validate_config(config_json: Vec<u8>) -> Vec<u8> {
        let payload: Value = match serde_json::from_slice(&config_json) {
            Ok(value) => value,
            Err(err) => {
                return json!({
                    "ok": false,
                    "error": format!("invalid config json: {err}")
                })
                .to_string()
                .into_bytes();
            }
        };
        let cfg = payload.get("config").unwrap_or(&payload).clone();
        match serde_json::from_value::<RuntimeProviderConfig>(cfg) {
            Ok(_) => json!({"ok": true}).to_string().into_bytes(),
            Err(err) => json!({
                "ok": false,
                "error": format!("invalid provider config: {err}")
            })
            .to_string()
            .into_bytes(),
        }
    }

    fn healthcheck() -> Vec<u8> {
        json!({"status": "healthy"}).to_string().into_bytes()
    }

    fn invoke(op: String, input_json: Vec<u8>) -> Vec<u8> {
        let result = match serde_json::from_slice::<WitDispatchInput>(&input_json) {
            Ok(parsed) => dispatch(
                parsed.host,
                parsed.provider,
                RuntimeEnvelope {
                    op,
                    input: parsed.input,
                },
            ),
            Err(_) => {
                let raw_input: Value = match serde_json::from_slice(&input_json) {
                    Ok(value) => value,
                    Err(err) => {
                        return json!({
                            "ok": false,
                            "error": format!("invalid input json: {err}")
                        })
                        .to_string()
                        .into_bytes();
                    }
                };
                if matches!(op.as_str(), "oidc.ingest-http" | "ingest_http") {
                    handle_ingest_http(raw_input, "generic_oidc")
                } else {
                    Err(RuntimeError::InvalidInput(
                        "runtime envelope required for this operation".to_string(),
                    ))
                }
            }
        };

        match result {
            Ok(value) => serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"ok\":false}".to_vec()),
            Err(err) => json!({
                "ok": false,
                "error": err.to_string()
            })
            .to_string()
            .into_bytes(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
bindings::export!(Component with_types_in bindings);

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> RuntimeHostConfig {
        RuntimeHostConfig {
            public_base_url: "https://auth.acme.example".into(),
        }
    }

    fn provider() -> RuntimeProviderConfig {
        RuntimeProviderConfig {
            provider_id: "oidc-generic".into(),
            client_id: Some("client-123".into()),
            client_secret: Some("secret-123".into()),
            client_id_key: None,
            client_secret_key: None,
            auth_url: "https://issuer.example.com/oauth2/v1/authorize".into(),
            token_url: "https://issuer.example.com/oauth2/v1/token".into(),
            default_scopes: vec!["openid".into(), "profile".into()],
        }
    }

    #[test]
    fn dispatches_authorize_operation() {
        let output = dispatch(
            host(),
            provider(),
            RuntimeEnvelope {
                op: "oidc.authorize-url".into(),
                input: json!({
                    "tenant": "acme",
                    "state": "state-1",
                    "code_challenge": "challenge-1"
                }),
            },
        )
        .expect("output");

        assert_eq!(output["ok"], true);
        assert!(
            output["authorize_url"]
                .as_str()
                .expect("authorize_url")
                .contains("response_type=code")
        );
    }

    #[test]
    fn dispatches_exchange_operation() {
        let output = dispatch(
            host(),
            provider(),
            RuntimeEnvelope {
                op: "oidc.exchange-code".into(),
                input: json!({
                    "tenant": "acme",
                    "code": "code-1",
                    "code_verifier": "verifier-1"
                }),
            },
        )
        .expect("output");

        assert_eq!(output["ok"], true);
        assert_eq!(
            output["http_request"]["url"],
            "https://issuer.example.com/oauth2/v1/token"
        );
    }

    #[test]
    fn dispatches_ingest_http_callback_operation() {
        let output = dispatch(
            host(),
            provider(),
            RuntimeEnvelope {
                op: "ingest_http".into(),
                input: json!({
                    "provider": "oauth-oidc-generic",
                    "method": "GET",
                    "path": "/v1/oauth/ingress/oauth-oidc-generic/acme/default",
                    "query": [["code", "code-1"], ["state", "state-1"]]
                }),
            },
        )
        .expect("output");

        assert_eq!(output["http"]["status"], 200);
        assert_eq!(output["http"]["body_json"]["ok"], true);
        assert_eq!(output["http"]["body_json"]["tenant"], "acme");
    }
}
