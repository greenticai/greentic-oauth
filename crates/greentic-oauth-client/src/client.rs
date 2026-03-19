use std::{collections::BTreeMap, time::Duration};

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ClientError;

/// High-level HTTP client for the Greentic OAuth broker.
#[derive(Clone)]
pub struct Client {
    http: HttpClient,
    base_url: Url,
}

/// Builder for [`Client`].
pub struct ClientBuilder {
    base_url: Option<Url>,
    timeout: Duration,
}

impl ClientBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the broker base URL (e.g. `https://broker.example.com/`).
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, ClientError> {
        let parsed = Url::parse(base_url.as_ref())
            .map_err(|err| ClientError::InvalidBaseUrl(format!("{} ({err})", base_url.as_ref())))?;
        self.base_url = Some(parsed);
        Ok(self)
    }

    /// Override the HTTP client timeout (defaults to 30 seconds).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Finalise the builder and create a [`Client`].
    pub fn build(self) -> Result<Client, ClientError> {
        let base_url = self.base_url.ok_or(ClientError::MissingBaseUrl)?;
        let http = HttpClient::builder().timeout(self.timeout).build()?;
        Ok(Client { http, base_url })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Begin building a new client.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Call `/oauth/start` to create a new authorization session.
    pub async fn start(&self, request: StartRequest) -> Result<StartResponse, ClientError> {
        let url = self.base_url.join("oauth/start")?;
        let payload = ApiStartRequest::from(&request);
        let response = self.http.post(url).json(&payload).send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let message = extract_error_message(&body);
            return Err(ClientError::status(status, message));
        }

        let body: ApiStartResponse = response.json().await?;
        Ok(StartResponse {
            start_url: body.start_url,
        })
    }
}

fn extract_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error").cloned())
        .and_then(|value| {
            if value.is_string() {
                value.as_str().map(|s| s.to_string())
            } else {
                Some(value.to_string())
            }
        })
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| body.to_string())
}

#[derive(Clone, Debug)]
pub struct StartRequest {
    pub env: String,
    pub tenant: String,
    pub provider: String,
    pub team: Option<String>,
    pub owner_kind: OwnerKind,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Option<Visibility>,
    pub extra_params: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize)]
struct ApiStartRequest<'a> {
    env: &'a str,
    tenant: &'a str,
    provider: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<&'a str>,
    owner_kind: &'a str,
    owner_id: &'a str,
    flow_id: &'a str,
    #[serde(skip_serializing_if = "slice_is_empty")]
    scopes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra_params: Option<&'a BTreeMap<String, String>>,
}

impl<'a> From<&'a StartRequest> for ApiStartRequest<'a> {
    fn from(request: &'a StartRequest) -> Self {
        Self {
            env: &request.env,
            tenant: &request.tenant,
            provider: &request.provider,
            team: request.team.as_deref(),
            owner_kind: request.owner_kind.as_str(),
            owner_id: &request.owner_id,
            flow_id: &request.flow_id,
            scopes: &request.scopes,
            redirect_uri: request.redirect_uri.as_deref(),
            visibility: request.visibility.as_ref().map(Visibility::as_str),
            extra_params: request.extra_params.as_ref(),
        }
    }
}

fn slice_is_empty<T>(value: &&[T]) -> bool {
    value.is_empty()
}

#[derive(Clone, Debug, Deserialize)]
struct ApiStartResponse {
    start_url: String,
}

/// Response returned by [`Client::start`].
#[derive(Clone, Debug)]
pub struct StartResponse {
    pub start_url: String,
}

/// Owner classification for the OAuth flow.
#[derive(Clone, Debug)]
pub enum OwnerKind {
    User,
    Service,
}

impl OwnerKind {
    fn as_str(&self) -> &'static str {
        match self {
            OwnerKind::User => "user",
            OwnerKind::Service => "service",
        }
    }
}

/// Visibility requested for the resulting token.
#[derive(Clone, Debug)]
pub enum Visibility {
    Private,
    Team,
    Tenant,
}

impl Visibility {
    fn as_str(&self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Team => "team",
            Visibility::Tenant => "tenant",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These tests validate the client-side request mapping and error parsing used by SDK/app
    // integrations so broker calls remain stable even when request shapes evolve.
    fn full_start_request() -> StartRequest {
        let mut extra_params = BTreeMap::new();
        extra_params.insert("prompt".to_string(), "consent".to_string());

        StartRequest {
            env: "dev".to_string(),
            tenant: "acme".to_string(),
            provider: "microsoft".to_string(),
            team: Some("ops".to_string()),
            owner_kind: OwnerKind::User,
            owner_id: "alice@example.com".to_string(),
            flow_id: "flow-123".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            visibility: Some(Visibility::Team),
            extra_params: Some(extra_params),
        }
    }

    #[test]
    fn builder_requires_base_url() {
        match Client::builder().build() {
            Ok(_) => panic!("build should fail without base url"),
            Err(err) => assert!(matches!(err, ClientError::MissingBaseUrl)),
        }
    }

    #[test]
    fn builder_rejects_invalid_base_url() {
        match Client::builder().base_url("not a valid url") {
            Ok(_) => panic!("invalid base url should fail"),
            Err(err) => match err {
                ClientError::InvalidBaseUrl(message) => {
                    assert!(message.contains("not a valid url"));
                }
                other => panic!("expected invalid base url error, got {other:?}"),
            },
        }
    }

    #[test]
    fn api_start_request_serializes_all_fields() {
        let request = full_start_request();
        let payload = ApiStartRequest::from(&request);
        let body = serde_json::to_value(payload).expect("request payload should serialize");

        assert_eq!(body.get("env"), Some(&json!("dev")));
        assert_eq!(body.get("tenant"), Some(&json!("acme")));
        assert_eq!(body.get("provider"), Some(&json!("microsoft")));
        assert_eq!(body.get("team"), Some(&json!("ops")));
        assert_eq!(body.get("owner_kind"), Some(&json!("user")));
        assert_eq!(body.get("owner_id"), Some(&json!("alice@example.com")));
        assert_eq!(body.get("flow_id"), Some(&json!("flow-123")));
        assert_eq!(body.get("scopes"), Some(&json!(["openid", "profile"])));
        assert_eq!(
            body.get("redirect_uri"),
            Some(&json!("https://app.example.com/callback"))
        );
        assert_eq!(body.get("visibility"), Some(&json!("team")));
        assert_eq!(
            body.get("extra_params"),
            Some(&json!({"prompt": "consent"}))
        );
    }

    #[test]
    fn api_start_request_omits_empty_optional_fields() {
        let request = StartRequest {
            env: "dev".to_string(),
            tenant: "acme".to_string(),
            provider: "microsoft".to_string(),
            team: None,
            owner_kind: OwnerKind::Service,
            owner_id: "svc-1".to_string(),
            flow_id: "flow-123".to_string(),
            scopes: Vec::new(),
            redirect_uri: None,
            visibility: None,
            extra_params: None,
        };
        let payload = ApiStartRequest::from(&request);
        let body = serde_json::to_value(payload).expect("request payload should serialize");

        assert!(body.get("team").is_none());
        assert!(body.get("scopes").is_none());
        assert!(body.get("redirect_uri").is_none());
        assert!(body.get("visibility").is_none());
        assert!(body.get("extra_params").is_none());
        assert_eq!(body.get("owner_kind"), Some(&json!("service")));
    }

    #[test]
    fn extract_error_message_prefers_error_field() {
        let body = r#"{"error":"invalid_client"}"#;
        assert_eq!(extract_error_message(body), "invalid_client");
    }

    #[test]
    fn extract_error_message_serializes_non_string_error_field() {
        let body = r#"{"error":{"code":"invalid_client","status":400}}"#;
        let message = extract_error_message(body);
        assert!(message.contains("invalid_client"));
        assert!(message.contains("400"));
    }

    #[test]
    fn extract_error_message_falls_back_to_raw_body() {
        let body = "upstream unavailable";
        assert_eq!(extract_error_message(body), "upstream unavailable");
    }

    #[test]
    fn owner_kind_and_visibility_string_values_are_stable() {
        assert_eq!(OwnerKind::User.as_str(), "user");
        assert_eq!(OwnerKind::Service.as_str(), "service");
        assert_eq!(Visibility::Private.as_str(), "private");
        assert_eq!(Visibility::Team.as_str(), "team");
        assert_eq!(Visibility::Tenant.as_str(), "tenant");
    }
}
