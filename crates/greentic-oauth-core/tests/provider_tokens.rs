use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures_util::future::FutureExt;
use greentic_oauth_core::{
    ProviderOAuthClientConfig, ProviderOAuthFlow, ProviderSecretStore, ProviderTokenError,
    ProviderTokenService, TenantCtx, client_credentials_path, refresh_token_path,
};
use greentic_types::{EnvId, TenantId};
use time::OffsetDateTime;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

async fn try_start_mock() -> Option<MockServer> {
    let fut = MockServer::start();
    let fut = std::panic::AssertUnwindSafe(fut);
    fut.catch_unwind().await.ok()
}

#[derive(Clone, Default)]
struct InMemorySecrets {
    configs: Arc<Mutex<HashMap<String, ProviderOAuthClientConfig>>>,
    refresh_tokens: Arc<Mutex<HashMap<String, Option<String>>>>,
    refresh_load_calls: Arc<Mutex<Vec<String>>>,
}

impl InMemorySecrets {
    fn insert(&self, provider_id: &str, config: ProviderOAuthClientConfig) {
        let mut guard = self.configs.lock().expect("config lock");
        guard.insert(provider_id.to_owned(), config);
    }

    fn set_refresh_token(&self, provider_id: &str, refresh_token: Option<&str>) {
        let mut guard = self.refresh_tokens.lock().expect("refresh token lock");
        guard.insert(provider_id.to_owned(), refresh_token.map(str::to_string));
    }

    fn refresh_load_call_count(&self, provider_id: &str) -> usize {
        let guard = self
            .refresh_load_calls
            .lock()
            .expect("refresh load calls lock");
        guard
            .iter()
            .filter(|called| called.as_str() == provider_id)
            .count()
    }
}

#[async_trait]
impl ProviderSecretStore for InMemorySecrets {
    async fn load_client_config(
        &self,
        _tenant_ctx: &TenantCtx,
        provider_id: &str,
    ) -> Result<ProviderOAuthClientConfig, ProviderTokenError> {
        let guard = self.configs.lock().expect("config lock");
        guard
            .get(provider_id)
            .cloned()
            .ok_or_else(|| ProviderTokenError::MissingConfig {
                provider: provider_id.to_owned(),
                missing: "client config".into(),
            })
    }

    async fn load_refresh_token(
        &self,
        _tenant_ctx: &TenantCtx,
        provider_id: &str,
    ) -> Result<Option<String>, ProviderTokenError> {
        self.refresh_load_calls
            .lock()
            .expect("refresh load calls lock")
            .push(provider_id.to_owned());

        let guard = self.refresh_tokens.lock().expect("refresh token lock");
        Ok(guard.get(provider_id).cloned().flatten())
    }
}

fn tenant_ctx() -> TenantCtx {
    TenantCtx::new(
        EnvId::try_from("dev").expect("env"),
        TenantId::try_from("acme").expect("tenant"),
    )
}

#[tokio::test]
async fn client_credentials_roundtrip() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping client_credentials_roundtrip: mock server unavailable");
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=custom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc",
            "token_type": "Bearer",
            "expires_in": 120,
            "scope": "custom email.read"
        })))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph-email",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec!["email.read".into()],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let token = service
        .get_provider_access_token(&tenant_ctx(), "msgraph-email", &[String::from("custom")])
        .await
        .expect("token");

    assert_eq!(token.access_token, "abc");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.scopes, vec!["custom", "email.read"]);
    assert!(token.expires_at > OffsetDateTime::now_utc());
}

#[tokio::test]
async fn reuses_cached_token_until_expired() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping reuses_cached_token_until_expired: mock server unavailable");
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cached",
            "token_type": "Bearer",
            "expires_in": 600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "slack-bot",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let first = service
        .get_provider_access_token(&tenant_ctx(), "slack-bot", &[])
        .await
        .expect("token");
    let second = service
        .get_provider_access_token(&tenant_ctx(), "slack-bot", &[])
        .await
        .expect("token");

    assert_eq!(first.access_token, second.access_token);
    server.verify().await;
}

#[tokio::test]
async fn unsupported_flow_is_rejected() {
    let secrets = InMemorySecrets::default();
    secrets.insert(
        "teams-channel-webhook",
        ProviderOAuthClientConfig {
            token_url: "https://auth.example/token".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec!["scope.a".into()],
            audience: None,
            flow: Some(ProviderOAuthFlow::AuthorizationCode),
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "teams-channel-webhook", &[])
        .await
        .expect_err("should reject flow");

    assert!(matches!(err, ProviderTokenError::UnsupportedFlow(_)));
}

#[tokio::test]
async fn missing_config_surfaces_error() {
    let secrets = InMemorySecrets::default();
    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "missing", &[])
        .await
        .expect_err("missing config");

    assert!(matches!(err, ProviderTokenError::MissingConfig { .. }));
}

#[tokio::test]
async fn token_endpoint_error_surfaces_status_and_body() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!(
                "skipping token_endpoint_error_surfaces_status_and_body: mock server unavailable"
            );
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("denied"))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect_err("expected token endpoint failure");

    match err {
        ProviderTokenError::TokenEndpoint { status, body } => {
            assert_eq!(status, 401);
            assert!(body.contains("denied"));
        }
        other => panic!("expected token endpoint error, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_json_response_is_rejected() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping invalid_json_response_is_rejected: mock server unavailable");
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect_err("expected invalid json response");

    assert!(matches!(err, ProviderTokenError::InvalidResponse(_)));
}

#[tokio::test]
async fn empty_access_token_is_rejected() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping empty_access_token_is_rejected: mock server unavailable");
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "",
            "token_type": "Bearer",
            "expires_in": 60
        })))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect_err("expected missing access token error");

    match err {
        ProviderTokenError::InvalidResponse(msg) => {
            assert!(
                msg.contains("missing access_token"),
                "actual message: {msg}"
            );
        }
        other => panic!("expected invalid response error, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_token_falls_back_to_secret_store_and_defaults_token_type() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!(
                "skipping refresh_token_falls_back_to_secret_store_and_defaults_token_type: mock server unavailable"
            );
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc",
            "expires_in": 60
        })))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );
    secrets.set_refresh_token("msgraph", Some("stored-refresh"));

    let service = ProviderTokenService::new(secrets.clone());
    let token = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect("token");

    assert_eq!(token.refresh_token.as_deref(), Some("stored-refresh"));
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(secrets.refresh_load_call_count("msgraph"), 1);
}

#[tokio::test]
async fn response_refresh_token_takes_precedence_over_secret_store() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!(
                "skipping response_refresh_token_takes_precedence_over_secret_store: mock server unavailable"
            );
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc",
            "token_type": "Bearer",
            "refresh_token": "payload-refresh",
            "expires_in": 60
        })))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );
    secrets.set_refresh_token("msgraph", Some("stored-refresh"));

    let service = ProviderTokenService::new(secrets.clone());
    let token = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect("token");

    assert_eq!(token.refresh_token.as_deref(), Some("payload-refresh"));
    assert_eq!(secrets.refresh_load_call_count("msgraph"), 0);
}

#[tokio::test]
async fn default_scopes_are_used_when_request_scopes_are_empty() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!(
                "skipping default_scopes_are_used_when_request_scopes_are_empty: mock server unavailable"
            );
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("scope=mail.read+openid+mail.read"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc",
            "token_type": "Bearer",
            "expires_in": 60
        })))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec!["mail.read".into(), "openid".into(), "mail.read".into()],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let token = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect("token");

    assert_eq!(token.scopes, vec!["mail.read", "openid"]);
}

#[tokio::test]
async fn audience_and_extra_params_are_sent_to_token_endpoint() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!(
                "skipping audience_and_extra_params_are_sent_to_token_endpoint: mock server unavailable"
            );
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("audience=api%3A%2F%2Facme"))
        .and(body_string_contains("prompt=consent"))
        .and(body_string_contains(
            "resource=https%3A%2F%2Fgraph.microsoft.com%2F.default",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc",
            "token_type": "Bearer",
            "expires_in": 60
        })))
        .mount(&server)
        .await;

    let mut extra = BTreeMap::new();
    extra.insert("prompt".to_string(), "consent".to_string());
    extra.insert(
        "resource".to_string(),
        "https://graph.microsoft.com/.default".to_string(),
    );

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: Some("api://acme".into()),
            flow: None,
            extra_params: Some(extra),
        },
    );

    let service = ProviderTokenService::new(secrets);
    let token = service
        .get_provider_access_token(&tenant_ctx(), "msgraph", &[])
        .await
        .expect("token");

    assert_eq!(token.access_token, "abc");
}

#[test]
fn secrets_paths_include_provider_and_tenant() {
    let ctx = tenant_ctx();

    assert_eq!(
        client_credentials_path(&ctx, "msgraph"),
        "oauth/msgraph/acme/client"
    );
    assert_eq!(
        refresh_token_path(&ctx, "msgraph"),
        "oauth/msgraph/acme/refresh-token"
    );
}
