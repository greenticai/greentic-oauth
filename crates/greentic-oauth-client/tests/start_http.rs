// These tests validate the HTTP contract used by callers of greentic-oauth-client:
// `/oauth/start` request/response behavior and status-error propagation from the broker.
use std::collections::BTreeMap;

use greentic_oauth_client::{Client, ClientError, OwnerKind, StartRequest, Visibility};
use reqwest::StatusCode;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

async fn try_start_mock() -> Option<MockServer> {
    let Ok(server) = tokio::spawn(async { MockServer::start().await }).await else {
        return None;
    };
    Some(server)
}

fn start_request() -> StartRequest {
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
        redirect_uri: Some("https://app.example.com/oauth/callback".to_string()),
        visibility: Some(Visibility::Team),
        extra_params: Some(extra_params),
    }
}

fn build_client(base_url: &str) -> Client {
    Client::builder()
        .base_url(base_url)
        .expect("base url should parse")
        .build()
        .expect("client should build")
}

#[tokio::test]
async fn start_roundtrip_success() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping start_roundtrip_success: mock server unavailable");
            return;
        }
    };

    Mock::given(method("POST"))
        .and(path("/oauth/start"))
        .and(body_json(json!({
            "env": "dev",
            "tenant": "acme",
            "provider": "microsoft",
            "team": "ops",
            "owner_kind": "user",
            "owner_id": "alice@example.com",
            "flow_id": "flow-123",
            "scopes": ["openid", "profile"],
            "redirect_uri": "https://app.example.com/oauth/callback",
            "visibility": "team",
            "extra_params": {"prompt": "consent"}
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"start_url": "https://idp.example.com/authorize"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let response = build_client(&server.uri())
        .start(start_request())
        .await
        .expect("start should succeed");
    assert_eq!(response.start_url, "https://idp.example.com/authorize");
}

#[tokio::test]
async fn start_surfaces_json_http_error() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping start_surfaces_json_http_error: mock server unavailable");
            return;
        }
    };

    Mock::given(method("POST"))
        .and(path("/oauth/start"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_client"})))
        .expect(1)
        .mount(&server)
        .await;

    let err = build_client(&server.uri())
        .start(start_request())
        .await
        .expect_err("start should fail");
    match err {
        ClientError::HttpStatus { status, message } => {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(message, "invalid_client");
        }
        other => panic!("expected status error, got {other:?}"),
    }
}

#[tokio::test]
async fn start_surfaces_plain_text_http_error() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping start_surfaces_plain_text_http_error: mock server unavailable");
            return;
        }
    };

    Mock::given(method("POST"))
        .and(path("/oauth/start"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
        .expect(1)
        .mount(&server)
        .await;

    let err = build_client(&server.uri())
        .start(start_request())
        .await
        .expect_err("start should fail");
    match err {
        ClientError::HttpStatus { status, message } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(message, "upstream unavailable");
        }
        other => panic!("expected status error, got {other:?}"),
    }
}
