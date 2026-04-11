//! Best-effort injection of oauth_login_success activity into the
//! originating webchat conversation via loopback HTTP.
//!
//! Uses a new `HttpClientForInject` trait (bearer-aware) so tests can mock it.

use serde_json::json;

use crate::RuntimeError;
use crate::token_exchange::HttpResponse;

pub trait HttpClientForInject {
    fn post_json_bearer(
        &self,
        url: &str,
        token: Option<&str>,
        json_body: &str,
    ) -> Result<HttpResponse, String>;
}

pub fn inject_oauth_login_success<C: HttpClientForInject>(
    client: &C,
    public_base_url: &str,
    tenant: &str,
    conversation_id: &str,
) -> Result<(), RuntimeError> {
    let base = public_base_url.trim_end_matches('/');

    // Step 1: mint a Direct Line token via loopback
    let mint_url = format!("{base}/v1/messaging/webchat/{tenant}/token?tenant={tenant}");
    let mint_response = client
        .post_json_bearer(&mint_url, None, "{}")
        .map_err(|err| RuntimeError::InvalidInput(format!("mint token failed: {err}")))?;
    if !(200..300).contains(&mint_response.status) {
        return Err(RuntimeError::InvalidInput(format!(
            "mint token HTTP {}",
            mint_response.status
        )));
    }
    let mint_body = String::from_utf8_lossy(&mint_response.body).to_string();
    let mint_json: serde_json::Value = serde_json::from_str(&mint_body)
        .map_err(|err| RuntimeError::InvalidInput(format!("mint token body not JSON: {err}")))?;
    let token = mint_json
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RuntimeError::InvalidInput("mint token response missing token".into()))?;

    // Step 2: POST synthetic activity
    let activities_url = format!(
        "{base}/v1/messaging/webchat/{tenant}/v3/directline/conversations/{conversation_id}/activities?tenant={tenant}",
    );
    let activity = json!({
        "type": "message",
        "from": {"id": "system", "name": "OAuth Callback"},
        "text": "oauth_login_success",
    });
    let activity_body = serde_json::to_string(&activity)
        .map_err(|err| RuntimeError::InvalidInput(format!("serialize activity: {err}")))?;
    let post_response = client
        .post_json_bearer(&activities_url, Some(token), &activity_body)
        .map_err(|err| RuntimeError::InvalidInput(format!("inject activity failed: {err}")))?;
    if !(200..300).contains(&post_response.status) {
        return Err(RuntimeError::InvalidInput(format!(
            "inject activity HTTP {}",
            post_response.status
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct SeqClient {
        responses: RefCell<Vec<Result<HttpResponse, String>>>,
        captured_urls: RefCell<Vec<String>>,
    }

    impl SeqClient {
        fn with(responses: Vec<Result<HttpResponse, String>>) -> Self {
            Self {
                responses: RefCell::new(responses),
                captured_urls: RefCell::new(vec![]),
            }
        }
    }

    impl HttpClientForInject for SeqClient {
        fn post_json_bearer(
            &self,
            url: &str,
            _token: Option<&str>,
            _body: &str,
        ) -> Result<HttpResponse, String> {
            self.captured_urls.borrow_mut().push(url.to_string());
            self.responses.borrow_mut().remove(0)
        }
    }

    fn ok_response(status: u16, body: &str) -> Result<HttpResponse, String> {
        Ok(HttpResponse {
            status,
            body: body.as_bytes().to_vec(),
            content_type: Some("application/json".to_string()),
        })
    }

    #[test]
    fn inject_mints_token_then_posts_activity() {
        let client = SeqClient::with(vec![
            ok_response(200, r#"{"token":"mock-token"}"#),
            ok_response(201, r#"{"id":"activity-1"}"#),
        ]);
        inject_oauth_login_success(&client, "http://127.0.0.1:8090", "demo", "conv-1").unwrap();
        let urls = client.captured_urls.borrow();
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("/v1/messaging/webchat/demo/token"));
        assert!(urls[1].contains("/v1/messaging/webchat/demo/v3/directline/conversations/conv-1/activities"));
    }

    #[test]
    fn inject_returns_err_when_mint_token_fails() {
        let client = SeqClient::with(vec![ok_response(500, "boom")]);
        let err = inject_oauth_login_success(&client, "http://127.0.0.1:8090", "demo", "conv-1")
            .unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => assert!(msg.contains("500")),
            _ => panic!(),
        }
    }

    #[test]
    fn inject_returns_err_when_activity_post_fails() {
        let client = SeqClient::with(vec![
            ok_response(200, r#"{"token":"mock-token"}"#),
            ok_response(401, "unauthorized"),
        ]);
        let err = inject_oauth_login_success(&client, "http://127.0.0.1:8090", "demo", "conv-1")
            .unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => assert!(msg.contains("401")),
            _ => panic!(),
        }
    }
}
