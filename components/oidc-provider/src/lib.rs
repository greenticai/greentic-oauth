use std::collections::BTreeMap;

use thiserror::Error;
use url::Url;

const ALLOWED_EXTRA_AUTH_PARAMS: [&str; 5] =
    ["prompt", "login_hint", "access_type", "resource", "claims"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub public_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProviderConfig {
    pub provider_id: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_url: String,
    pub token_url: String,
    pub default_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    pub tenant: String,
    pub state: String,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub extra_auth_params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeCodeRequest {
    pub tenant: String,
    pub code: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcComponent {
    host: HostConfig,
    provider: OidcProviderConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionOperation {
    AuthorizeUrl(AuthorizeRequest),
    ExchangeCode(ExchangeCodeRequest),
    RefreshToken(RefreshRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionOperationResult {
    AuthorizeUrlBuilt { url: String, redirect_uri: String },
    HttpRequestPrepared(HttpRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestOptions {
    pub timeout_ms: Option<u32>,
    pub allow_insecure: Option<bool>,
    pub follow_redirects: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub options: HttpRequestOptions,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OidcComponentError {
    #[error("invalid public_base_url: {0}")]
    InvalidPublicBaseUrl(String),
    #[error("public_base_url must use https")]
    InsecurePublicBaseUrl,
    #[error("invalid provider auth_url: {0}")]
    InvalidAuthUrl(String),
    #[error("invalid provider token_url: {0}")]
    InvalidTokenUrl(String),
    #[error("provider endpoints must use https")]
    InsecureProviderEndpoint,
    #[error("required field `{0}` is empty")]
    MissingField(&'static str),
}

impl OidcComponent {
    pub fn provider_id(&self) -> &str {
        &self.provider.provider_id
    }

    pub fn new(host: HostConfig, provider: OidcProviderConfig) -> Result<Self, OidcComponentError> {
        if provider.provider_id.trim().is_empty() {
            return Err(OidcComponentError::MissingField("provider_id"));
        }
        if provider.client_id.trim().is_empty() {
            return Err(OidcComponentError::MissingField("client_id"));
        }
        if host.public_base_url.trim().is_empty() {
            return Err(OidcComponentError::MissingField("public_base_url"));
        }

        validate_https_url(&host.public_base_url)
            .map_err(OidcComponentError::InvalidPublicBaseUrl)
            .and_then(|url| {
                if url.scheme() == "https" || (url.scheme() == "http" && is_loopback_host(&url)) {
                    Ok(url)
                } else {
                    Err(OidcComponentError::InsecurePublicBaseUrl)
                }
            })?;

        validate_https_url(&provider.auth_url)
            .map_err(OidcComponentError::InvalidAuthUrl)
            .and_then(|url| {
                if url.scheme() != "https" {
                    Err(OidcComponentError::InsecureProviderEndpoint)
                } else {
                    Ok(url)
                }
            })?;
        validate_https_url(&provider.token_url)
            .map_err(OidcComponentError::InvalidTokenUrl)
            .and_then(|url| {
                if url.scheme() != "https" {
                    Err(OidcComponentError::InsecureProviderEndpoint)
                } else {
                    Ok(url)
                }
            })?;

        Ok(Self { host, provider })
    }

    pub fn redirect_uri(&self, tenant: &str) -> Result<String, OidcComponentError> {
        if tenant.trim().is_empty() {
            return Err(OidcComponentError::MissingField("tenant"));
        }
        let mut base = Url::parse(&self.host.public_base_url)
            .map_err(|err| OidcComponentError::InvalidPublicBaseUrl(err.to_string()))?;
        base.set_path(&format!(
            "/oauth/callback/{tenant}/{}",
            self.provider.provider_id
        ));
        base.set_query(None);
        Ok(base.to_string())
    }

    pub fn authorize_url(&self, req: &AuthorizeRequest) -> Result<String, OidcComponentError> {
        if req.tenant.trim().is_empty() {
            return Err(OidcComponentError::MissingField("tenant"));
        }
        if req.state.trim().is_empty() {
            return Err(OidcComponentError::MissingField("state"));
        }
        if req.code_challenge.trim().is_empty() {
            return Err(OidcComponentError::MissingField("code_challenge"));
        }

        let mut url = Url::parse(&self.provider.auth_url)
            .map_err(|err| OidcComponentError::InvalidAuthUrl(err.to_string()))?;
        let redirect_uri = self.redirect_uri(&req.tenant)?;
        let scopes = if req.scopes.is_empty() {
            self.provider.default_scopes.join(" ")
        } else {
            req.scopes.join(" ")
        };

        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("client_id", &self.provider.client_id);
            qp.append_pair("response_type", "code");
            qp.append_pair("redirect_uri", &redirect_uri);
            qp.append_pair("scope", &scopes);
            qp.append_pair("state", &req.state);
            qp.append_pair("code_challenge", &req.code_challenge);
            qp.append_pair("code_challenge_method", "S256");
            for (k, v) in &req.extra_auth_params {
                if ALLOWED_EXTRA_AUTH_PARAMS.contains(&k.as_str()) {
                    qp.append_pair(k, v);
                }
            }
        }

        Ok(url.to_string())
    }

    pub fn execute_operation(
        &self,
        op: ExtensionOperation,
    ) -> Result<ExtensionOperationResult, OidcComponentError> {
        match op {
            ExtensionOperation::AuthorizeUrl(req) => {
                let url = self.authorize_url(&req)?;
                let redirect_uri = self.redirect_uri(&req.tenant)?;
                Ok(ExtensionOperationResult::AuthorizeUrlBuilt { url, redirect_uri })
            }
            ExtensionOperation::ExchangeCode(req) => {
                Ok(ExtensionOperationResult::HttpRequestPrepared(
                    self.exchange_code_http_request(&req)?,
                ))
            }
            ExtensionOperation::RefreshToken(req) => Ok(
                ExtensionOperationResult::HttpRequestPrepared(self.refresh_http_request(&req)?),
            ),
        }
    }

    pub fn exchange_code_form(
        &self,
        req: &ExchangeCodeRequest,
    ) -> Result<Vec<(String, String)>, OidcComponentError> {
        if req.tenant.trim().is_empty() {
            return Err(OidcComponentError::MissingField("tenant"));
        }
        if req.code.trim().is_empty() {
            return Err(OidcComponentError::MissingField("code"));
        }
        if req.code_verifier.trim().is_empty() {
            return Err(OidcComponentError::MissingField("code_verifier"));
        }

        let mut form = vec![
            ("client_id".to_string(), self.provider.client_id.clone()),
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), req.code.clone()),
            ("redirect_uri".to_string(), self.redirect_uri(&req.tenant)?),
            ("code_verifier".to_string(), req.code_verifier.clone()),
        ];
        if let Some(secret) = self
            .provider
            .client_secret
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            form.push(("client_secret".to_string(), secret.to_string()));
        }
        Ok(form)
    }

    pub fn refresh_form(
        &self,
        req: &RefreshRequest,
    ) -> Result<Vec<(String, String)>, OidcComponentError> {
        if req.refresh_token.trim().is_empty() {
            return Err(OidcComponentError::MissingField("refresh_token"));
        }
        let scopes = if req.scopes.is_empty() {
            self.provider.default_scopes.join(" ")
        } else {
            req.scopes.join(" ")
        };
        let mut form = vec![
            ("client_id".to_string(), self.provider.client_id.clone()),
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), req.refresh_token.clone()),
            ("scope".to_string(), scopes),
        ];
        if let Some(secret) = self
            .provider
            .client_secret
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            form.push(("client_secret".to_string(), secret.to_string()));
        }
        Ok(form)
    }

    pub fn exchange_code_http_request(
        &self,
        req: &ExchangeCodeRequest,
    ) -> Result<HttpRequest, OidcComponentError> {
        let form = self.exchange_code_form(req)?;
        Ok(HttpRequest {
            method: "POST".to_string(),
            url: self.provider.token_url.clone(),
            headers: vec![
                (
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
                ("accept".to_string(), "application/json".to_string()),
            ],
            body: Some(encode_form_body(&form).into_bytes()),
            options: HttpRequestOptions {
                timeout_ms: Some(15_000),
                allow_insecure: Some(false),
                follow_redirects: Some(false),
            },
        })
    }

    pub fn refresh_http_request(
        &self,
        req: &RefreshRequest,
    ) -> Result<HttpRequest, OidcComponentError> {
        let form = self.refresh_form(req)?;
        Ok(HttpRequest {
            method: "POST".to_string(),
            url: self.provider.token_url.clone(),
            headers: vec![
                (
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
                ("accept".to_string(), "application/json".to_string()),
            ],
            body: Some(encode_form_body(&form).into_bytes()),
            options: HttpRequestOptions {
                timeout_ms: Some(15_000),
                allow_insecure: Some(false),
                follow_redirects: Some(false),
            },
        })
    }
}

fn validate_https_url(input: &str) -> Result<Url, String> {
    Url::parse(input).map_err(|err| err.to_string())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn encode_form_body(form: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in form {
        serializer.append_pair(k, v);
    }
    serializer.finish()
}

#[cfg(all(feature = "wit-http", target_arch = "wasm32"))]
pub mod wit_http {
    use super::{HttpRequest, OidcComponentError};

    use greentic_interfaces_guest::http_client_v1_1::{
        HostError, Request, RequestOptions, Response, send,
    };

    pub fn send_via_host(
        req: &HttpRequest,
    ) -> Result<Result<Response, HostError>, OidcComponentError> {
        let request = Request {
            method: req.method.clone(),
            url: req.url.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        };
        let opts = Some(RequestOptions {
            timeout_ms: req.options.timeout_ms,
            allow_insecure: req.options.allow_insecure,
            follow_redirects: req.options.follow_redirects,
        });
        Ok(send(&request, opts, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component() -> OidcComponent {
        OidcComponent::new(
            HostConfig {
                public_base_url: "https://auth.acme.example".to_string(),
            },
            OidcProviderConfig {
                provider_id: "oidc-generic".to_string(),
                client_id: "client-123".to_string(),
                client_secret: None,
                auth_url: "https://issuer.example.com/oauth2/v1/authorize".to_string(),
                token_url: "https://issuer.example.com/oauth2/v1/token".to_string(),
                default_scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "offline_access".to_string(),
                ],
            },
        )
        .expect("component")
    }

    #[test]
    fn derives_redirect_uri_from_public_base_url() {
        let provider = component();
        let redirect = provider.redirect_uri("acme").expect("redirect");
        assert_eq!(
            redirect,
            "https://auth.acme.example/oauth/callback/acme/oidc-generic"
        );
    }

    #[test]
    fn builds_authorize_url_with_pkce_and_allowed_extras() {
        let provider = component();
        let mut extras = BTreeMap::new();
        extras.insert("prompt".to_string(), "login".to_string());
        extras.insert("login_hint".to_string(), "dev@acme.example".to_string());
        extras.insert("evil".to_string(), "drop-me".to_string());
        let req = AuthorizeRequest {
            tenant: "acme".to_string(),
            state: "state-123".to_string(),
            code_challenge: "challenge-abc".to_string(),
            scopes: vec![],
            extra_auth_params: extras,
        };

        let url = provider.authorize_url(&req).expect("authorize url");
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=challenge-abc"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=login"));
        assert!(url.contains("login_hint=dev%40acme.example"));
        assert!(!url.contains("evil=drop-me"));
    }

    #[test]
    fn exchange_form_uses_derived_redirect_uri() {
        let provider = component();
        let form = provider
            .exchange_code_form(&ExchangeCodeRequest {
                tenant: "acme".to_string(),
                code: "code-xyz".to_string(),
                code_verifier: "verifier-123".to_string(),
            })
            .expect("form");

        assert!(
            form.iter()
                .any(|(k, v)| k == "grant_type" && v == "authorization_code")
        );
        assert!(form.iter().any(|(k, v)| {
            k == "redirect_uri" && v == "https://auth.acme.example/oauth/callback/acme/oidc-generic"
        }));
    }

    #[test]
    fn exchange_http_request_is_wit_compatible_form_post() {
        let provider = component();
        let request = provider
            .exchange_code_http_request(&ExchangeCodeRequest {
                tenant: "acme".to_string(),
                code: "code-xyz".to_string(),
                code_verifier: "verifier-123".to_string(),
            })
            .expect("request");

        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "https://issuer.example.com/oauth2/v1/token");
        assert!(
            request
                .headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/x-www-form-urlencoded")
        );
        let body = String::from_utf8(request.body.expect("body")).expect("utf8");
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=code-xyz"));
        assert!(body.contains("code_verifier=verifier-123"));
    }

    #[test]
    fn refresh_http_request_uses_scope_string() {
        let provider = component();
        let request = provider
            .refresh_http_request(&RefreshRequest {
                refresh_token: "rt-123".to_string(),
                scopes: vec!["openid".to_string(), "email".to_string()],
            })
            .expect("request");
        let body = String::from_utf8(request.body.expect("body")).expect("utf8");
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=rt-123"));
        assert!(body.contains("scope=openid+email"));
    }

    #[test]
    fn refresh_form_falls_back_to_default_scopes() {
        let provider = component();
        let form = provider
            .refresh_form(&RefreshRequest {
                refresh_token: "refresh-123".to_string(),
                scopes: vec![],
            })
            .expect("form");

        assert!(
            form.iter()
                .any(|(k, v)| k == "scope" && v == "openid profile offline_access")
        );
    }

    #[test]
    fn rejects_insecure_public_base_url() {
        let err = OidcComponent::new(
            HostConfig {
                public_base_url: "http://example.com".to_string(),
            },
            OidcProviderConfig {
                provider_id: "oidc-generic".to_string(),
                client_id: "client-123".to_string(),
                client_secret: None,
                auth_url: "https://issuer.example.com/authorize".to_string(),
                token_url: "https://issuer.example.com/token".to_string(),
                default_scopes: vec!["openid".to_string()],
            },
        )
        .expect_err("must fail");

        assert_eq!(err, OidcComponentError::InsecurePublicBaseUrl);
    }

    #[test]
    fn rejects_missing_required_inputs() {
        let provider = component();
        let err = provider
            .authorize_url(&AuthorizeRequest {
                tenant: "acme".to_string(),
                state: String::new(),
                code_challenge: "challenge".to_string(),
                scopes: vec![],
                extra_auth_params: BTreeMap::new(),
            })
            .expect_err("must fail");

        assert_eq!(err, OidcComponentError::MissingField("state"));
    }

    #[test]
    fn operation_dispatch_authorize_returns_redirect_and_url() {
        let provider = component();
        let result = provider
            .execute_operation(ExtensionOperation::AuthorizeUrl(AuthorizeRequest {
                tenant: "acme".to_string(),
                state: "state-123".to_string(),
                code_challenge: "challenge-abc".to_string(),
                scopes: vec!["openid".to_string()],
                extra_auth_params: BTreeMap::new(),
            }))
            .expect("result");

        match result {
            ExtensionOperationResult::AuthorizeUrlBuilt { url, redirect_uri } => {
                assert!(url.contains("response_type=code"));
                assert_eq!(
                    redirect_uri,
                    "https://auth.acme.example/oauth/callback/acme/oidc-generic"
                );
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn operation_dispatch_exchange_returns_http_request() {
        let provider = component();
        let result = provider
            .execute_operation(ExtensionOperation::ExchangeCode(ExchangeCodeRequest {
                tenant: "acme".to_string(),
                code: "code-123".to_string(),
                code_verifier: "verifier-123".to_string(),
            }))
            .expect("result");

        match result {
            ExtensionOperationResult::HttpRequestPrepared(req) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.url, "https://issuer.example.com/oauth2/v1/token");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn loopback_http_127_0_0_1_is_accepted_as_public_base_url() {
        let host = HostConfig {
            public_base_url: "http://127.0.0.1:8090".to_string(),
        };
        let provider = OidcProviderConfig {
            provider_id: "github".to_string(),
            client_id: "cid".to_string(),
            client_secret: Some("csec".to_string()),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            default_scopes: vec![],
        };
        let result = OidcComponent::new(host, provider);
        assert!(result.is_ok(), "loopback HTTP public_base_url should be accepted, got {:?}", result.err());
    }

    #[test]
    fn loopback_http_localhost_is_accepted_as_public_base_url() {
        let host = HostConfig {
            public_base_url: "http://localhost:8090".to_string(),
        };
        let provider = OidcProviderConfig {
            provider_id: "github".to_string(),
            client_id: "cid".to_string(),
            client_secret: Some("csec".to_string()),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            default_scopes: vec![],
        };
        assert!(OidcComponent::new(host, provider).is_ok());
    }

    #[test]
    fn loopback_http_ipv6_is_accepted_as_public_base_url() {
        let host = HostConfig {
            public_base_url: "http://[::1]:8090".to_string(),
        };
        let provider = OidcProviderConfig {
            provider_id: "github".to_string(),
            client_id: "cid".to_string(),
            client_secret: Some("csec".to_string()),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            default_scopes: vec![],
        };
        assert!(OidcComponent::new(host, provider).is_ok());
    }

    #[test]
    fn non_loopback_http_is_still_rejected_as_public_base_url() {
        let host = HostConfig {
            public_base_url: "http://example.com".to_string(),
        };
        let provider = OidcProviderConfig {
            provider_id: "github".to_string(),
            client_id: "cid".to_string(),
            client_secret: Some("csec".to_string()),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            default_scopes: vec![],
        };
        let err = OidcComponent::new(host, provider).unwrap_err();
        assert_eq!(err, OidcComponentError::InsecurePublicBaseUrl);
    }

    #[test]
    fn includes_client_secret_in_exchange_when_configured() {
        let provider = OidcComponent::new(
            HostConfig {
                public_base_url: "https://auth.acme.example".to_string(),
            },
            OidcProviderConfig {
                provider_id: "oidc-generic".to_string(),
                client_id: "client-123".to_string(),
                client_secret: Some("secret-abc".to_string()),
                auth_url: "https://issuer.example.com/oauth2/v1/authorize".to_string(),
                token_url: "https://issuer.example.com/oauth2/v1/token".to_string(),
                default_scopes: vec!["openid".to_string()],
            },
        )
        .expect("component");

        let form = provider
            .exchange_code_form(&ExchangeCodeRequest {
                tenant: "acme".to_string(),
                code: "code-1".to_string(),
                code_verifier: "verifier-1".to_string(),
            })
            .expect("form");

        assert!(
            form.iter()
                .any(|(k, v)| k == "client_secret" && v == "secret-abc")
        );
    }
}
