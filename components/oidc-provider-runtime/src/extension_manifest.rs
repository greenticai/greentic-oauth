use serde_json::{Value, json};

pub const PROVIDER_EXTENSION_KEY: &str = "greentic.provider-extension.v1";
pub const OIDC_INGRESS_EXTENSION_KEY: &str = "oauth.provider_ingress.v1";
pub const OIDC_FLOW_HINTS_KEY: &str = "oauth.provider_flow_hints.v1";
pub const HTTP_ROUTES_EXTENSION_KEY: &str = "greentic.http-routes.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcExtensionManifestInput<'a> {
    pub version: &'a str,
    pub provider_type: &'a str,
    pub runtime_component_ref: &'a str,
    pub ingress_component_ref: &'a str,
    pub config_schema_ref: &'a str,
}

pub fn build_oidc_extension_manifest(input: OidcExtensionManifestInput<'_>) -> Value {
    json!({
        PROVIDER_EXTENSION_KEY: {
            "kind": PROVIDER_EXTENSION_KEY,
            "version": input.version,
            "inline": {
                "providers": [
                    {
                        "provider_type": input.provider_type,
                        "capabilities": ["oauth", "oauth-card"],
                        "envelope_wrap": true,
                        "ops": [
                            "authorize-url",
                            "exchange-code",
                            "refresh-token",
                            "resolve-card",
                            "ingest_http"
                        ],
                        "config_schema_ref": input.config_schema_ref,
                        "runtime": {
                            "component_ref": input.runtime_component_ref,
                            "export": "schema-core-api",
                            "world": "greentic:provider/schema-core@1.0.0"
                        }
                    }
                ]
            }
        },
        OIDC_INGRESS_EXTENSION_KEY: {
            "kind": OIDC_INGRESS_EXTENSION_KEY,
            "version": input.version,
            "inline": {
                "capabilities": {
                    "content_types": ["application/x-www-form-urlencoded"],
                    "supports_callback_validation": true
                },
                "card_rewrite": {
                    "marker": "oauth://start",
                    "capability_id": "greentic.cap.oauth.card.v1",
                    "op": "oauth.card.resolve"
                },
                "component_ref": input.ingress_component_ref,
                "export": "handle-callback",
                "world": "greentic:oidc-ingress/callback@0.1.0"
            }
        },
        OIDC_FLOW_HINTS_KEY: {
            "kind": OIDC_FLOW_HINTS_KEY,
            "version": input.version,
            "inline": {
                input.provider_type: {
                    "default": "authorize-url",
                    "callback": "exchange-code",
                    "refresh": "refresh-token"
                }
            }
        },
        HTTP_ROUTES_EXTENSION_KEY: {
            "kind": HTTP_ROUTES_EXTENSION_KEY,
            "version": input.version,
            "inline": {
                "schema_version": 1,
                "routes": [
                    {
                        "id": "oauth-oidc-callback",
                        "pattern": "/v1/oauth/callback/{path*}",
                        "methods": ["GET", "POST"],
                        "provider_op": "ingest_http",
                        "domain": "oauth"
                    }
                ]
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_messaging_style_provider_and_ingress_extensions() {
        let manifest = build_oidc_extension_manifest(OidcExtensionManifestInput {
            version: "0.4.24-local.1",
            provider_type: "oauth.oidc.generic",
            runtime_component_ref: "oidc-provider-runtime",
            ingress_component_ref: "oidc-ingress",
            config_schema_ref: "schemas/oauth/oidc/public.config.schema.json",
        });

        assert_eq!(
            manifest[PROVIDER_EXTENSION_KEY]["inline"]["providers"][0]["runtime"]["component_ref"],
            "oidc-provider-runtime"
        );
        assert_eq!(
            manifest[PROVIDER_EXTENSION_KEY]["inline"]["providers"][0]["envelope_wrap"],
            true
        );
        assert_eq!(
            manifest[OIDC_INGRESS_EXTENSION_KEY]["inline"]["component_ref"],
            "oidc-ingress"
        );
        assert_eq!(
            manifest[OIDC_INGRESS_EXTENSION_KEY]["inline"]["card_rewrite"]["marker"],
            "oauth://start"
        );
        assert_eq!(
            manifest[OIDC_INGRESS_EXTENSION_KEY]["inline"]["card_rewrite"]["capability_id"],
            "greentic.cap.oauth.card.v1"
        );
        assert_eq!(
            manifest[OIDC_FLOW_HINTS_KEY]["inline"]["oauth.oidc.generic"]["callback"],
            "exchange-code"
        );
        assert_eq!(
            manifest[HTTP_ROUTES_EXTENSION_KEY]["inline"]["routes"][0]["pattern"],
            "/v1/oauth/callback/{path*}"
        );
        assert_eq!(
            manifest[HTTP_ROUTES_EXTENSION_KEY]["inline"]["routes"][0]["domain"],
            "oauth"
        );
    }
}
