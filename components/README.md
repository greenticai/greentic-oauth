# OIDC Extension Components

This folder mirrors the proven messaging split pattern:

- `oidc-provider-runtime`: extension-provider runtime ops (authorize URL, exchange code, refresh token)
- `oidc-ingress`: inbound callback normalization (`code/state/error`) before runtime token exchange
- `oidc-provider`: shared OIDC logic + WIT-compatible HTTP request shaping

This is intentionally provider-extension focused, not an application-pack export surface.

Extension wiring skeleton (messaging-style) is available at:
- `static/examples/oidc-provider-extension.skeleton.json`

WIT worlds exposed:
- `oidc-provider-runtime`: `components/oidc-provider-runtime/wit/oidc-provider-runtime/world.wit`
- `oidc-ingress`: `components/oidc-ingress/wit/oidc-ingress/world.wit`
