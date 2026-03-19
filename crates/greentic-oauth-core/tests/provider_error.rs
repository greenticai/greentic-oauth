use greentic_oauth_core::provider::{ProviderError, ProviderErrorKind};

#[test]
fn provider_error_with_message_exposes_fields_and_display() {
    let err = ProviderError::new(
        ProviderErrorKind::Transport,
        "request timed out".to_string(),
    );

    assert_eq!(err.kind(), ProviderErrorKind::Transport);
    assert_eq!(err.message(), Some("request timed out"));
    assert_eq!(err.to_string(), "transport error: request timed out");
}

#[test]
fn provider_error_without_message_displays_kind_only() {
    let err = ProviderError::new(ProviderErrorKind::Authorization, None::<String>);

    assert_eq!(err.kind(), ProviderErrorKind::Authorization);
    assert_eq!(err.message(), None);
    assert_eq!(err.to_string(), "authorization error");
}

#[test]
fn provider_error_kind_labels_are_stable() {
    let cases = [
        (ProviderErrorKind::Configuration, "configuration error"),
        (ProviderErrorKind::Transport, "transport error"),
        (ProviderErrorKind::Authorization, "authorization error"),
        (ProviderErrorKind::InvalidResponse, "invalid response"),
        (ProviderErrorKind::Unsupported, "unsupported operation"),
        (ProviderErrorKind::Other, "provider error"),
    ];

    for (kind, expected) in cases {
        assert_eq!(kind.to_string(), expected);
    }
}

#[test]
fn provider_error_has_no_source_error() {
    let err = ProviderError::new(ProviderErrorKind::Other, "unexpected".to_string());
    let as_error: &dyn std::error::Error = &err;

    assert!(as_error.source().is_none());
}
