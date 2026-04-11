//! Pure helpers for handle_ingest_http: query parsing, HTML rendering,
//! provider_id extraction from path. No I/O, all unit-testable natively.

pub fn find_query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

pub fn extract_provider_id_from_path(path: &str) -> Option<String> {
    // Pattern: /v1/oauth/callback/<provider_id>[?...]
    let path_only = path.split('?').next().unwrap_or(path);
    path_only
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .nth(3)
        .map(|s| s.to_string())
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// SAFETY: `tenant` is interpolated into both HTML and the meta-refresh URL
// without escaping. This is safe only because tenant is system-controlled
// (operator-assigned from bundle config), never user input. If that ever
// changes, switch to `html_escape(tenant)` and percent-encode the URL path.
pub fn success_html(tenant: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Greentic OAuth — Login Successful</title>
<meta http-equiv="refresh" content="2;url=/v1/web/webchat/{tenant}/">
<style>body {{ font-family: system-ui; padding: 3rem; text-align: center; color: #1f2937; }} h1 {{ color: #16a34a; }}</style>
</head>
<body><h1>Login successful</h1><p>You can close this window and return to the chat.</p>
<p><a href="/v1/web/webchat/{tenant}/">Return to chat</a></p>
<script>setTimeout(() => window.close(), 1500);</script>
</body>
</html>"#,
    )
}

pub fn error_html(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Greentic OAuth — Error</title>
<style>body {{ font-family: system-ui; padding: 3rem; text-align: center; color: #1f2937; }} h1 {{ color: #dc2626; }}</style>
</head>
<body><h1>Login failed</h1><p>{message}</p><p><a href="/v1/web/webchat/demo/">Return to chat</a></p></body>
</html>"#,
        message = html_escape(message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_query_returns_matching_value() {
        let pairs = vec![
            ("code".to_string(), "abc".to_string()),
            ("state".to_string(), "xyz".to_string()),
        ];
        assert_eq!(find_query(&pairs, "code"), Some("abc"));
        assert_eq!(find_query(&pairs, "state"), Some("xyz"));
        assert_eq!(find_query(&pairs, "missing"), None);
    }

    #[test]
    fn extract_provider_id_from_canonical_path() {
        assert_eq!(
            extract_provider_id_from_path("/v1/oauth/callback/github"),
            Some("github".to_string())
        );
        assert_eq!(
            extract_provider_id_from_path("/v1/oauth/callback/github?code=1&state=2"),
            Some("github".to_string())
        );
    }

    #[test]
    fn extract_provider_id_returns_none_when_path_too_short() {
        assert_eq!(extract_provider_id_from_path("/v1/oauth/callback"), None);
        assert_eq!(extract_provider_id_from_path("/"), None);
    }

    #[test]
    fn html_escape_escapes_basic_chars() {
        assert_eq!(html_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
        assert_eq!(html_escape("he said \"hi\""), "he said &quot;hi&quot;");
        assert_eq!(html_escape("it's"), "it&#39;s");
    }

    #[test]
    fn success_html_contains_tenant_and_redirect() {
        let h = success_html("demo");
        assert!(h.contains("/v1/web/webchat/demo/"));
        assert!(h.contains("Login successful"));
    }

    #[test]
    fn error_html_escapes_message() {
        let h = error_html("fail <script>alert(1)</script>");
        assert!(h.contains("&lt;script&gt;"));
        assert!(!h.contains("<script>"));
    }
}
