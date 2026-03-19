use greentic_config_types::{NetworkConfig, TelemetryConfig, TlsMode};
use reqwest::blocking::{Client as BlockingClient, ClientBuilder as BlockingClientBuilder};
use reqwest::{Client, ClientBuilder, Proxy};
use std::time::Duration;

/// Runtime options derived from GreenticConfig and injected into OAuth clients.
#[derive(Clone, Debug, Default)]
pub struct OAuthClientOptions {
    pub network: NetworkConfig,
    pub telemetry: TelemetryConfig,
}

impl OAuthClientOptions {
    /// Create options from discrete config pieces.
    pub fn new(network: NetworkConfig, telemetry: TelemetryConfig) -> Self {
        Self { network, telemetry }
    }

    /// Build a reqwest client honoring the configured network policy (proxy, TLS mode, timeouts).
    pub fn build_http_client(&self) -> Result<Client, reqwest::Error> {
        let builder = ClientBuilder::new();
        self.apply_network(builder).build()
    }

    /// Build a blocking reqwest client honoring the configured network policy.
    pub fn build_blocking_http_client(&self) -> Result<BlockingClient, reqwest::Error> {
        let builder = BlockingClientBuilder::new();
        self.apply_network(builder).build()
    }

    fn apply_network<B>(&self, mut builder: B) -> B
    where
        B: ProxyConfigurable + TimeoutConfigurable,
    {
        if let Some(proxy) = self.network.proxy_url.as_ref()
            && let Ok(proxy_cfg) = Proxy::all(proxy)
        {
            builder = builder.with_proxy(proxy_cfg);
        }

        if let Some(connect_ms) = self.network.connect_timeout_ms {
            builder = builder.with_connect_timeout(Duration::from_millis(connect_ms));
        }
        if let Some(read_ms) = self.network.read_timeout_ms {
            builder = builder.with_timeout(Duration::from_millis(read_ms));
        }

        if matches!(self.network.tls_mode, TlsMode::Disabled) {
            tracing::warn!(
                "tls_mode=disabled is no longer supported; enforcing TLS certificate validation"
            );
        }

        builder
    }
}

trait ProxyConfigurable: Sized {
    fn with_proxy(self, proxy: Proxy) -> Self;
}

trait TimeoutConfigurable: Sized {
    fn with_connect_timeout(self, timeout: Duration) -> Self;
    fn with_timeout(self, timeout: Duration) -> Self;
}

impl ProxyConfigurable for ClientBuilder {
    fn with_proxy(self, proxy: Proxy) -> Self {
        self.proxy(proxy)
    }
}

impl ProxyConfigurable for BlockingClientBuilder {
    fn with_proxy(self, proxy: Proxy) -> Self {
        self.proxy(proxy)
    }
}

impl TimeoutConfigurable for ClientBuilder {
    fn with_connect_timeout(self, timeout: Duration) -> Self {
        self.connect_timeout(timeout)
    }

    fn with_timeout(self, timeout: Duration) -> Self {
        self.timeout(timeout)
    }
}

impl TimeoutConfigurable for BlockingClientBuilder {
    fn with_connect_timeout(self, timeout: Duration) -> Self {
        self.connect_timeout(timeout)
    }

    fn with_timeout(self, timeout: Duration) -> Self {
        self.timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestBuilder {
        proxy_calls: usize,
        connect_timeout: Option<Duration>,
        timeout: Option<Duration>,
    }

    impl ProxyConfigurable for TestBuilder {
        fn with_proxy(mut self, _proxy: Proxy) -> Self {
            self.proxy_calls += 1;
            self
        }
    }

    impl TimeoutConfigurable for TestBuilder {
        fn with_connect_timeout(mut self, timeout: Duration) -> Self {
            self.connect_timeout = Some(timeout);
            self
        }

        fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout = Some(timeout);
            self
        }
    }

    #[test]
    fn apply_network_sets_proxy_and_timeouts_when_valid() {
        let mut options = OAuthClientOptions::default();
        options.network.proxy_url = Some("http://127.0.0.1:8080".to_string());
        options.network.connect_timeout_ms = Some(1_500);
        options.network.read_timeout_ms = Some(2_500);

        let applied = options.apply_network(TestBuilder::default());

        assert_eq!(applied.proxy_calls, 1);
        assert_eq!(applied.connect_timeout, Some(Duration::from_millis(1_500)));
        assert_eq!(applied.timeout, Some(Duration::from_millis(2_500)));
    }

    #[test]
    fn apply_network_ignores_invalid_proxy_url() {
        let mut options = OAuthClientOptions::default();
        options.network.proxy_url = Some("://not-a-valid-proxy".to_string());

        let applied = options.apply_network(TestBuilder::default());

        assert_eq!(applied.proxy_calls, 0);
    }

    #[test]
    fn apply_network_keeps_defaults_when_unset() {
        let options = OAuthClientOptions::default();

        let applied = options.apply_network(TestBuilder::default());

        assert_eq!(applied.proxy_calls, 0);
        assert_eq!(applied.connect_timeout, None);
        assert_eq!(applied.timeout, None);
    }

    #[test]
    fn apply_network_accepts_zero_timeout_values() {
        let mut options = OAuthClientOptions::default();
        options.network.connect_timeout_ms = Some(0);
        options.network.read_timeout_ms = Some(0);

        let applied = options.apply_network(TestBuilder::default());

        assert_eq!(applied.connect_timeout, Some(Duration::from_millis(0)));
        assert_eq!(applied.timeout, Some(Duration::from_millis(0)));
    }

    #[test]
    fn build_clients_succeeds_when_tls_mode_is_disabled() {
        let mut options = OAuthClientOptions::default();
        options.network.tls_mode = TlsMode::Disabled;

        assert!(options.build_http_client().is_ok());
        assert!(options.build_blocking_http_client().is_ok());
    }
}
