use std::{io, net::IpAddr, sync::Arc, time::Duration};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rmcp::transport::auth::{
    OAuthHttpClient, OAuthHttpClientFuture, OAuthHttpRedirectPolicy, OAuthHttpRequest,
};
use url::{Host, Url};

use super::ConnectorError;

const MAX_OAUTH_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// A shared network boundary for both user-supplied MCP URLs and discovered
/// OAuth endpoints. DNS results are checked at connection time (not in a separate
/// preflight lookup); environment proxies and automatic redirects are disabled.
#[derive(Clone)]
pub struct OutboundHttp {
    pub(crate) client: reqwest::Client,
    allow_loopback: bool,
}

impl OutboundHttp {
    pub fn new() -> Result<Self, ConnectorError> {
        Self::build(false)
    }

    fn build(allow_loopback: bool) -> Result<Self, ConnectorError> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("aithos-a2a-agents/0.1");
        if !allow_loopback {
            builder = builder.https_only(true).dns_resolver(Arc::new(PublicDns));
        }
        Ok(Self {
            client: builder.build().map_err(ConnectorError::Network)?,
            allow_loopback,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_local_tests() -> Self {
        Self::build(true).expect("test HTTP client")
    }

    pub fn validate_url(&self, value: &str) -> Result<Url, ConnectorError> {
        let url = Url::parse(value).map_err(|_| ConnectorError::InvalidEndpoint)?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(ConnectorError::InvalidEndpoint);
        }
        if self.allow_loopback
            && url.scheme() == "http"
            && matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        {
            return Ok(url);
        }
        if url.scheme() != "https" {
            return Err(ConnectorError::InvalidEndpoint);
        }
        match url.host() {
            Some(Host::Domain(host)) if host != "localhost" && !host.ends_with(".localhost") => {}
            Some(Host::Ipv4(ip)) if is_public_ip(IpAddr::V4(ip)) => {}
            Some(Host::Ipv6(ip)) if is_public_ip(IpAddr::V6(ip)) => {}
            _ => return Err(ConnectorError::InvalidEndpoint),
        }
        Ok(url)
    }
}

impl OAuthHttpClient for OutboundHttp {
    fn execute(&self, operation: OAuthHttpRequest) -> OAuthHttpClientFuture<'_> {
        Box::pin(async move {
            let (parts, body) = operation.request.into_parts();
            let mut url = self.validate_url(&parts.uri.to_string())?;
            let original_origin = url.origin();
            for redirects in 0..=3 {
                let response = self
                    .client
                    .request(parts.method.clone(), url.clone())
                    .headers(parts.headers.clone())
                    .body(body.clone())
                    .timeout(operation.timeout.unwrap_or(Duration::from_secs(30)))
                    .send()
                    .await?;
                if response.status().is_redirection()
                    && matches!(operation.redirect_policy, OAuthHttpRedirectPolicy::Follow)
                {
                    // Following a POST can repeat registration or token issuance.
                    if parts.method != reqwest::Method::GET || redirects == 3 {
                        return Err(io::Error::other("OAuth redirect refused").into());
                    }
                    let location = response
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .ok_or_else(|| io::Error::other("OAuth redirect has no location"))?
                        .to_str()?;
                    let next = url.join(location)?;
                    self.validate_url(next.as_str())?;
                    if next.origin() != original_origin {
                        return Err(io::Error::other("OAuth cross-origin redirect refused").into());
                    }
                    url = next;
                    continue;
                }
                let status = response.status();
                let headers = response.headers().clone();
                let mut response = response;
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    if bytes.len().saturating_add(chunk.len()) > MAX_OAUTH_RESPONSE_BYTES {
                        return Err(io::Error::other("OAuth response too large").into());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                let mut result = oauth2::http::Response::builder()
                    .status(status)
                    .body(bytes)?;
                *result.headers_mut() = headers;
                return Ok(result);
            }
            Err(io::Error::other("OAuth redirect limit exceeded").into())
        })
    }
}

struct PublicDns;

impl Resolve for PublicDns {
    fn resolve(&self, name: Name) -> Resolving {
        let hostname = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((hostname.as_str(), 0))
                .await?
                .collect();
            if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
                return Err(io::Error::other("non-public connector address refused").into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Global unicast only; exclude special-purpose, documentation and
            // transition ranges that can encode non-public IPv4 destinations.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_metadata_loopback_private_and_encoded_ip_addresses() {
        let client = OutboundHttp::new().unwrap();
        for endpoint in [
            "http://example.com/mcp",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.1/mcp",
            "https://2130706433/mcp",
            "https://[::1]/mcp",
            "https://[::ffff:127.0.0.1]/mcp",
            "https://10.0.0.1/mcp",
            "https://100.100.100.200/mcp",
            "https://user:password@example.com/mcp",
            "https://localhost/mcp",
        ] {
            assert!(
                client.validate_url(endpoint).is_err(),
                "accepted {endpoint}"
            );
        }
        assert!(client.validate_url("https://mcp.notion.com/mcp").is_ok());
    }

    #[tokio::test]
    async fn resolver_rejects_localhost_even_if_validation_was_bypassed() {
        assert!(
            PublicDns
                .resolve("localhost".parse().unwrap())
                .await
                .is_err()
        );
    }
}
