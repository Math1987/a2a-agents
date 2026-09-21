//! Remote MCP connections and restart-safe OAuth orchestration.
//!
//! OAuth protocol operations are delegated to the official `rmcp` SDK. The
//! application supplies durable stores; no authorization depends on a warm Lambda.
mod http;
mod mcp;
mod oauth;

pub use http::OutboundHttp;
pub use mcp::McpSession;
pub use oauth::{AuthorizationStart, BeginOAuthRequest, OAuthConfiguration, OAuthService};

use rmcp::transport::auth::AuthError;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("the connector endpoint must be a public HTTPS URL")]
    InvalidEndpoint,
    #[error("connector network request failed")]
    Network(#[source] reqwest::Error),
    #[error("connector authorization failed")]
    OAuth(#[source] AuthError),
    #[error("the authorization server identity changed; reconnect the connector")]
    IssuerChanged,
    #[error("the connector does not publish supported OAuth metadata")]
    OAuthUnsupported,
    #[error("the connector requires authorization")]
    AuthorizationRequired,
    #[error("connector protocol request failed")]
    Protocol,
    #[error("connector request timed out")]
    Timeout,
}

impl ConnectorError {
    pub fn requires_authorization(&self) -> bool {
        matches!(
            self,
            Self::AuthorizationRequired
                | Self::IssuerChanged
                | Self::OAuth(
                    AuthError::AuthorizationRequired | AuthError::TokenRefreshRejected(_)
                )
        )
    }
}

impl From<AuthError> for ConnectorError {
    fn from(error: AuthError) -> Self {
        Self::OAuth(error)
    }
}

#[cfg(test)]
mod tests;
