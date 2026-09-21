use std::sync::Arc;

use oauth2::TokenResponse;
use rmcp::transport::auth::{
    AuthorizationManager, CredentialStore, InMemoryStateStore, OAuthClientConfig, StateStore,
};
use serde::{Deserialize, Serialize};

use super::{ConnectorError, OutboundHttp};

/// Owner-supplied setup parameters. Never log this value: it may contain an
/// OAuth client secret. Application-owned callback URLs must be supplied by the
/// backend, not accepted from an untrusted browser query string.
#[derive(Clone, Serialize, Deserialize)]
pub struct BeginOAuthRequest {
    pub mcp_url: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_metadata_url: Option<String>,
}

/// Persist this complete configuration encrypted before returning the browser
/// authorization URL. A client_id alone loses confidential client credentials
/// and the redirect URI when the callback executes in another Lambda.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthConfiguration {
    pub mcp_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub issuer: Option<String>,
}

pub struct AuthorizationStart {
    pub authorization_url: String,
    pub configuration: OAuthConfiguration,
}

#[derive(Clone)]
pub struct OAuthService {
    http: OutboundHttp,
}

impl OAuthService {
    pub fn new(http: OutboundHttp) -> Self {
        Self { http }
    }

    pub async fn begin<S, C>(
        &self,
        request: BeginOAuthRequest,
        states: S,
        credentials: C,
    ) -> Result<AuthorizationStart, ConnectorError>
    where
        S: StateStore + 'static,
        C: CredentialStore + 'static,
    {
        self.http.validate_url(&request.mcp_url)?;
        self.http.validate_url(&request.redirect_uri)?;
        if request.client_secret.is_some() && request.client_id.is_none() {
            return Err(ConnectorError::OAuthUnsupported);
        }
        let mut manager = self.new_manager(&request.mcp_url).await?;
        manager.set_state_store(states);
        manager.set_credential_store(credentials);
        let resolution = manager.resolve_metadata().await?;
        if !resolution.source.is_discovered() {
            return Err(ConnectorError::OAuthUnsupported);
        }
        self.http
            .validate_url(&resolution.metadata.authorization_endpoint)?;
        self.http
            .validate_url(&resolution.metadata.token_endpoint)?;
        let supports_metadata_client = resolution
            .metadata
            .additional_fields
            .get("client_id_metadata_document_supported")
            .and_then(|value| value.as_bool())
            == Some(true);
        let supports_offline = resolution
            .metadata
            .scopes_supported
            .as_ref()
            .is_some_and(|scopes| scopes.iter().any(|scope| scope == "offline_access"));
        let issuer = resolution.metadata.issuer.clone();
        manager.set_metadata(resolution.metadata);
        let mut scopes = if request.scopes.is_empty() {
            manager.select_scopes(None, &[])
        } else {
            request.scopes.clone()
        };
        if supports_offline && !scopes.iter().any(|scope| scope == "offline_access") {
            scopes.push("offline_access".to_owned());
        }

        // Use SDK discovery, registration, PKCE and code exchange. Registration
        // is explicit here so its full configuration can cross Lambda restarts.
        let config = if let Some(client_id) = request.client_id {
            let mut config = OAuthClientConfig::new(client_id, &request.redirect_uri)
                .with_scopes(scopes.clone())
                .with_application_type("web");
            config.client_secret = request.client_secret;
            config
        } else if let Some(metadata_url) = request
            .client_metadata_url
            .filter(|_| supports_metadata_client)
        {
            self.http.validate_url(&metadata_url)?;
            OAuthClientConfig::new(metadata_url, &request.redirect_uri)
                .with_scopes(scopes.clone())
                .with_application_type("web")
        } else {
            let selected: Vec<_> = scopes.iter().map(String::as_str).collect();
            manager
                .register_client("Aithos Agents", &request.redirect_uri, &selected)
                .await?
        };
        manager.configure_client(config.clone())?;
        let selected: Vec<_> = scopes.iter().map(String::as_str).collect();
        let authorization_url = manager.get_authorization_url(&selected).await?;
        Ok(AuthorizationStart {
            authorization_url,
            configuration: OAuthConfiguration {
                mcp_url: request.mcp_url,
                client_id: config.client_id,
                client_secret: config.client_secret,
                redirect_uri: config.redirect_uri,
                scopes,
                issuer,
            },
        })
    }

    /// The StateStore must check expiry and enforce one-time consumption in its
    /// delete operation. Tokens are persisted through CredentialStore::save by
    /// rmcp before this operation reports success.
    pub async fn finish<S, C>(
        &self,
        config: &OAuthConfiguration,
        code: &str,
        state: &str,
        issuer: Option<&str>,
        states: S,
        credentials: C,
    ) -> Result<(), ConnectorError>
    where
        S: StateStore + 'static,
        C: CredentialStore + 'static,
    {
        // Reauthorization may replace an older registration and its credentials.
        // The state/PKCE and issuer checks bind this callback to the new flow.
        let manager = self
            .restore_manager(config, states, credentials, false)
            .await?;
        manager
            .exchange_code_for_token_with_issuer(code, state, issuer)
            .await?;
        Ok(())
    }

    /// Called by scheduled maintenance while a connection is idle. The supplied
    /// CredentialStore must coordinate cross-Lambda refreshes and persist rotated
    /// tokens atomically. Provider absolute expirations still require consent.
    pub async fn refresh<C>(
        &self,
        config: &OAuthConfiguration,
        credentials: C,
    ) -> Result<(), ConnectorError>
    where
        C: CredentialStore + 'static,
    {
        let renewable = credentials
            .load()
            .await?
            .and_then(|stored| stored.token_response)
            .is_some_and(|token| token.refresh_token().is_some());
        let manager = self
            .manager(config, InMemoryStateStore::new(), credentials)
            .await?;
        if renewable {
            // Keep renewable grants active even when the agent is idle.
            manager.refresh_token().await?;
        } else {
            // Some providers issue long-lived access tokens without a refresh
            // token. Their absence is not an expired authorization: retain the
            // access token for its advertised lifetime (possibly unbounded).
            manager.get_access_token().await?;
        }
        Ok(())
    }

    /// Reconstruct authorization from durable state. The returned manager can be
    /// passed to McpSession::connect_oauth; automatic refresh writes through the
    /// supplied store, including refreshed credentials during an MCP task.
    pub async fn manager<S, C>(
        &self,
        config: &OAuthConfiguration,
        states: S,
        credentials: C,
    ) -> Result<AuthorizationManager, ConnectorError>
    where
        S: StateStore + 'static,
        C: CredentialStore + 'static,
    {
        self.restore_manager(config, states, credentials, true)
            .await
    }

    async fn restore_manager<S, C>(
        &self,
        config: &OAuthConfiguration,
        states: S,
        credentials: C,
        validate_existing: bool,
    ) -> Result<AuthorizationManager, ConnectorError>
    where
        S: StateStore + 'static,
        C: CredentialStore + 'static,
    {
        self.http.validate_url(&config.mcp_url)?;
        let mut manager = self.new_manager(&config.mcp_url).await?;
        let resolution = manager.resolve_metadata().await?;
        if !resolution.source.is_discovered() {
            return Err(ConnectorError::OAuthUnsupported);
        }
        if resolution.metadata.issuer != config.issuer {
            return Err(ConnectorError::IssuerChanged);
        }
        self.http
            .validate_url(&resolution.metadata.authorization_endpoint)?;
        self.http
            .validate_url(&resolution.metadata.token_endpoint)?;
        if validate_existing
            && let Some(stored) = credentials.load().await?
            && (stored.client_id != config.client_id || stored.issuer != config.issuer)
        {
            return Err(ConnectorError::AuthorizationRequired);
        }
        manager.set_metadata(resolution.metadata);
        let mut client = OAuthClientConfig::new(&config.client_id, &config.redirect_uri)
            .with_scopes(config.scopes.clone())
            .with_application_type("web");
        client.client_secret = config.client_secret.clone();
        manager.configure_client(client)?;
        manager.set_state_store(states);
        manager.set_credential_store(credentials);
        Ok(manager)
    }

    async fn new_manager(&self, url: &str) -> Result<AuthorizationManager, ConnectorError> {
        Ok(
            AuthorizationManager::new_with_oauth_http_client(url, Arc::new(self.http.clone()))
                .await?,
        )
    }
}
