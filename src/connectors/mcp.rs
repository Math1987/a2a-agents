use std::time::Duration;

use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult, ClientConfig, Tool},
    service::RunningService,
    transport::{
        StreamableHttpClientTransport,
        auth::{AuthClient, AuthorizationManager},
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Map, Value};

use super::{ConnectorError, OutboundHttp};

/// An MCP session lasts for one worker execution. Authorization is persisted
/// separately and therefore outlives the network connection and Lambda process.
pub struct McpSession {
    service: RunningService<RoleClient, ClientConfig>,
}

impl McpSession {
    pub async fn connect(
        http: &OutboundHttp,
        url: &str,
        bearer: Option<&str>,
    ) -> Result<Self, ConnectorError> {
        http.validate_url(url)?;
        let mut config = Self::transport_config(url);
        if let Some(token) = bearer {
            config = config.auth_header(token);
        }
        let transport = StreamableHttpClientTransport::with_client(http.client.clone(), config);
        let service = tokio::time::timeout(
            Duration::from_secs(45),
            ClientConfig::default().serve(transport),
        )
        .await
        .map_err(|_| ConnectorError::Timeout)?
        .map_err(|error| {
            if error.is_authorization_required() {
                ConnectorError::AuthorizationRequired
            } else {
                ConnectorError::Protocol
            }
        })?;
        Ok(Self { service })
    }

    pub async fn connect_oauth(
        http: &OutboundHttp,
        url: &str,
        manager: AuthorizationManager,
    ) -> Result<Self, ConnectorError> {
        http.validate_url(url)?;
        // Refresh before initialize to preserve the SDK's precise OAuth error
        // classification instead of flattening a failed handshake to transport.
        manager.get_access_token().await?;
        let auth = AuthClient::new(http.client.clone(), manager);
        let transport =
            StreamableHttpClientTransport::with_client(auth, Self::transport_config(url));
        let service = tokio::time::timeout(
            Duration::from_secs(45),
            ClientConfig::default().serve(transport),
        )
        .await
        .map_err(|_| ConnectorError::Timeout)?
        .map_err(|error| {
            if error.is_authorization_required() {
                ConnectorError::AuthorizationRequired
            } else {
                ConnectorError::Protocol
            }
        })?;
        Ok(Self { service })
    }

    pub async fn tools(&self) -> Result<Vec<Tool>, ConnectorError> {
        tokio::time::timeout(Duration::from_secs(60), self.service.list_all_tools())
            .await
            .map_err(|_| ConnectorError::Timeout)?
            .map_err(|_| ConnectorError::Protocol)
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> Result<CallToolResult, ConnectorError> {
        // No application retry: a failed/ambiguous write must not be executed twice.
        tokio::time::timeout(
            Duration::from_secs(90),
            self.service
                .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments)),
        )
        .await
        .map_err(|_| ConnectorError::Timeout)?
        .map_err(|_| ConnectorError::Protocol)
    }

    pub async fn close(self) -> Result<(), ConnectorError> {
        tokio::time::timeout(Duration::from_secs(5), self.service.cancel())
            .await
            .map_err(|_| ConnectorError::Timeout)?
            .map_err(|_| ConnectorError::Protocol)?;
        Ok(())
    }

    fn transport_config(url: &str) -> StreamableHttpClientTransportConfig {
        StreamableHttpClientTransportConfig::with_uri(url.to_owned())
            .max_concurrent_requests(1)
            .max_sse_event_size(2 * 1024 * 1024)
            .reinit_on_expired_session(false)
    }
}
