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

    /// Fetch the current catalog on this session, including all pages. Callers
    /// must refresh after tool calls when servers expose configuration-dependent
    /// tools; this method deliberately does not cache the initial catalog.
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use serde_json::json;
    use tokio::sync::Mutex;

    use super::*;

    const SESSION_ID: &str = "dynamic-tool-test-session";
    const CONFIGURE: &str = "google_calendar-create-event";
    const RUN: &str = "run_google_calendar-create-event";

    #[derive(Default)]
    struct DynamicState {
        configured: bool,
        initialized: bool,
        transcript: Vec<String>,
        wrong_session: bool,
    }

    struct Fixture {
        endpoint: String,
        state: Arc<Mutex<DynamicState>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn fixture() -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(DynamicState::default()));
        let router = Router::new()
            .route(
                "/mcp",
                post(dynamic_mcp)
                    // A server can decline a standalone SSE stream. This
                    // fixture requires clients to explicitly reload tools.
                    .get(|| async { StatusCode::METHOD_NOT_ALLOWED })
                    .delete(|| async { StatusCode::NO_CONTENT }),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Fixture {
            endpoint,
            state,
            server,
        }
    }

    async fn dynamic_mcp(
        State(shared): State<Arc<Mutex<DynamicState>>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        let mut state = shared.lock().await;
        let method = body["method"].as_str().unwrap_or_default();
        let request = if method == "tools/call" {
            format!(
                "tools/call:{}",
                body["params"]["name"].as_str().unwrap_or_default()
            )
        } else {
            method.to_owned()
        };
        state.transcript.push(request);
        if method != "initialize"
            && headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) != Some(SESSION_ID)
        {
            state.wrong_session = true;
            return StatusCode::NOT_FOUND.into_response();
        }
        let result = match method {
            "initialize" => json!({
                "protocolVersion": body["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "dynamic-catalog-fixture", "version": "1"}
            }),
            "notifications/initialized" => {
                state.initialized = true;
                return StatusCode::ACCEPTED.into_response();
            }
            "tools/list" => {
                let tool = if state.configured {
                    json!({"name": RUN, "description": "Run the configured local fixture",
                        "inputSchema": {"type": "object", "properties": {
                            "summary": {"type": "string"}}, "required": ["summary"]}})
                } else {
                    json!({"name": CONFIGURE, "description": "Configure the local fixture",
                        "inputSchema": {"type": "object", "properties": {
                            "calendar": {"type": "string"}}, "required": ["calendar"]}})
                };
                json!({"tools": [tool]})
            }
            "tools/call" if body["params"]["name"] == CONFIGURE => {
                if body["params"]["arguments"]["calendar"] != "fixture-only" {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                state.configured = true;
                json!({"content": [{"type": "text", "text":
                    "Configuration ready. Reload tools and call run_google_calendar-create-event."}],
                    "isError": false})
            }
            "tools/call" if state.configured && body["params"]["name"] == RUN => {
                if body["params"]["arguments"]["summary"] != "local-only" {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                json!({"content": [{"type": "text", "text": "Local fixture executed"}],
                    "isError": false})
            }
            _ => return StatusCode::BAD_REQUEST.into_response(),
        };
        let response = Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}));
        if method == "initialize" {
            ([("mcp-session-id", SESSION_ID)], response).into_response()
        } else {
            response.into_response()
        }
    }

    #[tokio::test]
    async fn dynamic_tools_reload_in_same_session_without_reconnect_or_replay() {
        let fixture = fixture().await;
        let http = OutboundHttp::for_local_tests();
        let session = McpSession::connect(&http, &fixture.endpoint, None)
            .await
            .unwrap();

        let initial = session.tools().await.unwrap();
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].name, CONFIGURE);
        assert_eq!(initial[0].input_schema["required"], json!(["calendar"]));

        let configured = session
            .call_tool(
                CONFIGURE,
                json!({"calendar": "fixture-only"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap();
        assert_eq!(configured.is_error, Some(false));

        let refreshed = session.tools().await.unwrap();
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].name, RUN);
        assert_eq!(refreshed[0].input_schema["required"], json!(["summary"]));

        let executed = session
            .call_tool(
                RUN,
                json!({"summary": "local-only"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap();
        assert_eq!(executed.is_error, Some(false));
        session.close().await.unwrap();

        let state = fixture.state.lock().await;
        assert!(state.initialized);
        assert!(!state.wrong_session);
        assert_eq!(
            state.transcript,
            [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call:google_calendar-create-event",
                "tools/list",
                "tools/call:run_google_calendar-create-event",
            ]
        );
    }
}
