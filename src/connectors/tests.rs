//! These tests run the real rmcp OAuth and Streamable HTTP client against a
//! local HTTP provider. Stores serialize every write and deserialize every read
//! so tests cannot accidentally rely on an in-memory AuthorizationManager.
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use oauth2::TokenResponse;
use rmcp::transport::auth::{
    AuthError, CredentialRefreshGuard, CredentialStore, StateStore, StoredAuthorizationState,
    StoredCredentials,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::*;

#[derive(Clone, Default)]
struct DurableStates(Arc<Mutex<HashMap<String, Vec<u8>>>>);

#[async_trait::async_trait]
impl StateStore for DurableStates {
    async fn save(&self, key: &str, state: StoredAuthorizationState) -> Result<(), AuthError> {
        self.0
            .lock()
            .await
            .insert(key.to_owned(), serde_json::to_vec(&state).unwrap());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Option<StoredAuthorizationState>, AuthError> {
        Ok(self
            .0
            .lock()
            .await
            .get(key)
            .map(|bytes| serde_json::from_slice(bytes).unwrap()))
    }
    async fn delete(&self, key: &str) -> Result<(), AuthError> {
        self.0
            .lock()
            .await
            .remove(key)
            .ok_or_else(|| AuthError::CredentialStoreError("state consumed".into()))?;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct DurableCredentials {
    bytes: Arc<Mutex<Option<Vec<u8>>>>,
    refresh_lock: Arc<Mutex<()>>,
}

#[async_trait::async_trait]
impl CredentialStore for DurableCredentials {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        Ok(self
            .bytes
            .lock()
            .await
            .as_ref()
            .map(|bytes| serde_json::from_slice(bytes).unwrap()))
    }
    async fn save(&self, value: StoredCredentials) -> Result<(), AuthError> {
        *self.bytes.lock().await = Some(serde_json::to_vec(&value).unwrap());
        Ok(())
    }
    async fn clear(&self) -> Result<(), AuthError> {
        *self.bytes.lock().await = None;
        Ok(())
    }
    async fn acquire_refresh_guard(&self) -> Result<Option<CredentialRefreshGuard>, AuthError> {
        Ok(Some(CredentialRefreshGuard::new(
            self.refresh_lock.clone().lock_owned().await,
        )))
    }
}

#[derive(Clone)]
struct Provider {
    base: String,
    challenge: Arc<Mutex<Option<String>>>,
    refresh_count: Arc<AtomicUsize>,
    next_refresh: Arc<Mutex<String>>,
}

struct Fixture {
    provider: Provider,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture() -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = Provider {
        base: format!("http://{}", listener.local_addr().unwrap()),
        challenge: Arc::new(Mutex::new(None)),
        refresh_count: Arc::new(AtomicUsize::new(0)),
        next_refresh: Arc::new(Mutex::new("refresh-0".into())),
    };
    let router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(server_metadata),
        )
        .route("/register", post(register))
        .route("/token", post(token))
        .route(
            "/mcp",
            post(mcp)
                .get(challenge)
                .delete(|| async { StatusCode::NO_CONTENT }),
        )
        .with_state(provider.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Fixture { provider, server }
}

async fn resource_metadata(State(p): State<Provider>) -> Json<Value> {
    Json(
        json!({"resource":format!("{}/mcp",p.base), "authorization_servers":[p.base], "scopes_supported":["mcp"]}),
    )
}

async fn server_metadata(State(p): State<Provider>) -> Json<Value> {
    Json(
        json!({"issuer":p.base, "authorization_endpoint":format!("{}/authorize",p.base),
        "token_endpoint":format!("{}/token",p.base), "registration_endpoint":format!("{}/register",p.base),
        "scopes_supported":["mcp","offline_access"], "response_types_supported":["code"],
        "code_challenge_methods_supported":["S256"], "token_endpoint_auth_methods_supported":["client_secret_basic"]}),
    )
}

async fn register(Json(body): Json<Value>) -> Json<Value> {
    assert_eq!(
        body["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    Json(
        json!({"client_id":"test-client", "client_secret":"test-secret", "redirect_uris":body["redirect_uris"]}),
    )
}

async fn challenge(State(p): State<Provider>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            "www-authenticate",
            format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                p.base
            ),
        )],
    )
        .into_response()
}

async fn token(
    State(p): State<Provider>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let expected_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("test-client:test-secret")
    );
    if headers.get("authorization").and_then(|h| h.to_str().ok()) != Some(expected_auth.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_client"})),
        )
            .into_response();
    }
    assert_eq!(form.get("resource").unwrap(), &format!("{}/mcp", p.base));
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            assert_eq!(form.get("code").unwrap(), "test-code");
            assert_eq!(
                form.get("redirect_uri").unwrap(),
                &format!("{}/callback", p.base)
            );
            let hash = Sha256::digest(form.get("code_verifier").unwrap().as_bytes());
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
            assert_eq!(Some(challenge), *p.challenge.lock().await);
            Json(json!({"access_token":"initial-access", "refresh_token":"refresh-0", "token_type":"Bearer", "expires_in":1})).into_response()
        }
        Some("refresh_token") => {
            let mut expected = p.next_refresh.lock().await;
            if form.get("refresh_token") != Some(&*expected) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"invalid_grant"})),
                )
                    .into_response();
            }
            let number = p.refresh_count.fetch_add(1, Ordering::SeqCst) + 1;
            let mut value = json!({"access_token":"refreshed-access", "token_type":"Bearer", "expires_in":3600});
            // The second response deliberately omits refresh_token: OAuth permits
            // omission, and the persisted rotated token must survive unchanged.
            if number != 2 {
                *expected = format!("refresh-{number}");
                value["refresh_token"] = json!(expected.clone());
            }
            Json(value).into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"unsupported_grant_type"})),
        )
            .into_response(),
    }
}

async fn mcp(
    State(p): State<Provider>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if headers.get("authorization").and_then(|h| h.to_str().ok()) != Some("Bearer refreshed-access")
    {
        return challenge(State(p)).await;
    }
    let result = match request["method"].as_str().unwrap() {
        "initialize" => {
            json!({"protocolVersion":request["params"]["protocolVersion"], "capabilities":{"tools":{}}, "serverInfo":{"name":"fixture", "version":"1"}})
        }
        "notifications/initialized" | "notifications/cancelled" => {
            return StatusCode::ACCEPTED.into_response();
        }
        "tools/list" => {
            json!({"tools":[{"name":"echo","description":"Echo a value","inputSchema":{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}}]})
        }
        "tools/call" => {
            json!({"content":[{"type":"text","text":request["params"]["arguments"]["message"]}]})
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})).into_response()
}

#[tokio::test]
async fn pkce_survives_restart_refresh_rotates_and_real_mcp_tool_executes() {
    let fixture = fixture().await;
    let http = OutboundHttp::for_local_tests();
    let states = DurableStates::default();
    let credentials = DurableCredentials::default();
    let service = OAuthService::new(http.clone());
    let started = service
        .begin(
            BeginOAuthRequest {
                mcp_url: format!("{}/mcp", fixture.provider.base),
                redirect_uri: format!("{}/callback", fixture.provider.base),
                scopes: vec!["mcp".into()],
                client_id: None,
                client_secret: None,
                client_metadata_url: None,
            },
            states.clone(),
            credentials.clone(),
        )
        .await
        .unwrap();
    let url = url::Url::parse(&started.authorization_url).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(query["scope"].contains("offline_access"));
    *fixture.provider.challenge.lock().await = Some(query["code_challenge"].clone());
    let serialized_config = serde_json::to_vec(&started.configuration).unwrap();
    drop(service);
    drop(started);

    // A new service + a deserialized configuration simulates a cold callback.
    let config: OAuthConfiguration = serde_json::from_slice(&serialized_config).unwrap();
    let restarted = OAuthService::new(http.clone());
    restarted
        .finish(
            &config,
            "test-code",
            &query["state"],
            None,
            states.clone(),
            credentials.clone(),
        )
        .await
        .unwrap();
    assert!(states.load(&query["state"]).await.unwrap().is_none());
    assert!(
        restarted
            .finish(
                &config,
                "test-code",
                &query["state"],
                None,
                states.clone(),
                credentials.clone()
            )
            .await
            .is_err()
    );

    // Initial access token is near expiry; connecting refreshes automatically.
    let manager = restarted
        .manager(&config, states.clone(), credentials.clone())
        .await
        .unwrap();
    let session = McpSession::connect_oauth(&http, &config.mcp_url, manager)
        .await
        .unwrap();
    assert_eq!(fixture.provider.refresh_count.load(Ordering::SeqCst), 1);
    let tools = session.tools().await.unwrap();
    assert_eq!(tools[0].name, "echo");
    let result = session
        .call_tool(
            "echo",
            json!({"message":"real MCP round trip"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
    let json_result = serde_json::to_value(result).unwrap();
    assert_eq!(json_result["content"][0]["text"], "real MCP round trip");
    session.close().await.unwrap();

    // Scheduled renewal preserves refresh_token when omitted by the server.
    restarted
        .refresh(&config, credentials.clone())
        .await
        .unwrap();
    let stored = credentials.load().await.unwrap().unwrap();
    assert_eq!(
        stored
            .token_response
            .unwrap()
            .refresh_token()
            .unwrap()
            .secret(),
        "refresh-1"
    );
    restarted
        .refresh(&config, credentials.clone())
        .await
        .unwrap();
    assert_eq!(fixture.provider.refresh_count.load(Ordering::SeqCst), 3);

    // Serialized refreshes always load the latest rotated token under the guard.
    let (a, b) = tokio::join!(
        restarted.refresh(&config, credentials.clone()),
        restarted.refresh(&config, credentials.clone())
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(fixture.provider.refresh_count.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn changed_issuer_is_rejected_before_sending_credentials() {
    let fixture = fixture().await;
    let service = OAuthService::new(OutboundHttp::for_local_tests());
    let config = OAuthConfiguration {
        mcp_url: format!("{}/mcp", fixture.provider.base),
        client_id: "test-client".into(),
        client_secret: Some("test-secret".into()),
        redirect_uri: format!("{}/callback", fixture.provider.base),
        scopes: vec!["mcp".into()],
        issuer: Some("https://old-issuer.example".into()),
    };
    let error = service
        .manager(
            &config,
            DurableStates::default(),
            DurableCredentials::default(),
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(error, ConnectorError::IssuerChanged));
    assert_eq!(fixture.provider.refresh_count.load(Ordering::SeqCst), 0);
}
