//! Compatibility checks use the official A2A Rust client and server over real HTTP.
//! No Bedrock call or third-party calendar is involved.
use std::sync::Arc;

use a2a_agents::{
    api,
    app::App,
    crypto::digest,
    domain::{agent_pk, now},
    store::Row,
};
use a2a_client::{A2AClient, auth::AuthInterceptor, jsonrpc::JsonRpcTransport};
use a2a_protocol as protocol;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn app() -> App {
    let app = App::local().await.unwrap();
    for (id, key) in [("alpha", "alpha-owner"), ("beta", "beta-owner")] {
        app.store.put(Row::new(agent_pk(id), "META", json!({
            "id":id,"name":"Test A2A","description":"Local protocol test", "key_hash":digest(key),"created_at":now()
        })), None).await.unwrap();
        app.store.put(Row::new(agent_pk(id), "SKILL#test", json!({
            "id":"test","name":"Test","description":"Text-only test", "instructions":"Answer briefly.","connector_ids":[]
        })), None).await.unwrap();
    }
    app
}

fn message() -> protocol::SendMessageRequest {
    protocol::SendMessageRequest {
        message: protocol::Message::new(
            protocol::Role::User,
            vec![protocol::Part::text("Bonjour")],
        ),
        configuration: Some(protocol::SendMessageConfiguration {
            return_immediately: Some(true),
            accepted_output_modes: Some(vec!["text/plain".into()]),
            history_length: Some(1),
            task_push_notification_config: None,
        }),
        metadata: None,
        tenant: None,
    }
}

#[tokio::test]
async fn official_sdk_client_round_trips_discovery_send_get_list_and_cancel() {
    let app = app().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut serving = app.clone();
    serving.public_url = url.clone();
    let server =
        tokio::spawn(async move { axum::serve(listener, api::router(serving)).await.unwrap() });
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let card: protocol::AgentCard = http
        .get(format!("{url}/agents/alpha/agent-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let interface = card.supported_interfaces.first().unwrap();
    assert_eq!(interface.protocol_binding, "JSONRPC");
    assert_eq!(interface.protocol_version, "1.0");
    assert_eq!(interface.url, format!("{url}/agents/alpha/a2a"));
    let client = A2AClient::new(JsonRpcTransport::new(http.clone(), interface.url.clone()))
        .with_interceptors(vec![Arc::new(AuthInterceptor::bearer("alpha-owner"))]);
    let request = message();
    let task = match client.send_message(&request).await.unwrap() {
        protocol::SendMessageResponse::Task(task) => task,
        _ => panic!("expected durable task"),
    };
    assert_eq!(task.status.state, protocol::TaskState::Submitted);
    assert_eq!(task.history.as_ref().unwrap()[0].text(), Some("Bonjour"));
    let retry = match client.send_message(&request).await.unwrap() {
        protocol::SendMessageResponse::Task(task) => task,
        _ => panic!("expected same task"),
    };
    assert_eq!(retry.id, task.id);
    let retrieved = client
        .get_task(&protocol::GetTaskRequest {
            id: task.id.clone(),
            history_length: Some(0),
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(retrieved.id, task.id);
    assert!(retrieved.history.is_none());
    let listing = client
        .list_tasks(&protocol::ListTasksRequest {
            context_id: Some(task.context_id.clone()),
            status: Some(protocol::TaskState::Submitted),
            page_size: Some(10),
            page_token: None,
            history_length: Some(0),
            status_timestamp_after: None,
            include_artifacts: Some(false),
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(listing.total_size, 1);
    assert_eq!(listing.tasks[0].id, task.id);
    let canceled = client
        .cancel_task(&protocol::CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(canceled.status.state, protocol::TaskState::Canceled);
    let second_cancel = client
        .cancel_task(&protocol::CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(second_cancel.status.state, protocol::TaskState::Canceled);
    let other_agent = A2AClient::new(JsonRpcTransport::new(
        http,
        format!("{url}/agents/beta/a2a"),
    ))
    .with_interceptors(vec![Arc::new(AuthInterceptor::bearer("beta-owner"))]);
    assert_eq!(
        other_agent
            .get_task(&protocol::GetTaskRequest {
                id: task.id,
                history_length: None,
                tenant: None
            })
            .await
            .unwrap_err()
            .code,
        protocol::error_code::TASK_NOT_FOUND
    );
    server.abort();
}

async fn raw(
    app: &App,
    key: Option<&str>,
    version: &str,
    method: &str,
    params: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/agents/alpha/a2a")
        .header("content-type", "application/json")
        .header("A2A-Version", version);
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let response = api::router(app.clone())
        .oneshot(
            builder
                .body(Body::from(
                    json!({
                        "jsonrpc":"2.0","id":"request-123","method":method,"params":params
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

#[tokio::test]
async fn http_authentication_versions_and_unsupported_requests_fail_before_persisting() {
    let app = app().await;
    let params = serde_json::to_value(message()).unwrap();
    for key in [None, Some("incorrect"), Some("beta-owner")] {
        let (status, headers, _) = raw(&app, key, "1.0", "SendMessage", params.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.contains_key("www-authenticate"));
    }
    for (version, method, params, code) in [
        (
            "0.3",
            "SendMessage",
            params.clone(),
            protocol::error_code::VERSION_NOT_SUPPORTED,
        ),
        (
            "1.0",
            "UnknownMethod",
            json!({}),
            protocol::error_code::METHOD_NOT_FOUND,
        ),
        (
            "1.0",
            "SendStreamingMessage",
            params.clone(),
            protocol::error_code::UNSUPPORTED_OPERATION,
        ),
        (
            "1.0",
            "ListTasks",
            json!({"pageSize":101}),
            protocol::error_code::INVALID_PARAMS,
        ),
    ] {
        let (status, _, result) = raw(&app, Some("alpha-owner"), version, method, params).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["id"], "request-123");
        assert_eq!(result["error"]["code"], code, "{result}");
    }
    // The official SDK normalizes non-positive protobuf pageSize values to
    // absent before calling the application handler.
    let (_, _, normalized) = raw(
        &app,
        Some("alpha-owner"),
        "1.0",
        "ListTasks",
        json!({"pageSize":-1}),
    )
    .await;
    assert_eq!(normalized["result"]["pageSize"], 50);
    let mut sync = message();
    sync.configuration.as_mut().unwrap().return_immediately = None;
    let (_, _, result) = raw(
        &app,
        Some("alpha-owner"),
        "1.0",
        "SendMessage",
        serde_json::to_value(sync).unwrap(),
    )
    .await;
    assert_eq!(
        result["error"]["code"],
        protocol::error_code::UNSUPPORTED_OPERATION
    );
    assert!(
        app.store
            .list(&agent_pk("alpha"), "TASK#")
            .await
            .unwrap()
            .is_empty()
    );
}
