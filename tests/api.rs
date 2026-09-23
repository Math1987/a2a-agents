//! In-process HTTP integration tests: actual Axum router, authorization middleware,
//! JSON extraction, encryption and compare-and-swap storage. No calendar is called.

use a2a_agents::{api::router, app::App, domain::agent_pk};
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

struct Client {
    app: App,
    router: Router,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
}

impl Client {
    async fn new() -> Self {
        let app = App::local().await.unwrap();
        let router = router(app.clone());
        Self { app, router }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> Reply {
        self.call_with_idempotency(method, path, key, body, None)
            .await
    }

    async fn call_with_idempotency(
        &self,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<Value>,
        idempotency: Option<&str>,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        if let Some(value) = idempotency {
            request = request.header("idempotency-key", value);
        }
        let body = if let Some(value) = body {
            request = request.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        } else {
            Body::empty()
        };
        let response = self
            .router
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"non_json_body":String::from_utf8_lossy(&bytes)}))
        };
        Reply {
            status,
            headers,
            json,
        }
    }

    async fn agent(&self, name: &str) -> (String, String) {
        let response = self
            .call(
                Method::POST,
                "/v1/agents",
                None,
                Some(json!({"name":name,"description":"Test agent"})),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.json);
        (
            response.json["id"].as_str().unwrap().into(),
            response.json["owner_key"].as_str().unwrap().into(),
        )
    }

    async fn skill(&self, agent: &str, key: &str, skill: &str) -> Reply {
        self.call(Method::PUT, &format!("/v1/agents/{agent}/skills/{skill}"), Some(key), Some(json!({
            "id":"body-id-is-not-authoritative", "name":"Plan a meeting", "description":"Find a common slot",
            "instructions":"PRIVATE_INSTRUCTIONS: prefer Tuesday after reviewing confidential project details.",
            "connector_ids":[]
        }))).await
    }
}

#[tokio::test]
async fn public_creation_issues_one_secret_and_stores_only_its_digest() {
    let client = Client::new().await;
    let (agent, key) = client.agent("First agent").await;
    assert!(key.starts_with("agt_"));
    assert!(key.len() >= 40);
    let (_, second_key) = client.agent("Second agent").await;
    assert_ne!(key, second_key);

    let response = client
        .call(
            Method::GET,
            &format!("/v1/agents/{agent}"),
            Some(&key),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json["name"], "First agent");
    assert!(response.json.get("owner_key").is_none());
    assert!(response.json.get("key_hash").is_none());
    assert_eq!(response.headers["cache-control"], "no-store");
    assert_eq!(response.headers["referrer-policy"], "no-referrer");

    let stored = client
        .app
        .store
        .get(&agent_pk(&agent), "META")
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.payload.to_string().contains(&key));
    assert!(!stored.payload["key_hash"].as_str().unwrap().is_empty());
    assert_eq!(
        client
            .call(Method::GET, &format!("/v1/agents/{agent}"), None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn owner_key_is_scoped_to_its_agent_across_management_and_invocation_routes() {
    let client = Client::new().await;
    let (_, alice_key) = client.agent("Alice").await;
    let (bob, bob_key) = client.agent("Bob").await;
    assert_eq!(
        client.skill(&bob, &bob_key, "planning").await.status,
        StatusCode::OK
    );
    for (method, suffix, body) in [
        (Method::GET, "", None),
        (Method::PATCH, "", Some(json!({"name":"Changed"}))),
        (Method::POST, "/key", None),
        (Method::GET, "/skills", None),
        (Method::GET, "/connectors", None),
        (
            Method::POST,
            "/connectors",
            Some(json!({"name":"Remote", "url":"https://example.com/mcp", "auth_type":"none"})),
        ),
        (Method::GET, "/tasks", None),
        (
            Method::POST,
            "/tasks",
            Some(json!({"request":"Find slots"})),
        ),
        (Method::DELETE, "", None),
    ] {
        let response = client
            .call(
                method.clone(),
                &format!("/v1/agents/{bob}{suffix}"),
                Some(&alice_key),
                body,
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{method} {suffix}: {}",
            response.json
        );
    }
    let bob_response = client
        .call(
            Method::GET,
            &format!("/v1/agents/{bob}"),
            Some(&bob_key),
            None,
        )
        .await;
    assert_eq!(bob_response.status, StatusCode::OK);
    assert_eq!(bob_response.json["name"], "Bob");
}

#[tokio::test]
async fn public_card_exposes_skill_capabilities_without_private_instructions_or_keys() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Calendar").await;
    let saved = client.skill(&agent, &key, "planning").await;
    assert_eq!(saved.status, StatusCode::OK);
    assert_eq!(saved.json["id"], "planning");
    let listed = client
        .call(
            Method::GET,
            &format!("/v1/agents/{agent}/skills"),
            Some(&key),
            None,
        )
        .await;
    assert!(
        listed.json["skills"][0]["instructions"]
            .as_str()
            .unwrap()
            .contains("PRIVATE_INSTRUCTIONS")
    );

    let response = client
        .call(
            Method::GET,
            &format!("/agents/{agent}/agent-card.json"),
            None,
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json["skills"][0]["id"], "planning");
    assert_eq!(
        response.json["skills"][0]["description"],
        "Find a common slot"
    );
    let body = response.json.to_string();
    for private in [&key, "key_hash", "PRIVATE_INSTRUCTIONS", "connector_ids"] {
        assert!(!body.contains(private), "private field exposed in card");
    }
    let binding = response.json["supportedInterfaces"][0]["protocolBinding"]
        .as_str()
        .unwrap();
    assert_eq!(binding, "JSONRPC");
    let card: a2a_protocol::AgentCard = serde_json::from_value(response.json).unwrap();
    assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    assert!(card.security_requirements.unwrap()[0].contains_key("owner"));

    assert_eq!(
        client
            .call(
                Method::DELETE,
                &format!("/v1/agents/{agent}/skills/planning"),
                Some(&key),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let response = client
        .call(
            Method::GET,
            &format!("/agents/{agent}/agent-card.json"),
            None,
            None,
        )
        .await;
    assert_eq!(response.json["skills"], json!([]));
}

#[tokio::test]
async fn rotating_owner_key_revokes_the_previous_secret_immediately() {
    let client = Client::new().await;
    let (agent, old_key) = client.agent("Rotate").await;
    let rotation = client
        .call(
            Method::POST,
            &format!("/v1/agents/{agent}/key"),
            Some(&old_key),
            None,
        )
        .await;
    assert_eq!(rotation.status, StatusCode::OK);
    let new_key = rotation.json["owner_key"].as_str().unwrap();
    assert_ne!(old_key, new_key);
    assert_eq!(
        client
            .call(
                Method::GET,
                &format!("/v1/agents/{agent}"),
                Some(&old_key),
                None
            )
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .call(
                Method::GET,
                &format!("/v1/agents/{agent}"),
                Some(new_key),
                None
            )
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        client
            .call(
                Method::POST,
                &format!("/v1/agents/{agent}/key"),
                Some(&old_key),
                None
            )
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn task_idempotency_reuses_one_task_and_rejects_changed_payloads() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Tasks").await;
    assert_eq!(
        client.skill(&agent, &key, "planning").await.status,
        StatusCode::OK
    );
    let path = format!("/v1/agents/{agent}/tasks");
    let request = json!({"request":"Find a 30 minute slot", "skill_ids":["planning"]});
    let first = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(request.clone()),
            Some("meeting-request-1"),
        )
        .await;
    let second = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(request),
            Some("meeting-request-1"),
        )
        .await;
    assert_eq!(first.status, StatusCode::ACCEPTED);
    assert_eq!(second.status, StatusCode::ACCEPTED);
    assert_eq!(first.json["id"], second.json["id"]);
    assert_eq!(first.json["status"], "queued");
    let changed = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Book a 60 minute slot"})),
            Some("meeting-request-1"),
        )
        .await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
    assert_eq!(changed.json["error"], "idempotency_key_reused");

    let tasks = client.call(Method::GET, &path, Some(&key), None).await;
    assert_eq!(tasks.json["tasks"].as_array().unwrap().len(), 1);
    let task_id = first.json["id"].as_str().unwrap();
    let task = client
        .call(Method::GET, &format!("{path}/{task_id}"), Some(&key), None)
        .await;
    assert_eq!(task.json["request"], "Find a 30 minute slot");
    let (_, foreign_key) = client.agent("Other agent").await;
    assert_eq!(
        client
            .call(
                Method::GET,
                &format!("{path}/{task_id}"),
                Some(&foreign_key),
                None
            )
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn concurrent_idempotent_submissions_create_a_single_stored_task() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Concurrent tasks").await;
    assert_eq!(
        client.skill(&agent, &key, "planning").await.status,
        StatusCode::OK
    );
    let path = format!("/v1/agents/{agent}/tasks");
    let (a, b) = tokio::join!(
        client.call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Find slots"})),
            Some("same-key")
        ),
        client.call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Find slots"})),
            Some("same-key")
        ),
    );
    assert_eq!(a.status, StatusCode::ACCEPTED);
    assert_eq!(b.status, StatusCode::ACCEPTED);
    assert_eq!(a.json["id"], b.json["id"]);
    assert_eq!(
        client
            .app
            .store
            .list(&agent_pk(&agent), "TASK#")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn bearer_connector_secret_is_encrypted_and_omitted_from_every_response() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Connector").await;
    let token = "private_connector_token_not_for_responses";
    let path = format!("/v1/agents/{agent}/connectors");
    let created = client.call(Method::POST, &path, Some(&key), Some(json!({
        "name":"Remote calendar", "url":"https://example.com/mcp", "auth_type":"bearer", "token":token,
        "allowed_tools":["list_slots"]
    }))).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json["status"], "connected");
    assert_eq!(created.json["allowed_tools"], json!(["list_slots"]));
    let listed = client.call(Method::GET, &path, Some(&key), None).await;
    for body in [&created.json, &listed.json] {
        assert!(!body.to_string().contains(token));
        assert!(!body.to_string().contains("secret"));
        assert!(!body.to_string().contains("oauth_config"));
    }
    let connection = created.json["id"].as_str().unwrap();
    let stored = client
        .app
        .store
        .get(&agent_pk(&agent), &format!("CONN#{connection}"))
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.payload.to_string().contains(token));
    let sealed = stored.payload["secret"].as_str().unwrap();
    let decrypted: String = client
        .app
        .vault
        .open(&format!("{agent}/{connection}"), sealed)
        .await
        .unwrap();
    assert_eq!(decrypted, token);
    assert!(
        client
            .app
            .vault
            .open::<String>("another-agent/connection", sealed)
            .await
            .is_err()
    );

    assert_eq!(
        client
            .call(
                Method::DELETE,
                &format!("{path}/{connection}"),
                Some(&key),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        client.call(Method::GET, &path, Some(&key), None).await.json["connectors"],
        json!([])
    );
    let stored = client
        .app
        .store
        .get(&agent_pk(&agent), &format!("CONN#{connection}"))
        .await
        .unwrap()
        .unwrap();
    assert!(stored.payload["secret"].is_null());
}

#[tokio::test]
async fn connector_cannot_reference_a_private_endpoint_or_another_agents_connection() {
    let client = Client::new().await;
    let (alice, alice_key) = client.agent("Alice").await;
    let (bob, bob_key) = client.agent("Bob").await;
    let created = client
        .call(
            Method::POST,
            &format!("/v1/agents/{bob}/connectors"),
            Some(&bob_key),
            Some(json!({
                "name":"Bob calendar", "url":"https://example.com/mcp", "auth_type":"none"
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let foreign_id = created.json["id"].as_str().unwrap();
    let response = client.call(Method::PUT, &format!("/v1/agents/{alice}/skills/planning"), Some(&alice_key), Some(json!({
        "id":"planning", "name":"Plan", "description":"Plan", "instructions":"Use Bob's calendar", "connector_ids":[foreign_id]
    }))).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    for url in [
        "http://example.com/mcp",
        "https://169.254.169.254/latest/meta-data/",
        "https://localhost/mcp",
    ] {
        let response = client
            .call(
                Method::POST,
                &format!("/v1/agents/{alice}/connectors"),
                Some(&alice_key),
                Some(json!({"name":"Unsafe", "url":url, "auth_type":"none"})),
            )
            .await;
        assert!(response.status.is_client_error() || response.status.is_server_error());
        assert!(!response.json.to_string().contains("169.254.169.254"));
    }
    assert!(
        client
            .app
            .store
            .list(&agent_pk(&alice), "CONN#")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn deleting_an_agent_revokes_auth_removes_its_card_and_clears_private_records() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Delete me").await;
    assert_eq!(
        client.skill(&agent, &key, "planning").await.status,
        StatusCode::OK
    );
    assert_eq!(
        client
            .call(
                Method::POST,
                &format!("/v1/agents/{agent}/tasks"),
                Some(&key),
                Some(json!({"request":"Find a slot"}))
            )
            .await
            .status,
        StatusCode::ACCEPTED
    );
    assert_eq!(client.call(Method::POST, &format!("/v1/agents/{agent}/connectors"), Some(&key), Some(json!({
        "name":"Calendar", "url":"https://example.com/mcp", "auth_type":"bearer", "token":"delete-this-secret"
    }))).await.status, StatusCode::CREATED);
    assert_eq!(
        client
            .call(
                Method::DELETE,
                &format!("/v1/agents/{agent}"),
                Some(&key),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    for suffix in ["", "/skills", "/connectors", "/tasks"] {
        assert_eq!(
            client
                .call(
                    Method::GET,
                    &format!("/v1/agents/{agent}{suffix}"),
                    Some(&key),
                    None
                )
                .await
                .status,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        client
            .call(
                Method::GET,
                &format!("/agents/{agent}/agent-card.json"),
                None,
                None
            )
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    for row in client.app.store.list(&agent_pk(&agent), "").await.unwrap() {
        if row.sk == "META" {
            assert_eq!(row.payload["deleted"], true);
            assert_eq!(row.payload["key_hash"], "");
        } else {
            assert!(row.payload.is_null());
            assert!(row.due.is_none());
            assert!(row.expires_at.is_some());
        }
    }
}

#[tokio::test]
async fn invocation_requires_a_real_configured_skill_and_rejects_unknown_skills() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Empty agent").await;
    let path = format!("/v1/agents/{agent}/tasks");
    assert_eq!(
        client
            .call(
                Method::POST,
                &path,
                Some(&key),
                Some(json!({"request":"Do something"}))
            )
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client.skill(&agent, &key, "planning").await.status,
        StatusCode::OK
    );
    assert_eq!(
        client
            .call(
                Method::POST,
                &path,
                Some(&key),
                Some(json!({"request":"Do something", "skill_ids":["missing"]}))
            )
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert!(
        client
            .app
            .store
            .list(&agent_pk(&agent), "TASK#")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn skill_id_comes_from_the_path_without_redundant_body_id() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Simple skill configuration").await;
    let response = client.call(Method::PUT, &format!("/v1/agents/{agent}/skills/planning"), Some(&key), Some(json!({
        "name":"Plan", "description":"Find a slot", "instructions":"Ask for the desired duration."
    }))).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json["id"], "planning");
}

fn matches_openapi_schema(name: &str, instance: &Value) {
    let contract: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    let schema = json!({
        "$ref":format!("#/components/schemas/{name}"),
        "components":contract["components"]
    });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        validator.is_valid(instance),
        "API response violates documented {name} schema: {:?}",
        validator
            .iter_errors(instance)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn live_route_responses_match_the_published_openapi_contract() {
    let client = Client::new().await;
    let response = client.call(Method::GET, "/openapi.json", None, None).await;
    assert_eq!(response.status, StatusCode::OK);
    matches_openapi_schema("OpenApiDocument", &response.json);
    assert_eq!(
        response.json["paths"]["/v1/agents"]["post"]["security"],
        json!([])
    );
    assert_eq!(
        response.json["paths"]["/agents/{agent}/agent-card.json"]["get"]["security"],
        json!([])
    );

    let created = client
        .call(
            Method::POST,
            "/v1/agents",
            None,
            Some(json!({"name":"Contract test"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    matches_openapi_schema("AgentCreated", &created.json);
    let agent = created.json["id"].as_str().unwrap();
    let key = created.json["owner_key"].as_str().unwrap();
    let response = client
        .call(Method::GET, &format!("/v1/agents/{agent}"), Some(key), None)
        .await;
    matches_openapi_schema("Agent", &response.json);
    let response = client.skill(agent, key, "planning").await;
    matches_openapi_schema("Skill", &response.json);
    let response = client
        .call(
            Method::GET,
            &format!("/agents/{agent}/agent-card.json"),
            None,
            None,
        )
        .await;
    matches_openapi_schema("AgentCard", &response.json);
    let task = client
        .call(
            Method::POST,
            &format!("/v1/agents/{agent}/tasks"),
            Some(key),
            Some(json!({"request":"Summarize the project"})),
        )
        .await;
    assert_eq!(task.status, StatusCode::ACCEPTED);
    matches_openapi_schema("Task", &task.json);

    // Simulate the worker's persisted result and verify the real retrieval route,
    // including the public accounting shape, without paid model inference.
    let task_id = task.json["id"].as_str().unwrap();
    let mut row = client
        .app
        .store
        .get(&agent_pk(agent), &format!("TASK#{task_id}"))
        .await
        .unwrap()
        .unwrap();
    let version = row.version;
    row.payload["status"] = json!("completed");
    row.payload["result"] = serde_json::to_value(a2a_agents::engine::EngineOutput {
        text: "Project is on track.".into(),
        usage: a2a_agents::engine::Usage {
            input_tokens: 100,
            output_tokens: 10,
        },
        cost_microusd: 165,
        model_calls: 1,
        tool_calls: 0,
        input_required: None,
        history: vec![],
    })
    .unwrap();
    assert!(client.app.store.put(row, Some(version)).await.unwrap());
    let response = client
        .call(
            Method::GET,
            &format!("/v1/agents/{agent}/tasks/{task_id}"),
            Some(key),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    matches_openapi_schema("Task", &response.json);
    assert_eq!(response.json["result"]["text"], "Project is on track.");
}

#[tokio::test]
async fn idempotent_replay_survives_deleting_the_original_explicit_skill() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Stable request receipt").await;
    assert_eq!(
        client.skill(&agent, &key, "planning").await.status,
        StatusCode::OK
    );
    let path = format!("/v1/agents/{agent}/tasks");
    let body = json!({"request":"Find a slot", "skill_ids":["planning"]});
    let original = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(body.clone()),
            Some("stable"),
        )
        .await;
    assert_eq!(original.status, StatusCode::ACCEPTED);
    assert_eq!(
        client
            .call(
                Method::DELETE,
                &format!("/v1/agents/{agent}/skills/planning"),
                Some(&key),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let replay = client
        .call_with_idempotency(Method::POST, &path, Some(&key), Some(body), Some("stable"))
        .await;
    assert_eq!(replay.status, StatusCode::ACCEPTED);
    assert_eq!(replay.json, original.json);
    let changed = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Find two slots", "skill_ids":["planning"]})),
            Some("stable"),
        )
        .await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
    assert_eq!(changed.json["error"], "idempotency_key_reused");
    assert_eq!(
        client
            .app
            .store
            .list(&agent_pk(&agent), "TASK#")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        client
            .app
            .store
            .list(&agent_pk(&agent), "IDEMPOTENCY#")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn omitted_skill_selection_replays_the_original_task_after_configuration_changes() {
    let client = Client::new().await;
    let (agent, key) = client.agent("Default selection receipt").await;
    assert_eq!(
        client.skill(&agent, &key, "first").await.status,
        StatusCode::OK
    );
    let path = format!("/v1/agents/{agent}/tasks");
    let original = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Summarize"})),
            Some("default-selection"),
        )
        .await;
    assert_eq!(original.status, StatusCode::ACCEPTED);
    assert_eq!(
        client.skill(&agent, &key, "second").await.status,
        StatusCode::OK
    );
    let replay = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Summarize", "skill_ids":[]})),
            Some("default-selection"),
        )
        .await;
    assert_eq!(replay.status, StatusCode::ACCEPTED);
    assert_eq!(replay.json["id"], original.json["id"]);
    assert_eq!(replay.json["skill_ids"], json!(["first"]));
    // An explicit selection is a different original request, even if it happens
    // to match the first task's resolved list.
    let changed = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Summarize", "skill_ids":["first"]})),
            Some("default-selection"),
        )
        .await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
    for skill in ["first", "second"] {
        assert_eq!(
            client
                .call(
                    Method::DELETE,
                    &format!("/v1/agents/{agent}/skills/{skill}"),
                    Some(&key),
                    None
                )
                .await
                .status,
            StatusCode::NO_CONTENT
        );
    }
    let replay = client
        .call_with_idempotency(
            Method::POST,
            &path,
            Some(&key),
            Some(json!({"request":"Summarize"})),
            Some("default-selection"),
        )
        .await;
    assert_eq!(replay.status, StatusCode::ACCEPTED);
    assert_eq!(replay.json, original.json);
}

#[tokio::test]
async fn oauth_disconnect_waits_for_inflight_refresh_before_clearing_rotated_tokens() {
    use rmcp::transport::auth::{CredentialStore, StoredCredentials};
    use std::time::Duration;

    let client = Client::new().await;
    let (agent, key) = client.agent("Refresh versus disconnect").await;
    let response = client
        .call(
            Method::POST,
            &format!("/v1/agents/{agent}/connectors"),
            Some(&key),
            Some(json!({
                "name":"OAuth fixture", "url":"https://example.com/mcp", "auth_type":"oauth"
            })),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let connection = response.json["id"].as_str().unwrap();
    let mut row = client
        .app
        .store
        .get(&agent_pk(&agent), &format!("CONN#{connection}"))
        .await
        .unwrap()
        .unwrap();
    let version = row.version;
    row.payload["status"] = json!("connected");
    assert!(client.app.store.put(row, Some(version)).await.unwrap());
    let credentials = |token: &str| {
        StoredCredentials::new(
        "fixture-client".into(),
        Some(serde_json::from_value(json!({"access_token":token,"refresh_token":"rotating-refresh","token_type":"Bearer","expires_in":3600})).unwrap()),
        vec![],
        Some(a2a_agents::domain::now() as u64),
    )
    };
    let stores = client.app.oauth_stores(&agent, connection);
    stores.save(credentials("initial")).await.unwrap();
    let guard = stores.acquire_refresh_guard().await.unwrap();

    // Hold the same durable lease a real SDK refresh owns while its provider
    // request is in flight, then route DELETE through the actual API.
    let router = client.router.clone();
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/v1/agents/{agent}/connectors/{connection}"))
        .header("authorization", format!("Bearer {key}"))
        .body(Body::empty())
        .unwrap();
    let mut deleting = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut deleting)
            .await
            .is_err(),
        "disconnect completed before the in-flight credential save"
    );
    let mut row = client
        .app
        .store
        .get(&agent_pk(&agent), &format!("CONN#{connection}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.payload["status"], "connected");
    // Maintenance may update this row while DELETE is waiting. The endpoint
    // must reload the new version after acquiring the lease.
    let version = row.version;
    row.payload["next_maintenance"] = json!(a2a_agents::domain::now() + 7 * 86400);
    assert!(client.app.store.put(row, Some(version)).await.unwrap());

    stores.save(credentials("rotated")).await.unwrap();
    drop(guard);
    let response = tokio::time::timeout(Duration::from_secs(2), deleting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let persisted = client
        .app
        .store
        .get(&agent_pk(&agent), &format!("CREDENTIALS#{connection}"))
        .await
        .unwrap()
        .unwrap();
    assert!(persisted.payload.get("sealed").is_none());
    assert!(stores.save(credentials("must-not-reappear")).await.is_err());
}
