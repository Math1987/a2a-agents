//! Live A2A smoke test using the official Rust client. Creates/deletes a disposable
//! agent, retains its key only in memory, and spends a small amount from the global
//! Bedrock budget. Never accesses a user's calendar or connector credentials.
use a2a_client::{A2AClient, A2AClientFactory, Transport, auth::AuthInterceptor};
use a2a_protocol::{
    GetTaskRequest, Message, Part, Role, SendMessageConfiguration, SendMessageRequest,
    SendMessageResponse, Task, TaskState,
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

fn send(text: &str, task: Option<&Task>) -> SendMessageRequest {
    let mut message = Message::new(Role::User, vec![Part::text(text)]);
    if let Some(task) = task {
        message.task_id = Some(task.id.clone());
        message.context_id = Some(task.context_id.clone());
    }
    SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            return_immediately: Some(true),
            accepted_output_modes: None,
            task_push_notification_config: None,
            history_length: None,
        }),
        metadata: None,
        tenant: None,
    }
}

fn task(response: SendMessageResponse) -> anyhow::Result<Task> {
    match response {
        SendMessageResponse::Task(t) => Ok(t),
        _ => anyhow::bail!("expected an asynchronous Task"),
    }
}

async fn wait(client: &A2AClient<Box<dyn Transport>>, mut task: Task) -> anyhow::Result<Task> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(290);
    while matches!(task.status.state, TaskState::Submitted | TaskState::Working) {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "task polling timed out"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        task = client
            .get_task(&GetTaskRequest {
                id: task.id.clone(),
                history_length: Some(20),
                tenant: None,
            })
            .await?;
    }
    Ok(task)
}

async fn exercise(
    http: &reqwest::Client,
    base: &str,
    agent: &str,
    key: &str,
) -> anyhow::Result<()> {
    let path = format!("{base}/v1/agents/{agent}");
    http.put(format!("{path}/skills/conversation")).bearer_auth(key).json(&json!({
        "name":"Conversation smoke test", "description":"Ask for a missing code then repeat it.",
        "instructions":"The user wants you to repeat a secret-free test code. If the code was not given, use runtime_request_input to ask for it. Once provided, respond in French with that exact code. Do not invent a code.", "connector_ids":[]
    })).send().await?.error_for_status()?;
    let card = a2a_client::agent_card::AgentCardResolver::new(Some(http.clone()))
        .resolve(&format!("{base}/agents/{agent}"))
        .await?;
    ensure!(
        card.supported_interfaces[0].protocol_binding == "JSONRPC",
        "missing A2A interface"
    );
    let client = A2AClientFactory::builder()
        .register(Arc::new(a2a_client::jsonrpc::JsonRpcTransportFactory::new(
            Some(http.clone()),
        )))
        .with_interceptor(Arc::new(AuthInterceptor::bearer(key)))
        .build()
        .create_from_card(&card)
        .await?;
    let request = send("Peux-tu me rappeler mon code de test ?", None);
    let submitted = task(client.send_message(&request).await?)?;
    let duplicate = task(client.send_message(&request).await?)?;
    ensure!(submitted.id == duplicate.id, "message was not deduplicated");
    let question = wait(&client, submitted).await?;
    ensure!(
        question.status.state == TaskState::InputRequired,
        "expected input-required, got {:?}",
        question.status.state
    );
    println!("PASS: official SDK discovery, asynchronous send, idempotency and input-required");
    let answer = send("Mon code de test est AZUR-724.", Some(&question));
    let resumed = task(client.send_message(&answer).await?)?;
    ensure!(
        resumed.id == question.id,
        "continuation changed task identity"
    );
    let completed = wait(&client, resumed).await?;
    ensure!(
        completed.status.state == TaskState::Completed,
        "continuation did not complete"
    );
    ensure!(
        serde_json::to_string(&completed.artifacts)?.contains("AZUR-724"),
        "result omitted real user input"
    );
    let internal: Value = http
        .get(format!("{path}/tasks/{}", completed.id))
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        internal["result"]["model_calls"].as_u64().unwrap_or(0) >= 2,
        "missing cumulative model accounting"
    );
    println!(
        "PASS: durable continuation, output artifact and cumulative budget ({} micro-USD)",
        internal["result"]["cost_microusd"]
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = std::env::args()
        .nth(1)
        .context("Usage: cargo run --example a2a_smoke -- https://agents.aithos.app")?;
    let base = base.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(28))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let created: Value = http
        .post(format!("{base}/v1/agents"))
        .json(&json!({"name":"Disposable A2A interoperability smoke"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let agent = created["id"].as_str().context("missing agent ID")?;
    let key = created["owner_key"].as_str().context("missing owner key")?;
    let result = exercise(&http, base, agent, key).await;
    http.delete(format!("{base}/v1/agents/{agent}"))
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?;
    println!("PASS: disposable agent cleanup");
    result
}
