use crate::{
    app::App,
    budget::GlobalBudget,
    connectors::{ConnectorError, McpSession, OAuthConfiguration, OAuthService},
    domain::*,
    engine::*,
    store::Row,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub async fn connect(app: &App, c: &Connection) -> Result<McpSession, ConnectorError> {
    if c.status != "connected" {
        return Err(ConnectorError::AuthorizationRequired);
    }
    let context = format!("{}/{}", c.agent_id, c.id);
    match c.auth_type.as_str() {
        "oauth" => {
            let cfg: OAuthConfiguration = app
                .vault
                .open(
                    &context,
                    c.oauth_config
                        .as_deref()
                        .ok_or(ConnectorError::AuthorizationRequired)?,
                )
                .await
                .map_err(|_| ConnectorError::AuthorizationRequired)?;
            let stores = app.oauth_stores(&c.agent_id, &c.id);
            let manager = OAuthService::new(app.http.clone())
                .manager(&cfg, stores.clone(), stores)
                .await?;
            McpSession::connect_oauth(&app.http, &c.url, manager).await
        }
        "bearer" => {
            let token: String = app
                .vault
                .open(
                    &context,
                    c.secret
                        .as_deref()
                        .ok_or(ConnectorError::AuthorizationRequired)?,
                )
                .await
                .map_err(|_| ConnectorError::AuthorizationRequired)?;
            McpSession::connect(&app.http, &c.url, Some(&token)).await
        }
        "none" => McpSession::connect(&app.http, &c.url, None).await,
        _ => Err(ConnectorError::AuthorizationRequired),
    }
}
struct Executor {
    app: App,
    agent: String,
    sessions: BTreeMap<String, McpSession>,
}
#[async_trait]
impl ToolExecutor for &Executor {
    async fn execute(
        &self,
        connector_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<ToolResult, ToolExecutionError> {
        let denied = || ToolExecutionError {
            message: "connector is no longer authorized".into(),
            outcome_unknown: false,
        };
        crate::api::agent(&self.app, &self.agent)
            .await
            .map_err(|_| denied())?;
        let (_, c) = crate::api::connection(&self.app, &self.agent, connector_id)
            .await
            .map_err(|_| denied())?;
        if c.status != "connected" || !c.allowed_tools.iter().any(|a| a == "*" || a == tool_name) {
            return Err(denied());
        }
        let session = self.sessions.get(connector_id).ok_or_else(denied)?;
        let args = arguments.as_object().cloned().ok_or_else(denied)?;
        let response =
            session
                .call_tool(tool_name, args)
                .await
                .map_err(|_| ToolExecutionError {
                    message: "connector operation outcome is unknown; automatic retry disabled"
                        .into(),
                    outcome_unknown: true,
                })?;
        Ok(ToolResult {
            is_error: response.is_error.unwrap_or(false),
            content: serde_json::to_value(response).map_err(|_| denied())?,
        })
    }

    async fn refresh_tools(
        &self,
        connector_id: &str,
    ) -> Result<Option<Vec<AvailableTool>>, ToolExecutionError> {
        let unavailable = || ToolExecutionError {
            message: "connector tools could not be refreshed".into(),
            outcome_unknown: false,
        };
        self.authorized_connection(connector_id).await?;
        let session = self.sessions.get(connector_id).ok_or_else(unavailable)?;
        let exposed = session.tools().await.map_err(|_| unavailable())?;
        // Permissions may change while tools/list is in flight. Rediscovery
        // cannot grant access: apply the latest exact allowlist after it returns.
        let connection = self.authorized_connection(connector_id).await?;
        Ok(Some(
            exposed
                .into_iter()
                .filter(|tool| {
                    connection
                        .allowed_tools
                        .iter()
                        .any(|allowed| allowed == "*" || allowed == tool.name.as_ref())
                })
                .map(|tool| AvailableTool {
                    connector_id: connector_id.to_owned(),
                    name: tool.name.to_string(),
                    description: tool
                        .description
                        .as_ref()
                        .map(|text| text.to_string())
                        .unwrap_or_default(),
                    input_schema: json!(tool.input_schema),
                })
                .collect(),
        ))
    }
}
impl Executor {
    async fn authorized_connection(
        &self,
        connector_id: &str,
    ) -> Result<Connection, ToolExecutionError> {
        let denied = || ToolExecutionError {
            message: "connector is no longer authorized".into(),
            outcome_unknown: false,
        };
        crate::api::agent(&self.app, &self.agent)
            .await
            .map_err(|_| denied())?;
        let (_, connection) = crate::api::connection(&self.app, &self.agent, connector_id)
            .await
            .map_err(|_| denied())?;
        if connection.status != "connected" {
            return Err(denied());
        }
        Ok(connection)
    }

    async fn close(self) {
        let mut pending = tokio::task::JoinSet::new();
        for (_, session) in self.sessions {
            pending.spawn(async move {
                let _ = session.close().await;
            });
        }
        while pending.join_next().await.is_some() {}
    }
}

async fn agent_active(app: &App, id: &str) -> anyhow::Result<bool> {
    let Some(row) = app.store.get(&agent_pk(id), "META").await? else {
        return Ok(false);
    };
    Ok(!row.payload.is_null() && row.payload["deleted"] != true)
}
pub async fn run_task(app: App, agent_id: &str, task_id: &str) -> anyhow::Result<()> {
    let pk = agent_pk(agent_id);
    let sk = format!("TASK#{task_id}");
    let Some(mut row) = app.store.get(&pk, &sk).await? else {
        return Ok(());
    };
    if row.payload.is_null() {
        return Ok(());
    }
    let mut task: Task = serde_json::from_value(row.payload.clone())?;
    if task.status != "queued" {
        return Ok(());
    }
    if !agent_active(&app, agent_id).await? {
        let version = row.version;
        task.status = "cancelled".into();
        task.error = Some("agent_deleted".into());
        task.updated_at = now();
        row.payload = json!(task);
        row.due = None;
        app.store.put(row, Some(version)).await?;
        return Ok(());
    }
    let version = row.version;
    task.status = "running".into();
    task.lease_until = now() + 270;
    task.updated_at = now();
    row.payload = json!(task);
    row.due = Some(("TASK".into(), task.lease_until));
    if !app.store.put(row, Some(version)).await? {
        return Ok(());
    }
    tracing::info!(event = "task_started", task_id);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(240),
        execute_task(app.clone(), &task),
    )
    .await;
    let Some(mut row) = app.store.get(&pk, &sk).await? else {
        return Ok(());
    };
    if row.payload.is_null() {
        return Ok(());
    }
    let mut current: Task = serde_json::from_value(row.payload.clone())?;
    if current.status != "running" {
        return Ok(());
    }
    match result {
        Ok(Ok(output)) => {
            current.status = "completed".into();
            current.result = Some(output);
        }
        Ok(Err(error)) => {
            current.status = if matches!(
                error,
                EngineError::ToolOutcomeUnknown { .. } | EngineError::ToolRefreshFailed { .. }
            ) {
                "interrupted"
            } else {
                "failed"
            }
            .into();
            current.error = Some(
                match error {
                    EngineError::Budget(BudgetError::Exhausted) => {
                        "global_monthly_budget_exhausted"
                    }
                    EngineError::ToolOutcomeUnknown { .. } => {
                        "tool_outcome_unknown_do_not_retry_blindly"
                    }
                    EngineError::ToolRefreshFailed { .. } => {
                        "tool_refresh_failed_after_execution_do_not_retry_blindly"
                    }
                    EngineError::InvalidInput(_) => "skill_or_connector_unavailable",
                    _ => "execution_failed",
                }
                .into(),
            );
        }
        Err(_) => {
            current.status = "interrupted".into();
            current.error = Some("execution_timeout_outcome_may_be_unknown".into());
        }
    }
    current.updated_at = now();
    current.lease_until = 0;
    let v = row.version;
    row.payload = json!(current);
    row.due = None;
    if !app.store.put(row, Some(v)).await? {
        anyhow::bail!("task completion conflict")
    }
    tracing::info!(event="task_finished",task_id,status=%current.status);
    Ok(())
}
async fn execute_task(app: App, task: &Task) -> Result<EngineOutput, EngineError> {
    let mut executor = Executor {
        app: app.clone(),
        agent: task.agent_id.clone(),
        sessions: BTreeMap::new(),
    };
    let result = execute_with_sessions(app, task, &mut executor).await;
    executor.close().await;
    result
}

async fn execute_with_sessions(
    app: App,
    task: &Task,
    executor: &mut Executor,
) -> Result<EngineOutput, EngineError> {
    let bad = || EngineError::InvalidInput("agent, skill or connector unavailable".into());
    crate::api::agent(&app, &task.agent_id)
        .await
        .map_err(|_| bad())?;
    let mut instructions = String::new();
    let mut ids = BTreeSet::new();
    for skill in &task.skill_ids {
        let row = app
            .store
            .get(&agent_pk(&task.agent_id), &format!("SKILL#{skill}"))
            .await
            .map_err(|_| bad())?
            .ok_or_else(bad)?;
        let skill: Skill = serde_json::from_value(row.payload).map_err(|_| bad())?;
        instructions.push_str(&format!("\n# {}\n{}\n", skill.name, skill.instructions));
        ids.extend(skill.connector_ids);
    }
    let mut tools = Vec::new();
    for id in ids {
        let (row, c) = crate::api::connection(&app, &task.agent_id, &id)
            .await
            .map_err(|_| bad())?;
        let credentials_version = if c.auth_type == "oauth" {
            app.store
                .get(&agent_pk(&c.agent_id), &format!("CREDENTIALS#{}", c.id))
                .await
                .map_err(|_| bad())?
                .map(|row| row.version)
        } else {
            None
        };
        let session = match connect(&app, &c).await {
            Ok(s) => s,
            Err(e) => {
                if e.requires_authorization() {
                    let _ = set_connection_status(
                        &app,
                        &c,
                        row.version,
                        "reauthorization_required",
                        None,
                        credentials_version,
                    )
                    .await;
                }
                return Err(bad());
            }
        };
        executor.sessions.insert(id.clone(), session);
        tools.extend(
            (&*executor)
                .refresh_tools(&id)
                .await
                .map_err(|_| bad())?
                .ok_or_else(bad)?,
        );
    }
    let config = app.aws.as_ref().ok_or_else(bad)?;
    let model = BedrockModel::new(config, app.model_id.clone(), app.count_model_id.clone());
    let budget = GlobalBudget {
        store: app.store.clone(),
        limit: app.monthly_budget,
    };
    Engine::new(model, budget, &*executor, app.engine_config.clone())
        .run(EngineInput {
            task_id: task.id.clone(),
            instructions,
            request: task.request.clone(),
            tools,
        })
        .await
}
async fn set_connection_status(
    app: &App,
    c: &Connection,
    expected_version: u64,
    status: &str,
    due: Option<i64>,
    clear_credentials_version: Option<u64>,
) -> anyhow::Result<bool> {
    if !agent_active(app, &c.agent_id).await? {
        return Ok(false);
    }
    let Some(mut row) = app
        .store
        .get(&agent_pk(&c.agent_id), &format!("CONN#{}", c.id))
        .await?
    else {
        return Ok(false);
    };
    // A refresh begun before an owner reconnects or edits the connection must
    // never overwrite the newer authorization's status or maintenance schedule.
    if row.version != expected_version
        || row.payload.is_null()
        || row.payload["status"] != c.status
        || row.payload["oauth_config"] != json!(c.oauth_config)
    {
        return Ok(false);
    }
    row.payload["status"] = json!(status);
    row.payload["next_maintenance"] = json!(due.unwrap_or(0));
    row.due = due.map(|t| ("CONNECTION".into(), t));
    if let Some(version) = clear_credentials_version {
        // CAS the credentials observed BEFORE refresh, not whatever a newer
        // successful callback might have written while the request was in flight.
        let empty = Row::new(
            agent_pk(&c.agent_id),
            format!("CREDENTIALS#{}", c.id),
            json!({}),
        );
        app.store
            .transaction(vec![(row, Some(expected_version)), (empty, Some(version))])
            .await
    } else {
        app.store.put(row, Some(expected_version)).await
    }
}

/// Dispatch a bounded page of due connections; each OAuth exchange runs in its
/// own SQS invocation. No scheduler invocation waits for 100 remote providers.
pub async fn maintenance(app: &App) -> anyhow::Result<()> {
    let candidates = app.store.due("CONNECTION", now()).await?;
    let full_page = candidates.len() >= 100;
    for candidate in candidates {
        let Some(mut row) = app.store.get(&candidate.pk, &candidate.sk).await? else {
            continue;
        };
        if row
            .due
            .as_ref()
            .is_none_or(|(kind, t)| kind != "CONNECTION" || *t > now())
        {
            continue;
        }
        let Ok(mut c) = serde_json::from_value::<Connection>(row.payload.clone()) else {
            clear_due(app, row).await?;
            continue;
        };
        if c.status != "connected"
            || c.auth_type != "oauth"
            || !agent_active(app, &c.agent_id).await?
        {
            clear_due(app, row).await?;
            continue;
        }
        if app.sqs.is_none() {
            continue;
        }
        let previous = row.version;
        // Claim before enqueue. A crash before send is recovered after five
        // minutes; a duplicate old SQS delivery cannot match the new version.
        c.next_maintenance = now() + 300;
        row.payload = json!(c);
        row.due = Some(("CONNECTION".into(), c.next_maintenance));
        if !app.store.put(row, Some(previous)).await? {
            continue;
        }
        enqueue_job(
            app,
            json!({"kind":"oauth_refresh", "agent_id":c.agent_id,
            "connection_id":c.id, "expected_version":previous + 1}),
            0,
        )
        .await?;
    }
    if full_page {
        // Re-query after GSI propagation, so later pages cannot starve behind
        // the first 100 results or stale index entries. No opaque cursor needed:
        // claimed rows move to a future due time and leave the current result set.
        enqueue_job(app, json!({"kind":"oauth_maintenance"}), 30).await?;
    }
    Ok(())
}

pub async fn refresh_connection(
    app: &App,
    agent_id: &str,
    connection_id: &str,
    expected_version: u64,
) -> anyhow::Result<()> {
    if !agent_active(app, agent_id).await? {
        return Ok(());
    }
    let Some(mut row) = app
        .store
        .get(&agent_pk(agent_id), &format!("CONN#{connection_id}"))
        .await?
    else {
        return Ok(());
    };
    if row.version != expected_version || row.payload.is_null() {
        return Ok(());
    }
    let mut c: Connection = serde_json::from_value(row.payload.clone())?;
    if c.status != "connected" || c.auth_type != "oauth" {
        return Ok(());
    }
    if row
        .due
        .as_ref()
        .is_none_or(|(kind, _)| kind != "CONNECTION")
    {
        return Ok(());
    }
    // Consume this queue generation before a remote request. SQS redeliveries
    // with the same expected_version cannot refresh twice concurrently.
    c.next_maintenance = now() + 300;
    row.payload = json!(c);
    row.due = Some(("CONNECTION".into(), c.next_maintenance));
    if !app.store.put(row, Some(expected_version)).await? {
        return Ok(());
    }
    let expected_version = expected_version + 1;
    let credentials_version = app
        .store
        .get(&agent_pk(agent_id), &format!("CREDENTIALS#{connection_id}"))
        .await?
        .map(|row| row.version);
    let cfg: OAuthConfiguration = app
        .vault
        .open(
            &format!("{}/{}", c.agent_id, c.id),
            c.oauth_config
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing OAuth config"))?,
        )
        .await?;
    match OAuthService::new(app.http.clone())
        .refresh(&cfg, app.oauth_stores(agent_id, connection_id))
        .await
    {
        Ok(()) => {
            set_connection_status(
                app,
                &c,
                expected_version,
                "connected",
                Some(now() + 7 * 86400),
                None,
            )
            .await?;
        }
        Err(error) if error.requires_authorization() => {
            set_connection_status(
                app,
                &c,
                expected_version,
                "reauthorization_required",
                None,
                credentials_version,
            )
            .await?;
        }
        Err(_) => {
            set_connection_status(
                app,
                &c,
                expected_version,
                "connected",
                Some(now() + 3600),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn clear_due(app: &App, mut row: Row) -> anyhow::Result<()> {
    let version = row.version;
    row.due = None;
    app.store.put(row, Some(version)).await?;
    Ok(())
}

async fn enqueue_job(app: &App, job: Value, delay_seconds: i32) -> anyhow::Result<()> {
    if let Some(sqs) = &app.sqs {
        sqs.send_message()
            .queue_url(&app.queue_url)
            .message_body(job.to_string())
            .delay_seconds(delay_seconds)
            .send()
            .await?;
    }
    Ok(())
}

pub async fn dispatch_pending(app: &App) -> anyhow::Result<()> {
    let candidates = app.store.due("TASK", now()).await?;
    let full_page = candidates.len() >= 100;
    for r in candidates {
        let Some(mut row) = app.store.get(&r.pk, &r.sk).await? else {
            continue;
        };
        if row
            .due
            .as_ref()
            .is_none_or(|(kind, t)| kind != "TASK" || *t > now())
        {
            continue;
        }
        let Ok(mut t) = serde_json::from_value::<Task>(row.payload.clone()) else {
            clear_due(app, row).await?;
            continue;
        };
        if t.status == "queued" {
            if !agent_active(app, &t.agent_id).await? {
                t.status = "cancelled".into();
                t.error = Some("agent_deleted".into());
                t.updated_at = now();
                let version = row.version;
                row.payload = json!(t);
                row.due = None;
                app.store.put(row, Some(version)).await?;
                continue;
            }
            if app.sqs.is_none() {
                continue;
            }
            let version = row.version;
            row.due = Some(("TASK".into(), now() + 300));
            if app.store.put(row, Some(version)).await? {
                app.enqueue(&t.agent_id, &t.id).await?;
            }
        } else if t.status == "running" && t.lease_until <= now() {
            let v = row.version;
            t.status = "interrupted".into();
            t.error = Some("worker_stopped_outcome_may_be_unknown".into());
            t.updated_at = now();
            t.lease_until = 0;
            row.payload = json!(t);
            row.due = None;
            app.store.put(row, Some(v)).await?;
        } else if t.status != "running" {
            clear_due(app, row).await?;
        }
    }
    if full_page {
        enqueue_job(app, json!({"kind":"dispatch_pending"}), 30).await?;
    }
    Ok(())
}

async fn handle_job(app: App, job: Value) -> anyhow::Result<()> {
    match job["kind"].as_str() {
        Some("oauth_maintenance") => maintenance(&app).await,
        Some("dispatch_pending") => dispatch_pending(&app).await,
        Some("oauth_refresh") => {
            refresh_connection(
                &app,
                job["agent_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing agent"))?,
                job["connection_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing connection"))?,
                job["expected_version"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("missing refresh version"))?,
            )
            .await
        }
        None | Some("task") => {
            run_task(
                app,
                job["agent_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing agent"))?,
                job["task_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing task"))?,
            )
            .await
        }
        _ => anyhow::bail!("unknown worker job"),
    }
}

pub async fn handle_event(app: App, event: Value) -> anyhow::Result<Value> {
    if event["kind"].as_str().is_some() {
        handle_job(app, event).await?;
        return Ok(json!({"ok":true}));
    }
    let records = event["Records"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid worker event"))?;
    let mut failed = Vec::new();
    for record in records {
        let result = async {
            let job = serde_json::from_str(
                record["body"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing body"))?,
            )?;
            handle_job(app.clone(), job).await
        }
        .await;
        if result.is_err() {
            failed.push(json!({"itemIdentifier":record["messageId"]}));
        }
    }
    Ok(json!({"batchItemFailures":failed}))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> App {
        let app = App::local().await.unwrap();
        let a = Agent {
            id: "agent".into(),
            name: "test".into(),
            description: String::new(),
            key_hash: "test".into(),
            created_at: now(),
            deleted: false,
        };
        app.store
            .put(Row::new(agent_pk("agent"), "META", json!(a)), None)
            .await
            .unwrap();
        app
    }

    async fn add_task(app: &App, status: &str) {
        let task = Task {
            id: "task".into(),
            agent_id: "agent".into(),
            request: "Do a task".into(),
            skill_ids: vec![],
            status: status.into(),
            created_at: now(),
            updated_at: now(),
            result: None,
            error: None,
            lease_until: if status == "running" { now() - 1 } else { 0 },
        };
        let mut row = Row::new(agent_pk("agent"), "TASK#task", json!(task));
        row.due = Some(("TASK".into(), now() - 1));
        app.store.put(row, None).await.unwrap();
    }

    async fn add_connection(app: &App, id: &str) -> Connection {
        let connection = Connection {
            id: id.into(),
            agent_id: "agent".into(),
            name: "test".into(),
            url: "https://mcp.example/mcp".into(),
            auth_type: "oauth".into(),
            status: "connected".into(),
            allowed_tools: vec!["*".into()],
            created_at: now(),
            next_maintenance: now() - 1,
            secret: None,
            oauth_config: Some("not-a-secret-test-placeholder".into()),
        };
        let mut row = Row::new(agent_pk("agent"), format!("CONN#{id}"), json!(connection));
        row.due = Some(("CONNECTION".into(), now() - 1));
        app.store.put(row, None).await.unwrap();
        connection
    }

    async fn delete_agent(app: &App) {
        let mut row = app
            .store
            .get(&agent_pk("agent"), "META")
            .await
            .unwrap()
            .unwrap();
        let version = row.version;
        row.payload["deleted"] = json!(true);
        app.store.put(row, Some(version)).await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_sqs_tasks_are_claimed_once_and_terminal_tasks_do_not_run_again() {
        let app = fixture().await;
        add_task(&app, "queued").await;
        let (a, b) = tokio::join!(
            run_task(app.clone(), "agent", "task"),
            run_task(app.clone(), "agent", "task")
        );
        a.unwrap();
        b.unwrap();
        let first = app
            .store
            .get(&agent_pk("agent"), "TASK#task")
            .await
            .unwrap()
            .unwrap();
        // The real worker enters once, then fails because this local app has no
        // Bedrock configuration. Initial row -> running -> terminal = version 3.
        assert_eq!(first.version, 3);
        assert_eq!(first.payload["status"], "failed");
        run_task(app.clone(), "agent", "task").await.unwrap();
        let after = app
            .store
            .get(&agent_pk("agent"), "TASK#task")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.version, first.version);
    }

    #[tokio::test]
    async fn expired_running_task_is_interrupted_and_never_replayed() {
        let app = fixture().await;
        add_task(&app, "running").await;
        dispatch_pending(&app).await.unwrap();
        let row = app
            .store
            .get(&agent_pk("agent"), "TASK#task")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.payload["status"], "interrupted");
        assert_eq!(
            row.payload["error"],
            "worker_stopped_outcome_may_be_unknown"
        );
        assert!(row.due.is_none());
        run_task(app.clone(), "agent", "task").await.unwrap();
        assert_eq!(
            app.store
                .get(&agent_pk("agent"), "TASK#task")
                .await
                .unwrap()
                .unwrap()
                .version,
            row.version
        );
    }

    #[tokio::test]
    async fn deletion_prevents_execution_and_maintenance_before_any_external_request() {
        let app = fixture().await;
        add_task(&app, "queued").await;
        add_connection(&app, "connection").await;
        delete_agent(&app).await;
        run_task(app.clone(), "agent", "task").await.unwrap();
        let task = app
            .store
            .get(&agent_pk("agent"), "TASK#task")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(task.payload["status"], "cancelled");
        assert_eq!(task.version, 2);
        // OAuth config is intentionally invalid: success proves that deleted
        // agents are rejected before secret decryption or remote discovery.
        refresh_connection(&app, "agent", "connection", 1)
            .await
            .unwrap();
        maintenance(&app).await.unwrap();
        assert!(
            app.store
                .get(&agent_pk("agent"), "CONN#connection")
                .await
                .unwrap()
                .unwrap()
                .due
                .is_none()
        );
    }

    #[tokio::test]
    async fn refresh_generation_is_consumed_once_even_when_execution_fails() {
        let app = fixture().await;
        add_connection(&app, "connection").await;
        assert!(
            refresh_connection(&app, "agent", "connection", 1)
                .await
                .is_err()
        );
        let row = app
            .store
            .get(&agent_pk("agent"), "CONN#connection")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.version, 2);
        assert!(row.due.as_ref().unwrap().1 > now());
        refresh_connection(&app, "agent", "connection", 1)
            .await
            .unwrap();
        assert_eq!(
            app.store
                .get(&agent_pk("agent"), "CONN#connection")
                .await
                .unwrap()
                .unwrap()
                .version,
            2
        );
    }

    #[tokio::test]
    async fn stale_refresh_cannot_change_reconnected_status_or_clear_rotated_credentials() {
        let app = fixture().await;
        let c = add_connection(&app, "connection").await;
        app.store
            .put(
                Row::new(
                    agent_pk("agent"),
                    "CREDENTIALS#connection",
                    json!({"sealed":"old"}),
                ),
                None,
            )
            .await
            .unwrap();
        let newer = Row::new(
            agent_pk("agent"),
            "CREDENTIALS#connection",
            json!({"sealed":"new"}),
        );
        app.store.put(newer, Some(1)).await.unwrap();
        assert!(
            !set_connection_status(&app, &c, 1, "reauthorization_required", None, Some(1))
                .await
                .unwrap()
        );
        let row = app
            .store
            .get(&agent_pk("agent"), "CONN#connection")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.payload["status"], "connected");
        let mut newer = row;
        newer.payload["oauth_config"] = json!("new-authorization");
        app.store.put(newer, Some(1)).await.unwrap();
        assert!(
            !set_connection_status(&app, &c, 1, "reauthorization_required", None, None)
                .await
                .unwrap()
        );
        let credentials = app
            .store
            .get(&agent_pk("agent"), "CREDENTIALS#connection")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(credentials.payload["sealed"], "new");
    }

    async fn dynamic_executor(allow_run: bool) -> (Executor, wiremock::MockServer) {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let configured = Arc::new(AtomicBool::new(false));
        Mock::given(method("POST")).respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let method = body["method"].as_str().unwrap();
            if method != "initialize" {
                assert_eq!(request.headers["mcp-session-id"], "worker-test-session");
            }
            let result = match method {
                "initialize" => json!({"protocolVersion":body["params"]["protocolVersion"],
                    "capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}),
                "notifications/initialized" => return ResponseTemplate::new(202),
                "tools/list" => json!({"tools":[{
                    "name": if configured.load(Ordering::SeqCst) {"run_calendar-create"} else {"calendar-create"},
                    "inputSchema":{"type":"object"}}]}),
                "tools/call" => {
                    assert_eq!(body["params"]["name"], "calendar-create");
                    configured.store(true, Ordering::SeqCst);
                    json!({"content":[{"type":"text","text":"Run tool now available"}],"isError":false})
                }
                _ => panic!("unexpected fixture method {method}"),
            };
            ResponseTemplate::new(200)
                .insert_header("mcp-session-id", "worker-test-session")
                .set_body_json(json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
        }).mount(&server).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(405))
            .mount(&server)
            .await;
        let mut app = fixture().await;
        app.http = crate::connectors::OutboundHttp::for_local_tests();
        let mut connection = add_connection(&app, "connection").await;
        connection.url = server.uri();
        connection.auth_type = "none".into();
        connection.allowed_tools = vec!["calendar-create".into()];
        if allow_run {
            connection.allowed_tools.push("run_calendar-create".into());
        }
        app.store
            .put(
                Row::new(agent_pk("agent"), "CONN#connection", json!(connection)),
                Some(1),
            )
            .await
            .unwrap();
        let session = connect(&app, &connection).await.unwrap();
        (
            Executor {
                app,
                agent: "agent".into(),
                sessions: BTreeMap::from([("connection".into(), session)]),
            },
            server,
        )
    }

    #[tokio::test]
    async fn refresh_dynamic_catalog_requires_exact_allowlist_on_the_same_session() {
        for allow_run in [false, true] {
            let (executor, server) = dynamic_executor(allow_run).await;
            let initial = (&executor)
                .refresh_tools("connection")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(initial.len(), 1);
            assert_eq!(initial[0].name, "calendar-create");
            (&executor)
                .execute("connection", "calendar-create", json!({}))
                .await
                .unwrap();
            let dynamic = (&executor)
                .refresh_tools("connection")
                .await
                .unwrap()
                .unwrap();
            if allow_run {
                assert_eq!(dynamic.len(), 1);
                assert_eq!(dynamic[0].name, "run_calendar-create");
            } else {
                assert!(dynamic.is_empty());
                let denied = (&executor)
                    .execute("connection", "run_calendar-create", json!({}))
                    .await
                    .unwrap_err();
                assert!(!denied.outcome_unknown);
            }
            let methods: Vec<_> = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.method == "POST")
                .map(|request| {
                    serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            assert_eq!(
                methods,
                [
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "tools/call",
                    "tools/list"
                ]
            );
            executor.close().await;
        }
    }

    #[tokio::test]
    async fn refresh_catalog_rejects_disconnected_connector_and_deleted_agent() {
        let (executor, server) = dynamic_executor(true).await;
        for status in ["disconnected", "connected"] {
            let mut row = executor
                .app
                .store
                .get(&agent_pk("agent"), "CONN#connection")
                .await
                .unwrap()
                .unwrap();
            let version = row.version;
            row.payload["status"] = json!(status);
            executor.app.store.put(row, Some(version)).await.unwrap();
            if status == "connected" {
                delete_agent(&executor.app).await;
            }
            let before = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count();
            let denied = (&executor).refresh_tools("connection").await.unwrap_err();
            assert!(!denied.outcome_unknown);
            assert_eq!(denied.message, "connector is no longer authorized");
            let after = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count();
            assert_eq!(
                before, after,
                "revocation must block tools/list before network I/O"
            );
        }
        executor.close().await;
    }

    #[tokio::test]
    async fn maintenance_fans_out_full_page_and_later_connections_are_not_starved() {
        use aws_sdk_sqs::config::{BehaviorVersion, Credentials, Region};
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"MessageId":"test-message","MD5OfMessageBody":"00000000000000000000000000000000"})
        )).mount(&server).await;
        let mut app = fixture().await;
        app.sqs = Some(aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("eu-west-1"))
                .credentials_provider(Credentials::new("test", "test", None, None, "test"))
                .endpoint_url(server.uri())
                .build(),
        ));
        app.queue_url = format!("{}/queue", server.uri());
        for number in 0..101 {
            add_connection(&app, &format!("connection-{number:03}")).await;
        }
        maintenance(&app).await.unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 101); // 100 refresh jobs plus continuation.
        let mut refreshes = 0;
        let mut continuation = false;
        for request in requests {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let message: Value =
                serde_json::from_str(body["MessageBody"].as_str().unwrap()).unwrap();
            match message["kind"].as_str().unwrap() {
                "oauth_refresh" => {
                    refreshes += 1;
                    assert_eq!(message["expected_version"], 2);
                }
                "oauth_maintenance" => {
                    continuation = true;
                    assert_eq!(body["DelaySeconds"], 30);
                }
                other => panic!("unexpected job {other}"),
            }
        }
        assert_eq!(refreshes, 100);
        assert!(continuation);
        maintenance(&app).await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 102);
        assert!(app.store.due("CONNECTION", now()).await.unwrap().is_empty());
    }
}
