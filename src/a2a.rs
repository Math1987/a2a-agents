//! A2A 1.0 application adapter. The official SDK owns JSON-RPC and ProtoJSON.
//! Execution remains durable in DynamoDB/SQS; no SDK in-memory worker is used.
use std::{sync::Arc, time::Duration};

use a2a_protocol as protocol;
use a2a_server::{RequestHandler, ServiceParams};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{
    a2a_auth::{self, Principal},
    app::App,
    crypto::digest,
    domain::{A2aTaskData, ConversationMessage, Task, agent_pk, now},
    store::Row,
};

const MAX_MESSAGES: usize = 32;
const MAX_CONVERSATION_BYTES: usize = 96 * 1024;
const MAX_TEXT_BYTES: usize = 32_000;

pub fn router(app: App) -> Router {
    Router::new()
        .route("/agents/{agent}/a2a", post(dispatch))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024))
        .with_state(app)
}

async fn dispatch(
    State(app): State<App>,
    Path(agent_id): Path<String>,
    mut request: Request,
) -> Response {
    let principal = match a2a_auth::authenticate(&app, &agent_id, request.headers()).await {
        Ok(principal) => principal,
        Err(error) => {
            let mut response = (error.status, Json(json!({"error":error.message}))).into_response();
            if error.status == axum::http::StatusCode::UNAUTHORIZED {
                response.headers_mut().insert(
                    "www-authenticate",
                    "Bearer realm=\"a2a\"".parse().expect("static header"),
                );
            }
            return response;
        }
    };
    // Capture the authenticated route identity instead of trusting a caller-
    // supplied tenant header. The SDK only sees this one agent's handler.
    let handler = Arc::new(Handler {
        app,
        agent_id,
        principal,
    });
    *request.uri_mut() = "/".parse().expect("static URI");
    match a2a_server::jsonrpc::jsonrpc_router(handler)
        .oneshot(request)
        .await
    {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

struct Handler {
    app: App,
    agent_id: String,
    principal: Principal,
}

fn internal(_: impl std::fmt::Display) -> protocol::A2AError {
    protocol::A2AError::internal("service unavailable")
}

fn invalid(message: &str) -> protocol::A2AError {
    protocol::A2AError::invalid_params(message)
}

fn identifier(value: &str) -> Result<(), protocol::A2AError> {
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(invalid(
            "identifiers must contain 1 to 200 characters without control characters",
        ));
    }
    Ok(())
}

fn history_length(value: Option<i32>) -> Result<Option<usize>, protocol::A2AError> {
    value
        .map(|length| {
            usize::try_from(length)
                .map_err(|_| invalid("historyLength must not be negative"))
                .map(|length| length.min(MAX_MESSAGES))
        })
        .transpose()
}

impl Handler {
    fn check(
        &self,
        params: &ServiceParams,
        tenant: Option<&str>,
    ) -> Result<(), protocol::A2AError> {
        if let Some(versions) = params.get("a2a-version")
            && (versions.len() != 1 || versions[0] != "1.0")
        {
            return Err(protocol::A2AError::version_not_supported(
                versions.first().map(String::as_str).unwrap_or(""),
            ));
        }
        if tenant.is_some_and(|tenant| !tenant.is_empty() && tenant != self.agent_id) {
            return Err(invalid("tenant must match the agent in the request URL"));
        }
        Ok(())
    }

    fn may_read(&self, task: &Task) -> bool {
        task.agent_id == self.agent_id
            && task.a2a.as_ref().is_some_and(|data| {
                self.principal.is_owner() || data.caller_id == self.principal.caller_id()
            })
    }

    async fn task(&self, id: &str) -> Result<(Row, Task), protocol::A2AError> {
        identifier(id)?;
        let missing = || protocol::A2AError::task_not_found(id);
        let row = self
            .app
            .store
            .get(&agent_pk(&self.agent_id), &format!("TASK#{id}"))
            .await
            .map_err(internal)?
            .ok_or_else(missing)?;
        if row.payload.is_null() {
            return Err(missing());
        }
        let task: Task = serde_json::from_value(row.payload.clone()).map_err(internal)?;
        if !self.may_read(&task) {
            return Err(missing());
        }
        Ok((row, task))
    }

    async fn allowed_skills(&self) -> Result<Vec<String>, protocol::A2AError> {
        let skills = crate::api::skills(&self.app, &self.agent_id)
            .await
            .map_err(|_| protocol::A2AError::internal("agent skills unavailable"))?;
        let mut ids = skills
            .into_iter()
            .map(|skill| skill.id)
            .filter(|id| match &self.principal {
                Principal::Owner => true,
                Principal::Invoker { skill_ids, .. } => skill_ids.contains(id),
            })
            .collect::<Vec<_>>();
        ids.sort();
        Ok(ids)
    }

    async fn receipt(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<Option<Task>, protocol::A2AError> {
        let Some(receipt) = self
            .app
            .store
            .get(&agent_pk(&self.agent_id), key)
            .await
            .map_err(internal)?
        else {
            return Ok(None);
        };
        if receipt.payload["fingerprint"].as_str() != Some(fingerprint) {
            return Err(invalid(
                "messageId was already used with different message contents",
            ));
        }
        let task_id = receipt.payload["task_id"]
            .as_str()
            .ok_or_else(|| protocol::A2AError::internal("invalid message receipt"))?;
        let (_, task) = self.task(task_id).await?;
        Ok(Some(task))
    }

    async fn enqueue(&self, task: &Task) {
        if self.app.enqueue(&self.agent_id, &task.id).await.is_err() {
            // The existing dispatcher recovers this durable queued record.
            tracing::warn!(event = "a2a_task_enqueue_deferred");
        }
        if self.app.sqs.is_none() && self.app.aws.is_some() {
            let app = self.app.clone();
            let agent_id = self.agent_id.clone();
            let task_id = task.id.clone();
            tokio::spawn(async move {
                let _ = crate::worker::run_task(app, &agent_id, &task_id).await;
            });
        }
    }
}

fn public_message(task: &Task, message: &ConversationMessage) -> protocol::Message {
    let mut result = protocol::Message::new(
        if message.role == "user" {
            protocol::Role::User
        } else {
            protocol::Role::Agent
        },
        vec![protocol::Part::text(&message.text)],
    );
    result.message_id = message.id.clone();
    result.task_id = Some(task.id.clone());
    result.context_id = task.a2a.as_ref().map(|data| data.context_id.clone());
    result
}

fn public_task(task: &Task, history: Option<usize>, artifacts: bool) -> protocol::Task {
    let data = task.a2a.as_ref().expect("A2A task already checked");
    let state = match task.status.as_str() {
        "queued" => protocol::TaskState::Submitted,
        "running" => protocol::TaskState::Working,
        "input_required" => protocol::TaskState::InputRequired,
        "completed" => protocol::TaskState::Completed,
        "cancelled" => protocol::TaskState::Canceled,
        _ => protocol::TaskState::Failed,
    };
    let status_message = if let Some(error) = &task.error {
        Some(public_message(
            task,
            &ConversationMessage {
                id: format!("{}:error:{}", task.id, data.turn),
                role: "agent".into(),
                text: error.clone(),
            },
        ))
    } else {
        data.messages
            .last()
            .filter(|message| message.role == "agent")
            .map(|message| public_message(task, message))
    };
    let history = match history {
        Some(0) => None,
        length => {
            let start = data
                .messages
                .len()
                .saturating_sub(length.unwrap_or(MAX_MESSAGES));
            Some(
                data.messages[start..]
                    .iter()
                    .map(|message| public_message(task, message))
                    .collect(),
            )
        }
    };
    let result_artifacts = if artifacts && task.status == "completed" {
        task.result.as_ref().map(|result| {
            vec![protocol::Artifact {
                artifact_id: format!("{}:result:{}", task.id, data.turn),
                name: Some("Response".into()),
                description: None,
                parts: vec![protocol::Part::text(&result.text)],
                metadata: None,
                extensions: None,
            }]
        })
    } else {
        None
    };
    protocol::Task {
        id: task.id.clone(),
        context_id: data.context_id.clone(),
        status: protocol::TaskStatus {
            state,
            message: status_message,
            timestamp: chrono::DateTime::from_timestamp(task.updated_at, 0),
        },
        artifacts: result_artifacts,
        history,
        // Never serialize the internal task: it contains the private model checkpoint.
        metadata: None,
    }
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    scope: String,
    after: String,
}

#[async_trait]
impl RequestHandler for Handler {
    async fn send_message(
        &self,
        params: &ServiceParams,
        req: protocol::SendMessageRequest,
    ) -> Result<protocol::SendMessageResponse, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        let config = req.configuration.as_ref();
        if config.and_then(|config| config.return_immediately) != Some(true) {
            return Err(protocol::A2AError::unsupported_operation(
                "This deployment requires configuration.returnImmediately=true; poll GetTask for completion. Blocking SendMessage is not supported.",
            ));
        }
        if config
            .and_then(|config| config.task_push_notification_config.as_ref())
            .is_some()
        {
            return Err(protocol::A2AError::push_notification_not_supported());
        }
        if config
            .and_then(|config| config.accepted_output_modes.as_ref())
            .is_some_and(|modes| {
                !modes.is_empty() && !modes.iter().any(|mode| mode == "text/plain")
            })
        {
            return Err(protocol::A2AError::content_type_not_supported());
        }
        let history = history_length(config.and_then(|config| config.history_length))?;
        let message = &req.message;
        identifier(&message.message_id)?;
        if message.role != protocol::Role::User {
            return Err(invalid("SendMessage requires ROLE_USER"));
        }
        if message
            .reference_task_ids
            .as_ref()
            .is_some_and(|ids| !ids.is_empty())
        {
            return Err(protocol::A2AError::unsupported_operation(
                "referenceTaskIds are not supported",
            ));
        }
        if message
            .extensions
            .as_ref()
            .is_some_and(|extensions| !extensions.is_empty())
        {
            return Err(protocol::A2AError::unsupported_operation(
                "message extensions are not supported",
            ));
        }
        let text = message
            .parts
            .iter()
            .map(|part| match &part.content {
                protocol::PartContent::Text(text)
                    if part
                        .media_type
                        .as_deref()
                        .is_none_or(|media| media == "text/plain") =>
                {
                    Ok(text.as_str())
                }
                _ => Err(protocol::A2AError::content_type_not_supported()),
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");
        if text.trim().is_empty() || text.len() > MAX_TEXT_BYTES {
            return Err(invalid("message text must contain 1 to 32000 bytes"));
        }
        let fingerprint = digest(
            &serde_json::to_string(&json!({
                "message": message, "metadata": req.metadata,
            }))
            .map_err(internal)?,
        );
        let caller = self.principal.caller_id();
        let receipt_key = format!(
            "A2AMESSAGE#{}",
            digest(&serde_json::to_string(&json!([caller, message.message_id])).map_err(internal)?)
        );
        if let Some(task) = self.receipt(&receipt_key, &fingerprint).await? {
            return Ok(protocol::SendMessageResponse::Task(public_task(
                &task, history, true,
            )));
        }
        let allowed = self.allowed_skills().await?;
        let selection = req
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("skill_ids"));
        let mut requested: Option<Vec<String>> = selection
            .map(|selection| {
                serde_json::from_value(selection.clone()).map_err(|_| {
                    invalid("metadata.skill_ids must be an array of skill identifiers")
                })
            })
            .transpose()?;
        if let Some(ids) = &mut requested {
            ids.sort();
            ids.dedup();
        }
        let pk = agent_pk(&self.agent_id);
        let mut new_context = None;
        let (mut row, mut task, expected) = if let Some(task_id) =
            message.task_id.as_deref().filter(|id| !id.is_empty())
        {
            let (row, mut task) = self.task(task_id).await?;
            let data = task.a2a.as_mut().expect("A2A task checked");
            if data.caller_id != caller {
                return Err(protocol::A2AError::task_not_found(task_id));
            }
            if message
                .context_id
                .as_ref()
                .is_some_and(|context| !context.is_empty() && context != &data.context_id)
            {
                return Err(invalid("contextId does not match task"));
            }
            if task.status != "input_required" {
                return Err(protocol::A2AError::unsupported_operation(
                    "Only an input-required task can accept another message; terminal tasks cannot be restarted.",
                ));
            }
            if requested
                .as_ref()
                .is_some_and(|ids| !ids.is_empty() && ids != &task.skill_ids)
            {
                return Err(invalid("skill selection cannot change within a task"));
            }
            if task.skill_ids.iter().any(|id| !allowed.contains(id)) {
                return Err(protocol::A2AError::unsupported_operation(
                    "task skills are no longer authorized",
                ));
            }
            data.turn = data
                .turn
                .checked_add(1)
                .ok_or_else(|| invalid("conversation limit reached"))?;
            let expected = Some(row.version);
            (row, task, expected)
        } else {
            let skill_ids = requested
                .filter(|ids| !ids.is_empty())
                .unwrap_or(allowed.clone());
            if skill_ids.is_empty() || skill_ids.iter().any(|id| !allowed.contains(id)) {
                return Err(invalid(
                    "no configured authorized skill matches this request",
                ));
            }
            let context_id = if let Some(context_id) =
                message.context_id.as_deref().filter(|id| !id.is_empty())
            {
                identifier(context_id)?;
                let context = self
                    .app
                    .store
                    .get(&pk, &format!("A2ACONTEXT#{context_id}"))
                    .await
                    .map_err(internal)?
                    .ok_or_else(|| invalid("context not found"))?;
                if context.payload["caller_id"].as_str() != Some(caller.as_str()) {
                    return Err(invalid("context not found"));
                }
                context_id.to_owned()
            } else {
                let id = uuid::Uuid::new_v4().to_string();
                new_context = Some(Row::new(
                    &pk,
                    format!("A2ACONTEXT#{id}"),
                    json!({"caller_id":caller}),
                ));
                id
            };
            let task = Task {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: self.agent_id.clone(),
                request: text.clone(),
                skill_ids,
                status: "queued".into(),
                created_at: now(),
                updated_at: now(),
                result: None,
                error: None,
                lease_until: 0,
                a2a: Some(A2aTaskData {
                    caller_id: caller.clone(),
                    context_id,
                    messages: vec![],
                    turn: 0,
                    engine_history: vec![],
                }),
            };
            let row = Row::new(&pk, format!("TASK#{}", task.id), Value::Null);
            (row, task, None)
        };
        let data = task.a2a.as_mut().expect("A2A data initialized");
        if data.messages.len() + 2 > MAX_MESSAGES
            || data
                .messages
                .iter()
                .map(|message| message.text.len())
                .sum::<usize>()
                + text.len()
                > MAX_CONVERSATION_BYTES
        {
            return Err(invalid("conversation limit reached; start a new task"));
        }
        data.messages.push(ConversationMessage {
            id: message.message_id.clone(),
            role: "user".into(),
            text: text.clone(),
        });
        task.request = text;
        task.status = "queued".into();
        task.error = None;
        task.lease_until = 0;
        task.updated_at = now();
        row.payload = serde_json::to_value(&task).map_err(internal)?;
        // DynamoDB item maximum is 400 KiB. Leave room for row/envelope metadata.
        if serde_json::to_vec(&row.payload).map_err(internal)?.len() > 350 * 1024 {
            return Err(invalid(
                "conversation checkpoint is too large; start a new task",
            ));
        }
        row.due = Some(("TASK".into(), now()));
        let receipt = Row::new(
            &pk,
            &receipt_key,
            json!({"fingerprint":fingerprint,"task_id":task.id}),
        );
        let mut writes = vec![(row, expected), (receipt, None)];
        if let Some(context) = new_context {
            writes.push((context, None));
        }
        if !self.app.store.transaction(writes).await.map_err(internal)? {
            if let Some(previous) = self.receipt(&receipt_key, &fingerprint).await? {
                return Ok(protocol::SendMessageResponse::Task(public_task(
                    &previous, history, true,
                )));
            }
            return Err(invalid(
                "task changed concurrently; retrieve its current state before resending",
            ));
        }
        self.enqueue(&task).await;
        Ok(protocol::SendMessageResponse::Task(public_task(
            &task, history, true,
        )))
    }

    async fn get_task(
        &self,
        params: &ServiceParams,
        req: protocol::GetTaskRequest,
    ) -> Result<protocol::Task, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        let history = history_length(req.history_length)?;
        let (_, task) = self.task(&req.id).await?;
        Ok(public_task(&task, history, true))
    }

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        req: protocol::CancelTaskRequest,
    ) -> Result<protocol::Task, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        let (mut row, mut task) = self.task(&req.id).await?;
        if task.status == "cancelled" {
            return Ok(public_task(&task, None, true));
        }
        if task.status != "queued" {
            return Err(protocol::A2AError::task_not_cancelable(&req.id));
        }
        let version = row.version;
        task.status = "cancelled".into();
        task.updated_at = now();
        task.lease_until = 0;
        row.payload = serde_json::to_value(&task).map_err(internal)?;
        row.due = None;
        if !self
            .app
            .store
            .put(row, Some(version))
            .await
            .map_err(internal)?
        {
            return Err(protocol::A2AError::task_not_cancelable(&req.id));
        }
        Ok(public_task(&task, None, true))
    }

    async fn list_tasks(
        &self,
        params: &ServiceParams,
        req: protocol::ListTasksRequest,
    ) -> Result<protocol::ListTasksResponse, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        let history = history_length(req.history_length)?;
        if req.page_size.is_some_and(|size| !(0..=100).contains(&size)) {
            return Err(invalid(
                "pageSize must be between 1 and 100, or 0 for the default",
            ));
        }
        let page_size = a2a_server::pagination::resolve_page_size(req.page_size);
        if let Some(context) = &req.context_id {
            identifier(context)?;
        }
        let scope = digest(
            &serde_json::to_string(&json!({
                "agent": self.agent_id, "caller": self.principal.caller_id(),
                "context": req.context_id, "status": req.status,
                "after": req.status_timestamp_after,
            }))
            .map_err(internal)?,
        );
        let after = if let Some(token) = req.page_token.as_deref().filter(|token| !token.is_empty())
        {
            if token.len() > 2048 {
                return Err(invalid("invalid pageToken"));
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| invalid("invalid pageToken"))?;
            let cursor: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| invalid("invalid pageToken"))?;
            if cursor.scope != scope {
                return Err(invalid("pageToken does not match this caller and query"));
            }
            Some(cursor.after)
        } else {
            None
        };
        // A2A requires an exact total before pagination. Bound work explicitly
        // instead of reporting a made-up total or scanning an unbounded tenant.
        let limit_error = || {
            protocol::A2AError::unsupported_operation(
                "Task listing limit reached; retrieve known tasks with GetTask.",
            )
        };
        let rows = tokio::time::timeout(Duration::from_secs(8), async {
            let mut rows = Vec::new();
            let mut scanned_bytes = 0;
            let mut cursor = None;
            loop {
                let page = self
                    .app
                    .store
                    .list_page(&agent_pk(&self.agent_id), "TASK#", cursor.as_deref(), 100)
                    .await
                    .map_err(internal)?;
                for row in &page.rows {
                    scanned_bytes += serde_json::to_vec(&row.payload).map_err(internal)?.len();
                }
                if scanned_bytes > 8 * 1024 * 1024 {
                    return Err(limit_error());
                }
                rows.extend(page.rows);
                if rows.len() > 1000 {
                    return Err(limit_error());
                }
                cursor = page.next_key;
                if cursor.is_none() {
                    return Ok(rows);
                }
                if rows.len() >= 1000 {
                    return Err(limit_error());
                }
            }
        })
        .await
        .map_err(|_| limit_error())??;
        let mut tasks = Vec::new();
        for row in rows {
            if row.payload.is_null() {
                continue;
            }
            let task: Task = serde_json::from_value(row.payload).map_err(internal)?;
            if !self.may_read(&task) {
                continue;
            }
            let public = public_task(&task, history, req.include_artifacts.unwrap_or(false));
            if req
                .context_id
                .as_ref()
                .is_some_and(|context| context != &public.context_id)
                || req
                    .status
                    .as_ref()
                    .is_some_and(|status| status != &public.status.state)
                || req.status_timestamp_after.is_some_and(|after| {
                    public
                        .status
                        .timestamp
                        .is_none_or(|timestamp| timestamp < after)
                })
            {
                continue;
            }
            tasks.push(public);
        }
        tasks.sort_by(|left, right| {
            right
                .status
                .timestamp
                .cmp(&left.status.timestamp)
                .then(left.id.cmp(&right.id))
        });
        let total_size = tasks.len() as i32;
        let offset = if let Some(after) = after {
            tasks
                .iter()
                .position(|task| task.id == after)
                .ok_or_else(|| invalid("pageToken task changed; restart listing"))?
                + 1
        } else {
            0
        };
        let mut selected = Vec::new();
        let mut response_bytes = 0;
        for task in tasks.into_iter().skip(offset).take(page_size) {
            let size = serde_json::to_vec(&task).map_err(internal)?.len();
            if !selected.is_empty() && response_bytes + size > 512 * 1024 {
                break;
            }
            response_bytes += size;
            selected.push(task);
        }
        let has_more = total_size as usize > offset + selected.len();
        let tasks = selected;
        let next_page_token = if has_more {
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Cursor {
                    scope,
                    after: tasks.last().expect("nonempty bounded page").id.clone(),
                })
                .map_err(internal)?,
            )
        } else {
            String::new()
        };
        Ok(protocol::ListTasksResponse {
            tasks,
            next_page_token,
            page_size: page_size as i32,
            total_size,
        })
    }

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        req: protocol::SendMessageRequest,
    ) -> Result<
        BoxStream<'static, Result<protocol::StreamResponse, protocol::A2AError>>,
        protocol::A2AError,
    > {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::unsupported_operation(
            "Streaming is not supported; use SendMessage with returnImmediately=true and GetTask",
        ))
    }
    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        req: protocol::SubscribeToTaskRequest,
    ) -> Result<
        BoxStream<'static, Result<protocol::StreamResponse, protocol::A2AError>>,
        protocol::A2AError,
    > {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::unsupported_operation(
            "Streaming is not supported; use GetTask",
        ))
    }
    async fn create_push_config(
        &self,
        params: &ServiceParams,
        req: protocol::TaskPushNotificationConfig,
    ) -> Result<protocol::TaskPushNotificationConfig, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::push_notification_not_supported())
    }
    async fn get_push_config(
        &self,
        params: &ServiceParams,
        req: protocol::GetTaskPushNotificationConfigRequest,
    ) -> Result<protocol::TaskPushNotificationConfig, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::push_notification_not_supported())
    }
    async fn list_push_configs(
        &self,
        params: &ServiceParams,
        req: protocol::ListTaskPushNotificationConfigsRequest,
    ) -> Result<protocol::ListTaskPushNotificationConfigsResponse, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::push_notification_not_supported())
    }
    async fn delete_push_config(
        &self,
        params: &ServiceParams,
        req: protocol::DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::push_notification_not_supported())
    }
    async fn get_extended_agent_card(
        &self,
        params: &ServiceParams,
        req: protocol::GetExtendedAgentCardRequest,
    ) -> Result<protocol::AgentCard, protocol::A2AError> {
        self.check(params, req.tenant.as_deref())?;
        Err(protocol::A2AError::unsupported_operation(
            "Extended agent cards are not supported; use the public agent card",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;

    async fn fixture() -> App {
        let app = App::local().await.unwrap();
        for id in ["one", "two"] {
            app.store.put(Row::new(agent_pk(id), "META", json!({
                "id":id,"name":"Test","description":"","key_hash":digest("owner-test-key"),"created_at":now()
            })), None).await.unwrap();
            for skill in ["read", "write"] {
                app.store.put(Row::new(agent_pk(id), format!("SKILL#{skill}"), json!({
                    "id":skill,"name":skill,"description":"Test","instructions":"Reply briefly.","connector_ids":[]
                })), None).await.unwrap();
            }
        }
        app
    }

    fn invoker(name: &str, skill: &str) -> Principal {
        Principal::Invoker {
            caller_id: name.into(),
            skill_ids: vec![skill.into()],
        }
    }

    fn send(id: &str, text: &str) -> Value {
        json!({"message":{"messageId":id,"role":"ROLE_USER","parts":[{"text":text}]},"configuration":{"returnImmediately":true}})
    }

    async fn rpc(
        app: &App,
        agent: &str,
        principal: Principal,
        method: &str,
        params: Value,
    ) -> Value {
        let router = a2a_server::jsonrpc::jsonrpc_router(Arc::new(Handler {
            app: app.clone(),
            agent_id: agent.into(),
            principal,
        }));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("A2A-Version", "1.0")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":17,"method":method,"params":params})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn callers_are_isolated_across_tasks_contexts_idempotency_and_listing() {
        let app = fixture().await;
        let alice = invoker("alice", "read");
        let bob = invoker("bob", "write");
        let first = rpc(
            &app,
            "one",
            alice.clone(),
            "SendMessage",
            send("same-message", "hello"),
        )
        .await;
        assert!(first.get("error").is_none(), "{first}");
        let a = first["result"]["task"]["id"].as_str().unwrap();
        let context = first["result"]["task"]["contextId"].as_str().unwrap();
        let second = rpc(
            &app,
            "one",
            bob.clone(),
            "SendMessage",
            send("same-message", "hello"),
        )
        .await;
        let b = second["result"]["task"]["id"].as_str().unwrap();
        assert_ne!(a, b);
        for (agent, principal) in [
            ("one", bob.clone()),
            ("two", alice.clone()),
            ("two", Principal::Owner),
        ] {
            for method in ["GetTask", "CancelTask"] {
                let denied = rpc(&app, agent, principal.clone(), method, json!({"id":a})).await;
                assert_eq!(
                    denied["error"]["code"],
                    protocol::error_code::TASK_NOT_FOUND,
                    "{denied}"
                );
            }
        }
        let owner = rpc(&app, "one", Principal::Owner, "GetTask", json!({"id":a})).await;
        assert_eq!(owner["result"]["id"], a);
        let mut cross_context = send("context-attack", "hello");
        cross_context["message"]["contextId"] = json!(context);
        let denied = rpc(&app, "one", bob.clone(), "SendMessage", cross_context).await;
        assert_eq!(
            denied["error"]["code"],
            protocol::error_code::INVALID_PARAMS
        );
        let mut escalate = send("skill-attack", "hello");
        escalate["metadata"] = json!({"skill_ids":["write"]});
        let denied = rpc(&app, "one", alice.clone(), "SendMessage", escalate).await;
        assert_eq!(
            denied["error"]["code"],
            protocol::error_code::INVALID_PARAMS
        );
        for (principal, expected) in [(alice, 1), (bob, 1), (Principal::Owner, 2)] {
            let page = rpc(&app, "one", principal, "ListTasks", json!({})).await;
            assert_eq!(page["result"]["totalSize"], expected, "{page}");
            assert_eq!(
                page["result"]["tasks"].as_array().unwrap().len(),
                expected as usize
            );
        }
        let stored = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{a}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.payload["skill_ids"], json!(["read"]));
    }

    #[tokio::test]
    async fn retries_are_atomic_and_payload_changes_or_terminal_restarts_are_rejected() {
        let app = fixture().await;
        let params = send("retry", "hello");
        let (first, retry) = tokio::join!(
            rpc(&app, "one", Principal::Owner, "SendMessage", params.clone()),
            rpc(&app, "one", Principal::Owner, "SendMessage", params.clone()),
        );
        assert_eq!(first["result"]["task"]["id"], retry["result"]["task"]["id"]);
        let task = first["result"]["task"]["id"].as_str().unwrap();
        assert_eq!(
            app.store
                .list(&agent_pk("one"), "TASK#")
                .await
                .unwrap()
                .len(),
            1
        );
        let changed = rpc(
            &app,
            "one",
            Principal::Owner,
            "SendMessage",
            send("retry", "changed"),
        )
        .await;
        assert_eq!(
            changed["error"]["code"],
            protocol::error_code::INVALID_PARAMS
        );
        let canceled = rpc(
            &app,
            "one",
            Principal::Owner,
            "CancelTask",
            json!({"id":task}),
        )
        .await;
        assert_eq!(canceled["result"]["status"]["state"], "TASK_STATE_CANCELED");
        let duplicate = rpc(&app, "one", Principal::Owner, "SendMessage", params).await;
        assert_eq!(
            duplicate["result"]["task"]["status"]["state"],
            "TASK_STATE_CANCELED"
        );
        let mut restart = send("restart", "restart");
        restart["message"]["taskId"] = json!(task);
        let rejected = rpc(&app, "one", Principal::Owner, "SendMessage", restart).await;
        assert_eq!(
            rejected["error"]["code"],
            protocol::error_code::UNSUPPORTED_OPERATION
        );
        let duplicate_cancel = rpc(
            &app,
            "one",
            Principal::Owner,
            "CancelTask",
            json!({"id":task}),
        )
        .await;
        assert_eq!(
            duplicate_cancel["result"]["status"]["state"],
            "TASK_STATE_CANCELED"
        );
    }

    #[tokio::test]
    async fn input_required_continuation_preserves_checkpoint_and_cost_without_leaking_it() {
        let app = fixture().await;
        let alice = invoker("alice", "read");
        let first = rpc(
            &app,
            "one",
            alice.clone(),
            "SendMessage",
            send("start", "help"),
        )
        .await;
        let id = first["result"]["task"]["id"].as_str().unwrap();
        let mut row = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        let version = row.version;
        row.payload["status"] = json!("input_required");
        row.payload["result"] = json!({"text":"Which time?","usage":{"input_tokens":10,"output_tokens":2},"cost_microusd":20,"model_calls":1,"tool_calls":0,"input_required":"Which time?"});
        row.payload["a2a"]["messages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"question","role":"agent","text":"Which time?"}));
        row.payload["a2a"]["engine_history"] = json!([
            {"role":"assistant","content":[{"type":"text","text":"PRIVATE-TOOL-TRACE"}]}
        ]);
        app.store.put(row, Some(version)).await.unwrap();
        let read = rpc(
            &app,
            "one",
            alice.clone(),
            "GetTask",
            json!({"id":id,"historyLength":1}),
        )
        .await;
        assert_eq!(
            read["result"]["status"]["state"],
            "TASK_STATE_INPUT_REQUIRED"
        );
        assert_eq!(read["result"]["history"].as_array().unwrap().len(), 1);
        assert!(!read.to_string().contains("PRIVATE-TOOL-TRACE"));
        let mut reply = send("answer", "14:30");
        reply["message"]["taskId"] = json!(id);
        reply["message"]["contextId"] = first["result"]["task"]["contextId"].clone();
        let resumed = rpc(&app, "one", alice.clone(), "SendMessage", reply.clone()).await;
        assert_eq!(resumed["result"]["task"]["id"], id, "{resumed}");
        assert_eq!(
            resumed["result"]["task"]["status"]["state"],
            "TASK_STATE_SUBMITTED"
        );
        let duplicate = rpc(&app, "one", alice, "SendMessage", reply).await;
        assert_eq!(duplicate["result"]["task"]["id"], id);
        let stored = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.payload["a2a"]["turn"], 1);
        assert_eq!(
            stored.payload["a2a"]["messages"].as_array().unwrap().len(),
            3
        );
        assert_eq!(stored.payload["result"]["cost_microusd"], 20);
        assert!(
            stored.payload["a2a"]["engine_history"]
                .to_string()
                .contains("PRIVATE-TOOL-TRACE")
        );
        assert_eq!(stored.payload["request"], "14:30");
    }

    #[tokio::test]
    async fn continuation_accepts_reordered_and_duplicate_skill_selection() {
        let app = fixture().await;
        let principal = Principal::Invoker {
            caller_id: "alice".into(),
            skill_ids: vec!["read".into(), "write".into()],
        };
        let mut request = send("start-skills", "help");
        request["metadata"] = json!({"skill_ids":["write","read","write"]});
        let first = rpc(&app, "one", principal.clone(), "SendMessage", request).await;
        let id = first["result"]["task"]["id"].as_str().unwrap();
        let mut row = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.payload["skill_ids"], json!(["read", "write"]));
        let version = row.version;
        row.payload["status"] = json!("input_required");
        app.store.put(row, Some(version)).await.unwrap();
        let mut reply = send("reply-skills", "Proceed with the supplied time");
        reply["message"]["taskId"] = json!(id);
        reply["metadata"] = json!({"skill_ids":["write","write","read","read"]});
        let resumed = rpc(&app, "one", principal, "SendMessage", reply).await;
        assert_eq!(resumed["result"]["task"]["id"], id, "{resumed}");
        assert_eq!(
            resumed["result"]["task"]["status"]["state"],
            "TASK_STATE_SUBMITTED"
        );
        let stored = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.payload["skill_ids"], json!(["read", "write"]));
        assert_eq!(stored.payload["a2a"]["turn"], 1);
    }

    #[tokio::test]
    async fn pagination_filters_and_tokens_preserve_caller_scope_and_exact_total() {
        let app = fixture().await;
        for index in 0..3 {
            rpc(
                &app,
                "one",
                invoker("alice", "read"),
                "SendMessage",
                send(&format!("m{index}"), "hello"),
            )
            .await;
        }
        let first = rpc(
            &app,
            "one",
            invoker("alice", "read"),
            "ListTasks",
            json!({"pageSize":2,"historyLength":0}),
        )
        .await;
        assert_eq!(first["result"]["totalSize"], 3, "{first}");
        assert_eq!(first["result"]["tasks"].as_array().unwrap().len(), 2);
        assert!(first["result"]["tasks"][0].get("history").is_none());
        let token = first["result"]["nextPageToken"].as_str().unwrap();
        let second = rpc(
            &app,
            "one",
            invoker("alice", "read"),
            "ListTasks",
            json!({"pageSize":2,"pageToken":token}),
        )
        .await;
        assert_eq!(second["result"]["totalSize"], 3);
        assert_eq!(second["result"]["tasks"].as_array().unwrap().len(), 1);
        assert_ne!(
            second["result"]["tasks"][0]["id"],
            first["result"]["tasks"][0]["id"]
        );
        let stolen = rpc(
            &app,
            "one",
            invoker("bob", "read"),
            "ListTasks",
            json!({"pageToken":token}),
        )
        .await;
        assert_eq!(
            stolen["error"]["code"],
            protocol::error_code::INVALID_PARAMS
        );
        let changed = rpc(
            &app,
            "one",
            invoker("alice", "read"),
            "ListTasks",
            json!({"pageToken":token,"status":"TASK_STATE_COMPLETED"}),
        )
        .await;
        assert_eq!(
            changed["error"]["code"],
            protocol::error_code::INVALID_PARAMS
        );
    }

    #[tokio::test]
    async fn listing_is_timestamp_inclusive_and_refuses_an_unbounded_total() {
        let app = fixture().await;
        let first = rpc(
            &app,
            "one",
            Principal::Owner,
            "SendMessage",
            send("boundary", "hello"),
        )
        .await;
        let id = first["result"]["task"]["id"].as_str().unwrap();
        let timestamp = first["result"]["task"]["status"]["timestamp"].clone();
        let inclusive = rpc(
            &app,
            "one",
            Principal::Owner,
            "ListTasks",
            json!({"statusTimestampAfter":timestamp}),
        )
        .await;
        assert_eq!(inclusive["result"]["totalSize"], 1);
        let original = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        for index in 0..1000 {
            let mut row = original.clone();
            row.sk = format!("TASK#synthetic-{index:04}");
            row.payload["id"] = json!(format!("synthetic-{index:04}"));
            app.store.put(row, None).await.unwrap();
        }
        let bounded = rpc(
            &app,
            "one",
            Principal::Owner,
            "ListTasks",
            json!({"pageSize":1}),
        )
        .await;
        assert_eq!(
            bounded["error"]["code"],
            protocol::error_code::UNSUPPORTED_OPERATION
        );
        // Known identifiers stay retrievable even when listing cannot compute a bounded exact total.
        let known = rpc(&app, "one", Principal::Owner, "GetTask", json!({"id":id})).await;
        assert_eq!(known["result"]["id"], id);
    }

    #[tokio::test]
    async fn unsupported_sync_push_content_and_running_cancellation_have_no_side_effects() {
        let app = fixture().await;
        for mut request in [
            send("sync", "hello"),
            send("push", "hello"),
            send("image", "hello"),
        ] {
            match request["message"]["messageId"].as_str().unwrap() {
                "sync" => request["configuration"]["returnImmediately"] = json!(false),
                "push" => {
                    request["configuration"]["taskPushNotificationConfig"] =
                        json!({"url":"https://example.com/callback"})
                }
                _ => {
                    request["message"]["parts"] =
                        json!([{"url":"https://example.com/image.png","mediaType":"image/png"}])
                }
            }
            let result = rpc(&app, "one", Principal::Owner, "SendMessage", request).await;
            assert!(result.get("error").is_some(), "{result}");
        }
        assert!(
            app.store
                .list(&agent_pk("one"), "TASK#")
                .await
                .unwrap()
                .is_empty()
        );
        let task = rpc(
            &app,
            "one",
            Principal::Owner,
            "SendMessage",
            send("running", "hello"),
        )
        .await;
        let id = task["result"]["task"]["id"].as_str().unwrap();
        let mut row = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        let version = row.version;
        row.payload["status"] = json!("running");
        app.store.put(row, Some(version)).await.unwrap();
        let cancel = rpc(
            &app,
            "one",
            Principal::Owner,
            "CancelTask",
            json!({"id":id}),
        )
        .await;
        assert_eq!(
            cancel["error"]["code"],
            protocol::error_code::TASK_NOT_CANCELABLE
        );
        let unchanged = app
            .store
            .get(&agent_pk("one"), &format!("TASK#{id}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.payload["status"], "running");
    }
}
