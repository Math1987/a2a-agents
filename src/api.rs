use crate::{
    app::App,
    connectors::{BeginOAuthRequest, OAuthConfiguration, OAuthService},
    crypto::{digest, random_secret},
    domain::*,
    store::Row,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use rmcp::transport::auth::{CredentialStore, StateStore};
use serde::Deserialize;
use serde_json::{Value, json};

pub struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "invalid_stored_record")
    }
}
impl From<crate::connectors::ConnectorError> for ApiError {
    fn from(e: crate::connectors::ConnectorError) -> Self {
        if e.requires_authorization() {
            Self(StatusCode::CONFLICT, "connector_authorization_required")
        } else {
            Self(
                StatusCode::BAD_GATEWAY,
                "connector_unavailable_or_unsupported",
            )
        }
    }
}
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}
fn conflict() -> ApiError {
    ApiError(StatusCode::CONFLICT, "concurrent_update_retry")
}
fn missing() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not_found")
}
pub fn router(app: App) -> Router {
    Router::new().route("/health",get(||async{Json(json!({"status":"ok","service":"a2a-agents"}))}))
      .route("/openapi.json",get(||async{([("content-type","application/json")],include_str!("../docs/openapi.json"))}))
      .route("/",get(||async{Json(json!({"service":"Aithos Agents","version":"0.2.0","docs":"https://github.com/Math1987/a2a-agents","phase":2}))}))
      .route("/v1/agents",post(create_agent))
      .route("/v1/agents/{agent}",get(get_agent).patch(update_agent).delete(delete_agent))
      .route("/v1/agents/{agent}/key",post(rotate_key))
      .route("/agents/{agent}/agent-card.json",get(card))
      .route("/agents/{agent}/.well-known/agent-card.json",get(card))
      .route("/v1/agents/{agent}/skills",get(list_skills))
      .route("/v1/agents/{agent}/skills/{skill}",put(save_skill).delete(remove_skill))
      .route("/v1/agents/{agent}/connectors",post(create_connection).get(list_connections))
      .route("/v1/agents/{agent}/connectors/{connection}",delete(disconnect))
      .route("/v1/agents/{agent}/connectors/{connection}/authorize",post(authorize))
      .route("/v1/agents/{agent}/connectors/{connection}/tools",get(list_tools))
      .route("/oauth/callback/{agent}/{connection}",get(callback))
      .route("/v1/agents/{agent}/tasks",post(create_task).get(list_tasks))
      .route("/v1/agents/{agent}/tasks/{task}",get(get_task))
      .with_state(app.clone())
      .merge(crate::a2a::router(app))
      .layer(DefaultBodyLimit::max(64*1024))
      .layer(axum::middleware::map_response(|mut response:Response|async move {response.headers_mut().insert("cache-control","no-store".parse().unwrap());response.headers_mut().insert("referrer-policy","no-referrer".parse().unwrap());response.headers_mut().insert("x-content-type-options","nosniff".parse().unwrap());response}))
}
pub async fn agent(app: &App, id: &str) -> Result<(Row, Agent), ApiError> {
    let row = app
        .store
        .get(&agent_pk(id), "META")
        .await?
        .ok_or_else(missing)?;
    let a: Agent = serde_json::from_value(row.payload.clone())?;
    if a.deleted {
        return Err(missing());
    }
    Ok((row, a))
}
async fn owner(app: &App, id: &str, headers: &HeaderMap) -> Result<(Row, Agent), ApiError> {
    let secret = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_owner_key"))?;
    let (row, a) = agent(app, id).await?;
    if digest(secret) != a.key_hash {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_owner_key"));
    }
    Ok((row, a))
}
fn agent_public(a: &Agent, base: &str) -> Value {
    json!({"id":a.id,"name":a.name,"description":a.description,"created_at":a.created_at,"card_url":format!("{base}/agents/{}/agent-card.json",a.id)})
}
#[derive(Deserialize)]
struct AgentInput {
    name: String,
    #[serde(default)]
    description: String,
}
async fn create_agent(
    State(app): State<App>,
    Json(input): Json<AgentInput>,
) -> Result<impl IntoResponse, ApiError> {
    if input.name.trim().is_empty() || input.name.len() > 200 || input.description.len() > 4000 {
        return Err(invalid());
    }
    let secret = format!("agt_{}", random_secret()?);
    let id = uuid::Uuid::new_v4().to_string();
    let a = Agent {
        id: id.clone(),
        name: input.name,
        description: input.description,
        key_hash: digest(&secret),
        created_at: now(),
        deleted: false,
    };
    if !app
        .store
        .put(
            Row::new(agent_pk(&id), "META", serde_json::to_value(&a)?),
            None,
        )
        .await?
    {
        return Err(conflict());
    }
    let mut response = agent_public(&a, &app.public_url);
    response["owner_key"] = json!(secret);
    Ok((StatusCode::CREATED, Json(response)))
}
async fn get_agent(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, a) = owner(&app, &id, &h).await?;
    Ok(Json(agent_public(&a, &app.public_url)))
}
async fn update_agent(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(input): Json<AgentInput>,
) -> Result<Json<Value>, ApiError> {
    let (mut row, mut a) = owner(&app, &id, &h).await?;
    if input.name.trim().is_empty() || input.name.len() > 200 || input.description.len() > 4000 {
        return Err(invalid());
    }
    a.name = input.name;
    a.description = input.description;
    let v = row.version;
    row.payload = serde_json::to_value(&a)?;
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    Ok(Json(agent_public(&a, &app.public_url)))
}
async fn rotate_key(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (mut row, mut a) = owner(&app, &id, &h).await?;
    let key = format!("agt_{}", random_secret()?);
    a.key_hash = digest(&key);
    let v = row.version;
    row.payload = serde_json::to_value(a)?;
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    Ok(Json(json!({"owner_key":key})))
}
async fn delete_agent(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (mut row, mut a) = owner(&app, &id, &h).await?;
    a.deleted = true;
    a.key_hash.clear();
    let v = row.version;
    row.payload = serde_json::to_value(a)?;
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    for mut r in app.store.list(&agent_pk(&id), "").await? {
        if r.sk != "META" {
            let v = r.version;
            r.payload = json!(null);
            r.due = None;
            r.expires_at = Some(now() + 86400);
            let _ = app.store.put(r, Some(v)).await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn skills(app: &App, id: &str) -> Result<Vec<Skill>, ApiError> {
    Ok(app
        .store
        .list(&agent_pk(id), "SKILL#")
        .await?
        .into_iter()
        .filter(|r| !r.payload.is_null())
        .map(|r| serde_json::from_value(r.payload))
        .collect::<Result<_, _>>()?)
}
async fn list_skills(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    owner(&app, &id, &h).await?;
    Ok(Json(json!({"skills":skills(&app,&id).await?})))
}
async fn save_skill(
    State(app): State<App>,
    Path((id, skill)): Path<(String, String)>,
    h: HeaderMap,
    Json(mut input): Json<Skill>,
) -> Result<Json<Skill>, ApiError> {
    owner(&app, &id, &h).await?;
    if skill.len() > 100
        || input.name.trim().is_empty()
        || input.instructions.is_empty()
        || input.instructions.len() > 32000
        || input.description.len() > 4000
        || input.name.len() > 200
    {
        return Err(invalid());
    }
    input.id = skill.clone();
    for c in &input.connector_ids {
        connection(&app, &id, c).await?;
    }
    let key = format!("SKILL#{skill}");
    let old = app.store.get(&agent_pk(&id), &key).await?;
    if !app
        .store
        .put(
            Row::new(agent_pk(&id), key, serde_json::to_value(&input)?),
            old.map(|r| r.version),
        )
        .await?
    {
        return Err(conflict());
    }
    Ok(Json(input))
}
async fn remove_skill(
    State(app): State<App>,
    Path((id, skill)): Path<(String, String)>,
    h: HeaderMap,
) -> Result<StatusCode, ApiError> {
    owner(&app, &id, &h).await?;
    let mut row = app
        .store
        .get(&agent_pk(&id), &format!("SKILL#{skill}"))
        .await?
        .ok_or_else(missing)?;
    let v = row.version;
    row.payload = Value::Null;
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn card(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let card = agent_card(&app, &id).await?;
    let mut value = a2a_pb::protojson_conv::to_value(&card)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "invalid_agent_card"))?;
    // Keep the existing public card contract explicit even when ProtoJSON
    // would omit an empty scalar or repeated field. Both forms are valid.
    value["description"] = json!(card.description);
    if card.skills.is_empty() {
        value["skills"] = json!([]);
    }
    // ProtoJSON's omitted empty StringList is equivalent to {"list":[]}.
    // Emit the latter explicitly: a2a-lf 0.3.1's card resolver accepts the
    // canonical wrapper but requires this default field to be present.
    if let Some(requirements) = value
        .get_mut("securityRequirements")
        .and_then(Value::as_array_mut)
    {
        for requirement in requirements {
            if let Some(schemes) = requirement
                .get_mut("schemes")
                .and_then(Value::as_object_mut)
            {
                for scopes in schemes.values_mut() {
                    if let Some(scopes) = scopes.as_object_mut() {
                        scopes.entry("list").or_insert_with(|| json!([]));
                    }
                }
            }
        }
    }
    Ok(Json(value))
}
pub(crate) async fn agent_card(app: &App, id: &str) -> Result<a2a_protocol::AgentCard, ApiError> {
    use a2a_protocol::{
        AgentCapabilities, AgentCard, AgentInterface, AgentSkill, HttpAuthSecurityScheme,
        SecurityScheme,
    };
    let (_, a) = agent(app, id).await?;
    let sk = skills(app, id).await?;
    let mut schemes = std::collections::HashMap::from([(
        "owner".into(),
        SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
            scheme: "Bearer".into(),
            description: Some("Owner key for this agent.".into()),
            bearer_format: None,
        }),
    )]);
    let mut requirements = vec![std::collections::HashMap::from([("owner".into(), vec![])])];
    if app.a2a_auth.is_some() {
        schemes.insert("aithos".into(), SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
            scheme: "Bearer".into(), description: Some("Aithos access token scoped to this agent and its permitted skills; invocation only.".into()), bearer_format: Some("JWT".into()),
        }));
        requirements.push(std::collections::HashMap::from([("aithos".into(), vec![])]));
    }
    Ok(AgentCard {
        name: a.name,
        description: a.description,
        version: "0.2.0".into(),
        supported_interfaces: vec![AgentInterface::new(
            format!("{}/agents/{id}/a2a", app.public_url),
            "JSONRPC",
        )],
        capabilities: AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extended_agent_card: Some(false),
            ..Default::default()
        },
        default_input_modes: vec!["text/plain".into()],
        default_output_modes: vec!["text/plain".into()],
        skills: sk
            .into_iter()
            .map(|s| AgentSkill {
                id: s.id,
                name: s.name,
                description: s.description,
                tags: vec!["configured-skill".into()],
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            })
            .collect(),
        provider: None,
        documentation_url: Some(
            "https://github.com/Math1987/a2a-agents/blob/main/docs/a2a.md".into(),
        ),
        icon_url: None,
        security_schemes: Some(schemes),
        security_requirements: Some(requirements),
        signatures: None,
    })
}
pub async fn connection(app: &App, agent: &str, id: &str) -> Result<(Row, Connection), ApiError> {
    let row = app
        .store
        .get(&agent_pk(agent), &format!("CONN#{id}"))
        .await?
        .ok_or_else(missing)?;
    if row.payload.is_null() {
        return Err(missing());
    }
    let c: Connection = serde_json::from_value(row.payload.clone())?;
    if c.status == "disconnected" {
        return Err(missing());
    }
    Ok((row, c))
}
fn connection_public(c: &Connection) -> Value {
    json!({"id":c.id,"name":c.name,"url":c.url,"auth_type":c.auth_type,"status":c.status,"allowed_tools":c.allowed_tools,"next_maintenance":c.next_maintenance})
}
#[derive(Deserialize)]
struct ConnectionInput {
    name: String,
    url: String,
    #[serde(default = "oauth")]
    auth_type: String,
    token: Option<String>,
    #[serde(default = "all_tools")]
    allowed_tools: Vec<String>,
}
fn oauth() -> String {
    "oauth".into()
}
fn all_tools() -> Vec<String> {
    vec!["*".into()]
}
async fn create_connection(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(input): Json<ConnectionInput>,
) -> Result<impl IntoResponse, ApiError> {
    owner(&app, &id, &h).await?;
    app.http.validate_url(&input.url)?;
    if !["oauth", "bearer", "none"].contains(&input.auth_type.as_str())
        || input.name.is_empty()
        || input.name.len() > 200
        || input.url.len() > 2048
        || input.allowed_tools.len() > 100
    {
        return Err(invalid());
    }
    if input.auth_type == "bearer" && input.token.as_ref().is_none_or(|v| v.is_empty()) {
        return Err(invalid());
    }
    if input.auth_type != "bearer" && input.token.is_some() {
        return Err(invalid());
    }
    let cid = uuid::Uuid::new_v4().to_string();
    let secret = if let Some(token) = input.token {
        Some(app.vault.seal(&format!("{id}/{cid}"), &token).await?)
    } else {
        None
    };
    let c = Connection {
        id: cid.clone(),
        agent_id: id.clone(),
        name: input.name,
        url: input.url,
        auth_type: input.auth_type.clone(),
        status: if input.auth_type == "oauth" {
            "authorization_required"
        } else {
            "connected"
        }
        .into(),
        allowed_tools: input.allowed_tools,
        created_at: now(),
        next_maintenance: 0,
        secret,
        oauth_config: None,
    };
    app.store
        .put(
            Row::new(
                agent_pk(&id),
                format!("CONN#{cid}"),
                serde_json::to_value(&c)?,
            ),
            None,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(connection_public(&c))))
}
async fn list_connections(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    owner(&app, &id, &h).await?;
    let connections = app
        .store
        .list(&agent_pk(&id), "CONN#")
        .await?
        .into_iter()
        .filter_map(|r| serde_json::from_value::<Connection>(r.payload).ok())
        .filter(|c| c.status != "disconnected")
        .map(|c| connection_public(&c))
        .collect::<Vec<_>>();
    Ok(Json(json!({"connectors":connections})))
}
#[derive(Default, Deserialize)]
struct OAuthInput {
    #[serde(default)]
    scopes: Vec<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}
async fn authorize(
    State(app): State<App>,
    Path((id, cid)): Path<(String, String)>,
    h: HeaderMap,
    Json(input): Json<OAuthInput>,
) -> Result<Json<Value>, ApiError> {
    owner(&app, &id, &h).await?;
    let (mut row, mut c) = connection(&app, &id, &cid).await?;
    if c.auth_type != "oauth" {
        return Err(invalid());
    }
    let existing: Option<OAuthConfiguration> = if let Some(ref sealed) = c.oauth_config {
        Some(app.vault.open(&format!("{id}/{cid}"), sealed).await?)
    } else {
        None
    };
    let request = BeginOAuthRequest {
        mcp_url: c.url.clone(),
        redirect_uri: format!("{}/oauth/callback/{id}/{cid}", app.public_url),
        scopes: if input.scopes.is_empty() {
            existing
                .as_ref()
                .map(|e| e.scopes.clone())
                .unwrap_or_default()
        } else {
            input.scopes
        },
        client_id: input
            .client_id
            .or_else(|| existing.as_ref().map(|e| e.client_id.clone())),
        client_secret: input
            .client_secret
            .or_else(|| existing.as_ref().and_then(|e| e.client_secret.clone())),
        client_metadata_url: None,
    };
    let stores = app.oauth_stores(&id, &cid);
    let start = OAuthService::new(app.http.clone())
        .begin(request, stores.clone(), stores)
        .await?;
    c.oauth_config = Some(
        app.vault
            .seal(&format!("{id}/{cid}"), &start.configuration)
            .await?,
    );
    c.status = "authorization_pending".into();
    let v = row.version;
    row.payload = serde_json::to_value(&c)?;
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    Ok(Json(
        json!({"connector_id":cid,"status":c.status,"authorization_url":start.authorization_url,"expires_in":600}),
    ))
}
#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}
async fn callback(
    State(app): State<App>,
    Path((id, cid)): Path<(String, String)>,
    Query(query): Query<Callback>,
) -> Result<Json<Value>, ApiError> {
    agent(&app, &id).await?;
    let (mut row, mut c) = connection(&app, &id, &cid).await?;
    if c.status != "authorization_pending" {
        return Err(invalid());
    }
    let state = query.state.as_deref().ok_or_else(invalid)?;
    let stores = app.oauth_stores(&id, &cid);
    if StateStore::load(&stores, state)
        .await
        .map_err(|_| invalid())?
        .is_none()
    {
        return Err(invalid());
    }
    if query.error.is_some() {
        StateStore::delete(&stores, state)
            .await
            .map_err(|_| invalid())?;
        return Err(ApiError(StatusCode::BAD_REQUEST, "authorization_declined"));
    }
    let cfg: OAuthConfiguration = app
        .vault
        .open(
            &format!("{id}/{cid}"),
            c.oauth_config.as_deref().ok_or_else(invalid)?,
        )
        .await?;
    let _guard = CredentialStore::acquire_refresh_guard(&stores)
        .await
        .map_err(|_| conflict())?;
    OAuthService::new(app.http.clone())
        .finish(
            &cfg,
            query.code.as_deref().ok_or_else(invalid)?,
            state,
            query.iss.as_deref(),
            stores.clone(),
            stores.clone(),
        )
        .await?;
    c.status = "connected".into();
    c.next_maintenance = now() + 7 * 86400;
    let v = row.version;
    row.payload = serde_json::to_value(&c)?;
    row.due = Some(("CONNECTION".into(), c.next_maintenance));
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    Ok(Json(
        json!({"status":"connected","connector_id":cid,"message":"You may close this window. The agent can now use this connection."}),
    ))
}
async fn disconnect(
    State(app): State<App>,
    Path((id, cid)): Path<(String, String)>,
    h: HeaderMap,
) -> Result<StatusCode, ApiError> {
    owner(&app, &id, &h).await?;
    let (_, initial) = connection(&app, &id, &cid).await?;
    let stores = app.oauth_stores(&id, &cid);
    // Serialize with in-flight refreshes before changing the connection. A save
    // that passed its active check must finish before we clear its credentials.
    let _guard = if initial.auth_type == "oauth" {
        CredentialStore::acquire_refresh_guard(&stores)
            .await
            .map_err(|_| conflict())?
    } else {
        None
    };
    // A refresh/callback may have updated the row while we waited for its lease.
    let (mut row, mut c) = connection(&app, &id, &cid).await?;
    c.status = "disconnected".into();
    c.secret = None;
    c.oauth_config = None;
    let v = row.version;
    row.payload = serde_json::to_value(c)?;
    row.due = None;
    if !app.store.put(row, Some(v)).await? {
        return Err(conflict());
    }
    CredentialStore::clear(&stores)
        .await
        .map_err(|_| conflict())?;
    Ok(StatusCode::NO_CONTENT)
}
async fn list_tools(
    State(app): State<App>,
    Path((id, cid)): Path<(String, String)>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    owner(&app, &id, &h).await?;
    let (_, c) = connection(&app, &id, &cid).await?;
    let session = crate::worker::connect(&app, &c).await?;
    let tools = session.tools().await?;
    let _ = session.close().await;
    Ok(Json(
        json!({"tools":tools.into_iter().filter(|t|c.allowed_tools.iter().any(|a|a=="*"||a==t.name.as_ref())).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
struct TaskInput {
    request: String,
    #[serde(default)]
    skill_ids: Vec<String>,
}

async fn previous_idempotent_task(
    app: &App,
    agent: &str,
    task: &str,
    fingerprint: &str,
) -> Result<Option<Task>, ApiError> {
    let pk = agent_pk(agent);
    let Some(receipt) = app.store.get(&pk, &format!("IDEMPOTENCY#{task}")).await? else {
        return Ok(None);
    };
    if receipt.payload["fingerprint"].as_str() != Some(fingerprint) {
        return Err(ApiError(StatusCode::CONFLICT, "idempotency_key_reused"));
    }
    let row = app
        .store
        .get(&pk, &format!("TASK#{task}"))
        .await?
        .ok_or_else(conflict)?;
    Ok(Some(serde_json::from_value(row.payload)?))
}

async fn create_task(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(mut input): Json<TaskInput>,
) -> Result<impl IntoResponse, ApiError> {
    owner(&app, &id, &h).await?;
    if input.request.trim().is_empty() || input.request.len() > 32000 {
        return Err(invalid());
    }
    let (tid, fingerprint) = if let Some(key) = h.get("idempotency-key") {
        let key = key.to_str().map_err(|_| invalid())?;
        if key.len() > 200 || key.is_empty() {
            return Err(invalid());
        }
        let tid = digest(&format!("{id}:{key}"));
        // Bind idempotency to what the caller submitted, before resolving the
        // mutable skill configuration. Omitted skill_ids and [] are equivalent.
        let fingerprint = digest(&serde_json::to_string(&json!({
            "request":input.request,"skill_ids":input.skill_ids
        }))?);
        if let Some(old) = previous_idempotent_task(&app, &id, &tid, &fingerprint).await? {
            return Ok((StatusCode::ACCEPTED, Json(json!(old))));
        }
        (tid, Some(fingerprint))
    } else {
        (uuid::Uuid::new_v4().to_string(), None)
    };
    let available = skills(&app, &id).await?;
    if input.skill_ids.is_empty() {
        input.skill_ids = available.iter().map(|s| s.id.clone()).collect();
    }
    if input.skill_ids.is_empty()
        || input
            .skill_ids
            .iter()
            .any(|s| !available.iter().any(|a| &a.id == s))
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "configure_a_skill_first"));
    }
    let task = Task {
        id: tid.clone(),
        agent_id: id.clone(),
        request: input.request,
        skill_ids: input.skill_ids,
        status: "queued".into(),
        created_at: now(),
        updated_at: now(),
        result: None,
        error: None,
        lease_until: 0,
        a2a: None,
    };
    let mut row = Row::new(
        agent_pk(&id),
        format!("TASK#{tid}"),
        serde_json::to_value(&task)?,
    );
    row.due = Some(("TASK".into(), now()));
    let created = if let Some(fingerprint) = &fingerprint {
        let receipt = Row::new(
            agent_pk(&id),
            format!("IDEMPOTENCY#{tid}"),
            json!({"fingerprint":fingerprint}),
        );
        app.store
            .transaction(vec![(row, None), (receipt, None)])
            .await?
    } else {
        app.store.put(row, None).await?
    };
    if !created {
        if let Some(fingerprint) = &fingerprint
            && let Some(old) = previous_idempotent_task(&app, &id, &tid, fingerprint).await?
        {
            return Ok((StatusCode::ACCEPTED, Json(json!(old))));
        }
        return Err(conflict());
    }
    if app.enqueue(&id, &tid).await.is_err() {
        tracing::warn!(event = "task_enqueue_deferred");
    }
    if app.sqs.is_none() && app.aws.is_some() {
        let a = app.clone();
        let t = tid.clone();
        tokio::spawn(async move {
            let _ = crate::worker::run_task(a, &id, &t).await;
        });
    }
    Ok((StatusCode::ACCEPTED, Json(json!(task))))
}
async fn list_tasks(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    owner(&app, &id, &h).await?;
    let tasks = app
        .store
        .list(&agent_pk(&id), "TASK#")
        .await?
        .into_iter()
        .filter(|r| !r.payload.is_null())
        .map(|r| r.payload)
        .collect::<Vec<_>>();
    Ok(Json(json!({"tasks":tasks})))
}
async fn get_task(
    State(app): State<App>,
    Path((id, tid)): Path<(String, String)>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    owner(&app, &id, &h).await?;
    let row = app
        .store
        .get(&agent_pk(&id), &format!("TASK#{tid}"))
        .await?
        .ok_or_else(missing)?;
    Ok(Json(row.payload))
}
