use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub description: String,
    pub key_hash: String,
    pub created_at: i64,
    #[serde(default)]
    pub deleted: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Skill {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub description: String,
    pub instructions: String,
    #[serde(default)]
    pub connector_ids: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub agent_id: String,
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub status: String,
    pub allowed_tools: Vec<String>,
    pub created_at: i64,
    pub next_maintenance: i64,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub oauth_config: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub agent_id: String,
    pub request: String,
    pub skill_ids: Vec<String>,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub result: Option<crate::engine::EngineOutput>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub lease_until: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a: Option<A2aTaskData>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct A2aTaskData {
    pub caller_id: String,
    pub context_id: String,
    pub messages: Vec<ConversationMessage>,
    pub turn: u64,
    /// Private execution checkpoint, never part of an A2A history response.
    pub engine_history: Vec<crate::engine::Message>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub id: String,
    pub role: String,
    pub text: String,
}
pub fn agent_pk(id: &str) -> String {
    format!("AGENT#{id}")
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
