use crate::{connectors::OutboundHttp, crypto::Vault, store::Store};
use std::sync::Arc;

#[derive(Clone)]
pub struct App {
    pub store: Arc<dyn Store>,
    pub vault: Vault,
    pub http: OutboundHttp,
    pub public_url: String,
    pub sqs: Option<aws_sdk_sqs::Client>,
    pub queue_url: String,
    pub aws: Option<aws_config::SdkConfig>,
    pub model_id: String,
    pub count_model_id: String,
    pub monthly_budget: u64,
    pub engine_config: crate::engine::EngineConfig,
}
impl App {
    pub async fn enqueue(&self, agent_id: &str, task_id: &str) -> anyhow::Result<()> {
        if let Some(sqs) = &self.sqs {
            sqs.send_message()
                .queue_url(&self.queue_url)
                .message_body(
                    serde_json::json!({"agent_id":agent_id,"task_id":task_id}).to_string(),
                )
                .send()
                .await?;
        }
        Ok(())
    }
    pub fn oauth_stores(&self, agent: &str, connection: &str) -> crate::oauth_store::OAuthStores {
        crate::oauth_store::OAuthStores::new(
            self.store.clone(),
            self.vault.clone(),
            agent.into(),
            connection.into(),
        )
    }
    pub async fn local() -> anyhow::Result<Self> {
        Ok(Self {
            store: Arc::new(crate::store::MemoryStore::default()),
            vault: Vault::ephemeral()?,
            http: OutboundHttp::new()?,
            public_url: "http://127.0.0.1:3188".into(),
            sqs: None,
            queue_url: String::new(),
            aws: None,
            model_id: String::new(),
            count_model_id: String::new(),
            monthly_budget: 25_000_000,
            engine_config: Default::default(),
        })
    }
}
