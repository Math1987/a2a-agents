use a2a_agents::{app::App, crypto::Vault, store::DynamoStore};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // OAuth SDK debug logs may contain credentials. Keep this filter fixed.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("off,a2a_agents=info")
        .init();
    let mode = std::env::var("APP_MODE").unwrap_or_else(|_| "local".into());
    let mut app = if mode == "local" {
        let mut app = App::local().await?;
        if std::env::var("APP_LOCAL_BEDROCK").is_ok() {
            app.aws = Some(aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await);
            app.model_id = std::env::var("APP_MODEL_ID")
                .unwrap_or_else(|_| "eu.anthropic.claude-haiku-4-5-20251001-v1:0".into());
            app.count_model_id = "anthropic.claude-haiku-4-5-20251001-v1:0".into();
        }
        app
    } else {
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let engine_config = a2a_agents::engine::EngineConfig {
            input_microusd_per_million: env_number(
                "APP_INPUT_PRICE_PER_MILLION_MICRO_USD",
                1_100_000,
            )?,
            output_microusd_per_million: env_number(
                "APP_OUTPUT_PRICE_PER_MILLION_MICRO_USD",
                5_500_000,
            )?,
            ..Default::default()
        };
        App {
            store: Arc::new(DynamoStore::new(
                aws_sdk_dynamodb::Client::new(&cfg),
                std::env::var("APP_TABLE")?,
            )),
            vault: Vault::Kms {
                client: aws_sdk_kms::Client::new(&cfg),
                key_id: std::env::var("APP_KMS_KEY_ID")?,
            },
            http: a2a_agents::connectors::OutboundHttp::new()?,
            public_url: std::env::var("APP_PUBLIC_URL")?
                .trim_end_matches('/')
                .into(),
            sqs: Some(aws_sdk_sqs::Client::new(&cfg)),
            queue_url: std::env::var("APP_QUEUE_URL")?,
            aws: Some(cfg.clone()),
            model_id: std::env::var("APP_MODEL_ID")?,
            count_model_id: std::env::var("APP_COUNT_MODEL_ID")?,
            monthly_budget: env_number("APP_MONTHLY_BUDGET_MICRO_USD", 25_000_000)?,
            engine_config,
            a2a_auth: None,
            card_signing: if mode == "worker" {
                None
            } else {
                Some(Arc::new(
                    a2a_agents::cards::CardSigning::kms(
                        aws_sdk_kms::Client::new(&cfg),
                        std::env::var("APP_CARD_SIGNING_KEY_ID")?,
                        serde_json::from_str(
                            &std::env::var("APP_CARD_RETAINED_KEY_IDS")
                                .unwrap_or_else(|_| "[]".into()),
                        )?,
                    )
                    .await?,
                ))
            },
        }
    };
    app.a2a_auth = a2a_agents::a2a_auth::A2aAuthConfig::from_env(app.http.clone())?;
    match mode.as_str() {
        "publish-cards" => {
            let cfg = app.aws.as_ref().expect("AWS configuration");
            let client = aws_sdk_dynamodb::Client::new(cfg);
            let mut cursor = None;
            let mut count = 0;
            loop {
                let page = client
                    .scan()
                    .table_name(std::env::var("APP_TABLE")?)
                    .filter_expression("sk = :meta")
                    .expression_attribute_values(
                        ":meta",
                        aws_sdk_dynamodb::types::AttributeValue::S("META".into()),
                    )
                    .projection_expression("pk")
                    .set_exclusive_start_key(cursor)
                    .send()
                    .await?;
                for item in page.items() {
                    let pk = item
                        .get("pk")
                        .and_then(|v| v.as_s().ok())
                        .ok_or_else(|| anyhow::anyhow!("invalid agent key"))?;
                    let id = pk
                        .strip_prefix("AGENT#")
                        .ok_or_else(|| anyhow::anyhow!("invalid agent partition"))?;
                    if a2a_agents::api::republish_existing_card(&app, id)
                        .await
                        .map_err(|_| {
                            anyhow::anyhow!("card publication failed for {id}; safe to rerun")
                        })?
                    {
                        count += 1;
                    }
                }
                cursor = page.last_evaluated_key;
                if cursor.is_none() {
                    break;
                }
            }
            println!("Published {count} signed cards.");
        }
        "worker" => {
            lambda_runtime::run(lambda_runtime::service_fn(
                move |event: lambda_runtime::LambdaEvent<serde_json::Value>| {
                    let app = app.clone();
                    async move {
                        a2a_agents::worker::handle_event(app, event.payload)
                            .await
                            .map_err(|_| lambda_runtime::Error::from("worker operation failed"))
                    }
                },
            ))
            .await
            .map_err(|_| anyhow::anyhow!("worker runtime failed"))?;
        }
        "api" => {
            lambda_http::run(a2a_agents::api::router(app))
                .await
                .map_err(|_| anyhow::anyhow!("API runtime failed"))?;
        }
        "local" => {
            let address = std::env::var("APP_LISTEN").unwrap_or_else(|_| "127.0.0.1:3188".into());
            let listener = tokio::net::TcpListener::bind(address).await?;
            axum::serve(listener, a2a_agents::api::router(app)).await?;
        }
        _ => anyhow::bail!("unknown APP_MODE"),
    }
    Ok(())
}
fn env_number(key: &str, default: u64) -> anyhow::Result<u64> {
    Ok(std::env::var(key)
        .ok()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(default))
}
