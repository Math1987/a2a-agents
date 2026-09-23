use async_trait::async_trait;
use aws_sdk_dynamodb::{Client, types::AttributeValue as Av};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub pk: String,
    pub sk: String,
    pub version: u64,
    pub payload: Value,
    pub expires_at: Option<i64>,
    pub due: Option<(String, i64)>,
}
pub struct Page {
    pub rows: Vec<Row>,
    pub next_key: Option<String>,
}
impl Row {
    pub fn new(pk: impl Into<String>, sk: impl Into<String>, payload: Value) -> Self {
        Self {
            pk: pk.into(),
            sk: sk.into(),
            payload,
            version: 0,
            expires_at: None,
            due: None,
        }
    }
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn get(&self, pk: &str, sk: &str) -> anyhow::Result<Option<Row>>;
    /// None means insert only. A version means compare-and-swap. Returns false on conflict.
    async fn put(&self, row: Row, expected: Option<u64>) -> anyhow::Result<bool>;
    async fn transaction(&self, rows: Vec<(Row, Option<u64>)>) -> anyhow::Result<bool>;
    async fn list(&self, pk: &str, prefix: &str) -> anyhow::Result<Vec<Row>>;
    /// A bounded, ordered partition query. The cursor is a sort key in this partition.
    async fn list_page(
        &self,
        pk: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Page>;
    async fn due(&self, kind: &str, before: i64) -> anyhow::Result<Vec<Row>>;
}

#[derive(Default, Clone)]
pub struct MemoryStore(Arc<Mutex<BTreeMap<(String, String), Row>>>);
#[async_trait]
impl Store for MemoryStore {
    async fn get(&self, pk: &str, sk: &str) -> anyhow::Result<Option<Row>> {
        Ok(self.0.lock().await.get(&(pk.into(), sk.into())).cloned())
    }
    async fn put(&self, mut row: Row, expected: Option<u64>) -> anyhow::Result<bool> {
        let mut data = self.0.lock().await;
        let key = (row.pk.clone(), row.sk.clone());
        if data.get(&key).map(|r| r.version) != expected {
            return Ok(false);
        }
        row.version = expected.unwrap_or(0) + 1;
        data.insert(key, row);
        Ok(true)
    }
    async fn transaction(&self, rows: Vec<(Row, Option<u64>)>) -> anyhow::Result<bool> {
        let mut data = self.0.lock().await;
        for (row, expected) in &rows {
            if data
                .get(&(row.pk.clone(), row.sk.clone()))
                .map(|r| r.version)
                != *expected
            {
                return Ok(false);
            }
        }
        for (mut row, expected) in rows {
            row.version = expected.unwrap_or(0) + 1;
            data.insert((row.pk.clone(), row.sk.clone()), row);
        }
        Ok(true)
    }
    async fn list(&self, pk: &str, prefix: &str) -> anyhow::Result<Vec<Row>> {
        Ok(self
            .0
            .lock()
            .await
            .values()
            .filter(|r| r.pk == pk && r.sk.starts_with(prefix))
            .cloned()
            .collect())
    }
    async fn list_page(
        &self,
        pk: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Page> {
        anyhow::ensure!((1..=100).contains(&limit), "invalid page size");
        anyhow::ensure!(
            after.is_none_or(|key| key.starts_with(prefix)),
            "invalid page cursor"
        );
        let mut rows: Vec<_> = self
            .0
            .lock()
            .await
            .values()
            .filter(|row| {
                row.pk == pk
                    && row.sk.starts_with(prefix)
                    && after.is_none_or(|key| row.sk.as_str() > key)
            })
            .take(limit + 1)
            .cloned()
            .collect();
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_key = if more {
            rows.last().map(|r| r.sk.clone())
        } else {
            None
        };
        Ok(Page { rows, next_key })
    }
    async fn due(&self, kind: &str, before: i64) -> anyhow::Result<Vec<Row>> {
        let mut rows: Vec<_> = self
            .0
            .lock()
            .await
            .values()
            .filter(|r| {
                r.due
                    .as_ref()
                    .is_some_and(|(k, t)| k == kind && *t <= before)
            })
            .cloned()
            .collect();
        rows.sort_by_key(|row| row.due.as_ref().map(|(_, time)| *time));
        rows.truncate(100);
        Ok(rows)
    }
}

pub struct DynamoStore {
    client: Client,
    table: String,
}
impl DynamoStore {
    pub fn new(client: Client, table: String) -> Self {
        Self { client, table }
    }
    fn decode(mut item: std::collections::HashMap<String, Av>) -> anyhow::Result<Row> {
        fn string(
            m: &mut std::collections::HashMap<String, Av>,
            k: &str,
        ) -> anyhow::Result<String> {
            m.remove(k)
                .and_then(|v| v.as_s().ok().cloned())
                .ok_or_else(|| anyhow::anyhow!("invalid database record"))
        }
        let pk = string(&mut item, "pk")?;
        let sk = string(&mut item, "sk")?;
        let version = item
            .remove("version")
            .and_then(|v| v.as_n().ok().and_then(|s| s.parse().ok()))
            .ok_or_else(|| anyhow::anyhow!("invalid version"))?;
        let payload = serde_json::from_str(&string(&mut item, "payload")?)?;
        let expires_at = item
            .remove("expires_at")
            .and_then(|v| v.as_n().ok().and_then(|s| s.parse().ok()));
        let due = match (
            item.remove("maintenance_pk"),
            item.remove("maintenance_due"),
        ) {
            (Some(k), Some(t)) => Some((
                k.as_s()
                    .map_err(|_| anyhow::anyhow!("invalid index"))?
                    .clone(),
                t.as_n()
                    .map_err(|_| anyhow::anyhow!("invalid index"))?
                    .parse()?,
            )),
            _ => None,
        };
        Ok(Row {
            pk,
            sk,
            version,
            payload,
            expires_at,
            due,
        })
    }
}
#[async_trait]
impl Store for DynamoStore {
    async fn get(&self, pk: &str, sk: &str) -> anyhow::Result<Option<Row>> {
        self.client
            .get_item()
            .table_name(&self.table)
            .key("pk", Av::S(pk.into()))
            .key("sk", Av::S(sk.into()))
            .consistent_read(true)
            .send()
            .await?
            .item
            .map(Self::decode)
            .transpose()
    }
    async fn put(&self, mut row: Row, expected: Option<u64>) -> anyhow::Result<bool> {
        row.version = expected.unwrap_or(0) + 1;
        let mut request = self
            .client
            .put_item()
            .table_name(&self.table)
            .item("pk", Av::S(row.pk))
            .item("sk", Av::S(row.sk))
            .item("version", Av::N(row.version.to_string()))
            .item("payload", Av::S(serde_json::to_string(&row.payload)?));
        if let Some(t) = row.expires_at {
            request = request.item("expires_at", Av::N(t.to_string()));
        }
        if let Some((k, t)) = row.due {
            request = request
                .item("maintenance_pk", Av::S(k))
                .item("maintenance_due", Av::N(t.to_string()));
        }
        request = if let Some(v) = expected {
            request
                .condition_expression("#v = :v")
                .expression_attribute_names("#v", "version")
                .expression_attribute_values(":v", Av::N(v.to_string()))
        } else {
            request.condition_expression("attribute_not_exists(pk)")
        };
        match request.send().await {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }
    async fn transaction(&self, rows: Vec<(Row, Option<u64>)>) -> anyhow::Result<bool> {
        let mut request = self.client.transact_write_items();
        for (row, expected) in rows {
            let mut put = aws_sdk_dynamodb::types::Put::builder()
                .table_name(&self.table)
                .item("pk", Av::S(row.pk))
                .item("sk", Av::S(row.sk))
                .item("payload", Av::S(serde_json::to_string(&row.payload)?))
                .item("version", Av::N((expected.unwrap_or(0) + 1).to_string()));
            if let Some(t) = row.expires_at {
                put = put.item("expires_at", Av::N(t.to_string()));
            }
            if let Some((k, t)) = row.due {
                put = put
                    .item("maintenance_pk", Av::S(k))
                    .item("maintenance_due", Av::N(t.to_string()));
            }
            put = if let Some(v) = expected {
                put.condition_expression("#v = :v")
                    .expression_attribute_names("#v", "version")
                    .expression_attribute_values(":v", Av::N(v.to_string()))
            } else {
                put.condition_expression("attribute_not_exists(pk)")
            };
            request = request.transact_items(
                aws_sdk_dynamodb::types::TransactWriteItem::builder()
                    .put(put.build()?)
                    .build(),
            );
        }
        match request.send().await {
            Ok(_) => Ok(true),
            Err(e)
                if matches!(e.as_service_error(), Some(
                    aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError::TransactionCanceledException(canceled)
                ) if canceled.cancellation_reasons().iter().any(|r| matches!(r.code(), Some("ConditionalCheckFailed" | "TransactionConflict")))
                    && canceled.cancellation_reasons().iter().all(|r| matches!(r.code(), None | Some("None" | "ConditionalCheckFailed" | "TransactionConflict")))) =>
            {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }
    async fn list(&self, pk: &str, prefix: &str) -> anyhow::Result<Vec<Row>> {
        let mut rows = Vec::new();
        let mut cursor = None;
        loop {
            let mut request = self
                .client
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk")
                .expression_attribute_values(":pk", Av::S(pk.into()))
                .consistent_read(true)
                .set_exclusive_start_key(cursor);
            if !prefix.is_empty() {
                request = request
                    .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                    .expression_attribute_values(":prefix", Av::S(prefix.into()));
            }
            let out = request.send().await?;
            for item in out.items.unwrap_or_default() {
                rows.push(Self::decode(item)?)
            }
            cursor = out.last_evaluated_key;
            if cursor.as_ref().is_none_or(|v| v.is_empty()) {
                break;
            }
        }
        Ok(rows)
    }
    async fn list_page(
        &self,
        pk: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Page> {
        anyhow::ensure!((1..=100).contains(&limit), "invalid page size");
        anyhow::ensure!(
            after.is_none_or(|key| key.starts_with(prefix)),
            "invalid page cursor"
        );
        let mut request = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("pk = :pk")
            .expression_attribute_values(":pk", Av::S(pk.into()))
            .consistent_read(true)
            .limit(limit as i32);
        if !prefix.is_empty() {
            request = request
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":prefix", Av::S(prefix.into()));
        }
        if let Some(sk) = after {
            request = request
                .exclusive_start_key("pk", Av::S(pk.into()))
                .exclusive_start_key("sk", Av::S(sk.into()));
        }
        let output = request.send().await?;
        let next_key = output
            .last_evaluated_key
            .as_ref()
            .and_then(|m| m.get("sk"))
            .and_then(|v| v.as_s().ok())
            .cloned();
        let rows = output
            .items
            .unwrap_or_default()
            .into_iter()
            .map(Self::decode)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { rows, next_key })
    }
    async fn due(&self, kind: &str, before: i64) -> anyhow::Result<Vec<Row>> {
        let mut rows = Vec::new();
        let mut cursor = None;
        loop {
            let out = self
                .client
                .query()
                .table_name(&self.table)
                .index_name("maintenance-index")
                .key_condition_expression("maintenance_pk = :kind AND maintenance_due <= :now")
                .expression_attribute_values(":kind", Av::S(kind.into()))
                .expression_attribute_values(":now", Av::N(before.to_string()))
                .limit((100 - rows.len()) as i32)
                .set_exclusive_start_key(cursor)
                .send()
                .await?;
            for item in out.items.unwrap_or_default() {
                rows.push(Self::decode(item)?);
            }
            cursor = out.last_evaluated_key;
            // DynamoDB may reach its 1 MiB page limit before the item limit.
            if rows.len() >= 100 || cursor.as_ref().is_none_or(|v| v.is_empty()) {
                break;
            }
        }
        Ok(rows)
    }
}
