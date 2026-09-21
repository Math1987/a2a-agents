use crate::{
    engine::{Budget, BudgetError},
    store::{Row, Store},
};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct GlobalBudget {
    pub store: Arc<dyn Store>,
    pub limit: u64,
}
fn error() -> BudgetError {
    BudgetError::Storage("reservation conflict or storage unavailable".into())
}
#[async_trait]
impl Budget for GlobalBudget {
    async fn reserve(&self, id: &str, amount: u64) -> Result<(), BudgetError> {
        let month = chrono::Utc::now().format("%Y-%m").to_string();
        for _ in 0..20 {
            let old = self
                .store
                .get("BUDGET", &month)
                .await
                .map_err(|_| error())?;
            let used = old
                .as_ref()
                .and_then(|r| r.payload["used"].as_u64())
                .unwrap_or(0);
            let total = used.checked_add(amount).ok_or(BudgetError::Exhausted)?;
            if total > self.limit {
                return Err(BudgetError::Exhausted);
            }
            if self
                .store
                .get("RESERVATION", id)
                .await
                .map_err(|_| error())?
                .is_some()
            {
                return Err(error());
            }
            let ledger = Row::new("BUDGET", &month, json!({"used":total,"limit":self.limit}));
            let receipt = Row::new(
                "RESERVATION",
                id,
                json!({"month":month,"reserved":amount,"settled":false}),
            );
            if self
                .store
                .transaction(vec![(ledger, old.map(|r| r.version)), (receipt, None)])
                .await
                .map_err(|_| error())?
            {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
        Err(error())
    }
    async fn settle(&self, id: &str, reserved: u64, actual: u64) -> Result<(), BudgetError> {
        for _ in 0..20 {
            let mut receipt = self
                .store
                .get("RESERVATION", id)
                .await
                .map_err(|_| error())?
                .ok_or_else(error)?;
            if receipt.payload["settled"] == true {
                return Ok(());
            }
            if receipt.payload["reserved"].as_u64() != Some(reserved) {
                return Err(error());
            }
            let month = receipt.payload["month"]
                .as_str()
                .ok_or_else(error)?
                .to_owned();
            let mut ledger = self
                .store
                .get("BUDGET", &month)
                .await
                .map_err(|_| error())?
                .ok_or_else(error)?;
            let used = ledger.payload["used"].as_u64().ok_or_else(error)?;
            ledger.payload["used"] = json!(
                used.checked_sub(reserved)
                    .and_then(|n| n.checked_add(actual))
                    .ok_or_else(error)?
            );
            receipt.payload["settled"] = json!(true);
            receipt.payload["actual"] = json!(actual);
            let lv = ledger.version;
            let rv = receipt.version;
            if self
                .store
                .transaction(vec![(ledger, Some(lv)), (receipt, Some(rv))])
                .await
                .map_err(|_| error())?
            {
                return Ok(());
            }
        }
        Err(error())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    #[tokio::test]
    async fn concurrent_agents_share_one_cap() {
        let store = Arc::new(MemoryStore::default());
        let b = GlobalBudget {
            store: store.clone(),
            limit: 100,
        };
        let mut jobs = Vec::new();
        for i in 0..50 {
            let b = b.clone();
            jobs.push(tokio::spawn(async move {
                b.reserve(&format!("agent-{i}"), 10).await.is_ok()
            }));
        }
        let mut n = 0;
        for j in jobs {
            n += usize::from(j.await.unwrap());
        }
        assert_eq!(n, 10);
    }
    #[tokio::test]
    async fn reservation_cannot_authorize_two_calls_and_settle_is_idempotent() {
        let b = GlobalBudget {
            store: Arc::new(MemoryStore::default()),
            limit: 100,
        };
        b.reserve("a", 100).await.unwrap();
        assert!(b.reserve("a", 100).await.is_err());
        b.settle("a", 100, 10).await.unwrap();
        b.settle("a", 100, 10).await.unwrap();
        b.reserve("b", 90).await.unwrap();
        assert!(b.reserve("c", 1).await.is_err());
    }
}
