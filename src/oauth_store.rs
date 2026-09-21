//! Durable SDK stores. OAuth state has a TTL; credentials never inherit it.
use crate::{
    crypto::{Vault, digest},
    domain::{agent_pk, now},
    store::{Row, Store},
};
use async_trait::async_trait;
use rmcp::transport::auth::{
    AuthError, CredentialRefreshGuard, CredentialStore, StateStore, StoredAuthorizationState,
    StoredCredentials,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

fn err() -> AuthError {
    AuthError::CredentialStoreError("persistent authorization store unavailable or busy".into())
}
#[derive(Clone)]
pub struct OAuthStores {
    pub store: Arc<dyn Store>,
    pub vault: Vault,
    pub agent_id: String,
    pub connection_id: String,
    lease: Arc<Mutex<Option<Row>>>,
    local_refresh: Arc<tokio::sync::Mutex<()>>,
}
impl OAuthStores {
    pub fn new(
        store: Arc<dyn Store>,
        vault: Vault,
        agent_id: String,
        connection_id: String,
    ) -> Self {
        Self {
            store,
            vault,
            agent_id,
            connection_id,
            lease: Arc::new(Mutex::new(None)),
            local_refresh: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    fn context(&self) -> String {
        format!("{}/{}", self.agent_id, self.connection_id)
    }
    fn state_key(&self, csrf: &str) -> String {
        format!("OAUTH#{}#{}", self.connection_id, digest(csrf))
    }
    async fn active(&self) -> Result<(), AuthError> {
        let a = self
            .store
            .get(&agent_pk(&self.agent_id), "META")
            .await
            .map_err(|_| err())?
            .ok_or_else(err)?;
        let c = self
            .store
            .get(
                &agent_pk(&self.agent_id),
                &format!("CONN#{}", self.connection_id),
            )
            .await
            .map_err(|_| err())?
            .ok_or_else(err)?;
        if a.payload["deleted"] == true || c.payload["status"] == "disconnected" {
            return Err(AuthError::AuthorizationRequired);
        }
        Ok(())
    }
    async fn release(&self) -> Result<(), AuthError> {
        let lease = self.lease.lock().map_err(|_| err())?.take();
        if let Some(lease) = lease {
            self.release_version(lease).await?;
        }
        Ok(())
    }
    async fn release_version(&self, mut lease: Row) -> Result<(), AuthError> {
        // A delayed Drop must never release a newer holder's lease. Compare the
        // exact version acquired by this guard; a conflict means it is obsolete.
        let version = lease.version;
        lease.payload = json!({"until":0});
        self.store
            .put(lease, Some(version))
            .await
            .map_err(|_| err())?;
        Ok(())
    }
}
#[async_trait]
impl StateStore for OAuthStores {
    async fn save(&self, csrf: &str, state: StoredAuthorizationState) -> Result<(), AuthError> {
        let sealed = self
            .vault
            .seal(&self.context(), &state)
            .await
            .map_err(|_| err())?;
        let mut row = Row::new(
            agent_pk(&self.agent_id),
            self.state_key(csrf),
            json!({"sealed":sealed,"consumed":false}),
        );
        row.expires_at = Some(now() + 600);
        if !self.store.put(row, None).await.map_err(|_| err())? {
            return Err(err());
        }
        Ok(())
    }
    async fn load(&self, csrf: &str) -> Result<Option<StoredAuthorizationState>, AuthError> {
        let Some(row) = self
            .store
            .get(&agent_pk(&self.agent_id), &self.state_key(csrf))
            .await
            .map_err(|_| err())?
        else {
            return Ok(None);
        };
        if row.expires_at.is_none_or(|t| t <= now()) || row.payload["consumed"] == true {
            return Ok(None);
        }
        self.vault
            .open(
                &self.context(),
                row.payload["sealed"].as_str().ok_or_else(err)?,
            )
            .await
            .map(Some)
            .map_err(|_| err())
    }
    async fn delete(&self, csrf: &str) -> Result<(), AuthError> {
        let mut row = self
            .store
            .get(&agent_pk(&self.agent_id), &self.state_key(csrf))
            .await
            .map_err(|_| err())?
            .ok_or_else(err)?;
        if row.expires_at.is_none_or(|t| t <= now()) || row.payload["consumed"] == true {
            return Err(err());
        }
        let version = row.version;
        row.payload = json!({"consumed":true});
        if !self
            .store
            .put(row, Some(version))
            .await
            .map_err(|_| err())?
        {
            return Err(err());
        }
        Ok(())
    }
}
struct RefreshLease {
    stores: OAuthStores,
    row: Row,
    _local_guard: tokio::sync::OwnedMutexGuard<()>,
}
impl Drop for RefreshLease {
    fn drop(&mut self) {
        if let Ok(mut held) = self.stores.lease.lock()
            && held
                .as_ref()
                .is_some_and(|row| row.version == self.row.version)
        {
            held.take();
        }
        let stores = self.stores.clone();
        let row = self.row.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = stores.release_version(row).await;
            });
        }
        // If Lambda freezes here, the 120-second database lease expires. Saving
        // credentials releases it transactionally before reporting success.
    }
}
#[async_trait]
impl CredentialStore for OAuthStores {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        self.active().await?;
        let row = self
            .store
            .get(
                &agent_pk(&self.agent_id),
                &format!("CREDENTIALS#{}", self.connection_id),
            )
            .await
            .map_err(|_| err())?;
        match row.and_then(|r| r.payload["sealed"].as_str().map(str::to_owned)) {
            Some(sealed) => self
                .vault
                .open(&self.context(), &sealed)
                .await
                .map(Some)
                .map_err(|_| err()),
            None => Ok(None),
        }
    }
    async fn save(&self, credentials: StoredCredentials) -> Result<(), AuthError> {
        self.active().await?;
        let pk = agent_pk(&self.agent_id);
        let sk = format!("CREDENTIALS#{}", self.connection_id);
        let old = self.store.get(&pk, &sk).await.map_err(|_| err())?;
        let sealed = self
            .vault
            .seal(&self.context(), &credentials)
            .await
            .map_err(|_| err())?;
        let row = Row::new(pk, sk, json!({"sealed":sealed,"updated_at":now()}));
        let lease = self.lease.lock().map_err(|_| err())?.clone();
        let committed = if let Some(mut lease) = lease {
            if lease.payload["until"].as_i64().unwrap_or(0) <= now() {
                return Err(err());
            }
            let version = lease.version;
            lease.payload = json!({"until":0});
            self.store
                .transaction(vec![
                    (row, old.as_ref().map(|r| r.version)),
                    (lease, Some(version)),
                ])
                .await
                .map_err(|_| err())?
        } else {
            self.store
                .put(row, old.as_ref().map(|r| r.version))
                .await
                .map_err(|_| err())?
        };
        if !committed {
            return Err(err());
        }
        self.lease.lock().map_err(|_| err())?.take();
        Ok(())
    }
    async fn clear(&self) -> Result<(), AuthError> {
        let pk = agent_pk(&self.agent_id);
        let sk = format!("CREDENTIALS#{}", self.connection_id);
        if let Some(mut row) = self.store.get(&pk, &sk).await.map_err(|_| err())? {
            let v = row.version;
            row.payload = json!({});
            if !self.store.put(row, Some(v)).await.map_err(|_| err())? {
                return Err(err());
            }
        }
        self.release().await
    }
    async fn acquire_refresh_guard(&self) -> Result<Option<CredentialRefreshGuard>, AuthError> {
        // Cloned SDK stores inside one process also need serialization: save()
        // releases the database lease before its SDK refresh guard is dropped.
        let local_guard = self.local_refresh.clone().lock_owned().await;
        let pk = agent_pk(&self.agent_id);
        let sk = format!("LOCK#{}", self.connection_id);
        for _ in 0..30 {
            let old = self.store.get(&pk, &sk).await.map_err(|_| err())?;
            if old
                .as_ref()
                .is_none_or(|r| r.payload["until"].as_i64().unwrap_or(0) <= now())
            {
                let mut row = Row::new(&pk, &sk, json!({"until":now()+120}));
                let expected = old.as_ref().map(|r| r.version);
                if self
                    .store
                    .put(row.clone(), expected)
                    .await
                    .map_err(|_| err())?
                {
                    row.version = expected.unwrap_or(0) + 1;
                    *self.lease.lock().map_err(|_| err())? = Some(row.clone());
                    return Ok(Some(CredentialRefreshGuard::new(RefreshLease {
                        stores: self.clone(),
                        row,
                        _local_guard: local_guard,
                    })));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err(err())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use oauth2::{CsrfToken, PkceCodeVerifier};

    async fn setup() -> OAuthStores {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::default());
        store
            .put(
                Row::new(agent_pk("agent"), "META", json!({"deleted":false})),
                None,
            )
            .await
            .unwrap();
        store
            .put(
                Row::new(
                    agent_pk("agent"),
                    "CONN#connection",
                    json!({"status":"connected"}),
                ),
                None,
            )
            .await
            .unwrap();
        OAuthStores::new(
            store,
            Vault::ephemeral().unwrap(),
            "agent".into(),
            "connection".into(),
        )
    }

    fn restored(stores: &OAuthStores) -> OAuthStores {
        OAuthStores::new(
            stores.store.clone(),
            stores.vault.clone(),
            stores.agent_id.clone(),
            stores.connection_id.clone(),
        )
    }

    fn credentials(token: &str) -> StoredCredentials {
        let response=serde_json::from_value(json!({"access_token":token,"refresh_token":"durable-refresh","token_type":"Bearer","expires_in":3600})).unwrap();
        StoredCredentials::new(
            "client".into(),
            Some(response),
            vec!["mcp".into()],
            Some(now() as u64),
        )
    }

    #[tokio::test]
    async fn state_is_encrypted_expires_and_can_only_be_consumed_once_after_restart() {
        let stores = setup().await;
        let state = StoredAuthorizationState::new(
            &PkceCodeVerifier::new("pkce-secret".into()),
            &CsrfToken::new("csrf-state".into()),
        );
        StateStore::save(&stores, "csrf-state", state.clone())
            .await
            .unwrap();
        let row = stores
            .store
            .get(&agent_pk("agent"), &stores.state_key("csrf-state"))
            .await
            .unwrap()
            .unwrap();
        assert!(!row.payload.to_string().contains("pkce-secret"));
        let restarted = restored(&stores);
        assert_eq!(
            StateStore::load(&restarted, "csrf-state")
                .await
                .unwrap()
                .unwrap()
                .pkce_verifier,
            "pkce-secret"
        );
        let (a, b) = tokio::join!(
            StateStore::delete(&stores, "csrf-state"),
            StateStore::delete(&restarted, "csrf-state")
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(
            StateStore::load(&restarted, "csrf-state")
                .await
                .unwrap()
                .is_none()
        );
        StateStore::save(&stores, "expired-state", state)
            .await
            .unwrap();
        let mut expired = stores
            .store
            .get(&agent_pk("agent"), &stores.state_key("expired-state"))
            .await
            .unwrap()
            .unwrap();
        let version = expired.version;
        expired.expires_at = Some(now() - 1);
        stores.store.put(expired, Some(version)).await.unwrap();
        assert!(
            StateStore::load(&restarted, "expired-state")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            StateStore::delete(&restarted, "expired-state")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn credentials_survive_reconstruction_without_temporary_state_ttl() {
        let stores = setup().await;
        CredentialStore::save(&stores, credentials("initial"))
            .await
            .unwrap();
        let restarted = restored(&stores);
        let persisted = CredentialStore::load(&restarted).await.unwrap().unwrap();
        assert!(persisted.token_response.is_some());
        let row = stores
            .store
            .get(&agent_pk("agent"), "CREDENTIALS#connection")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.expires_at, None);
        assert!(!row.payload.to_string().contains("durable-refresh"));
        let wrong_connection = OAuthStores::new(
            stores.store.clone(),
            stores.vault.clone(),
            "agent".into(),
            "other".into(),
        );
        assert!(CredentialStore::load(&wrong_connection).await.is_err());
    }

    #[tokio::test]
    async fn expired_holder_cannot_save_or_release_the_new_holders_lease() {
        let stores = setup().await;
        CredentialStore::save(&stores, credentials("initial"))
            .await
            .unwrap();
        let old_guard = stores.acquire_refresh_guard().await.unwrap();
        let old_snapshot = stores.lease.lock().unwrap().clone().unwrap();
        // Advance the database lease as if its time had elapsed and another
        // Lambda legitimately acquired it. The old process still holds its snapshot.
        let mut expired = old_snapshot.clone();
        expired.payload = json!({"until":0});
        stores
            .store
            .put(expired, Some(old_snapshot.version))
            .await
            .unwrap();
        let new_holder = restored(&stores);
        let new_guard = new_holder.acquire_refresh_guard().await.unwrap();
        let new_snapshot = new_holder.lease.lock().unwrap().clone().unwrap();
        assert!(
            CredentialStore::save(&stores, credentials("stale"))
                .await
                .is_err()
        );
        stores.release_version(old_snapshot.clone()).await.unwrap();
        let current = stores
            .store
            .get(&agent_pk("agent"), "LOCK#connection")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.version, new_snapshot.version);
        assert!(current.payload["until"].as_i64().unwrap() > now());
        drop(old_guard);
        CredentialStore::save(&new_holder, credentials("new"))
            .await
            .unwrap();
        drop(new_guard);
        let row = stores
            .store
            .get(&agent_pk("agent"), "CREDENTIALS#connection")
            .await
            .unwrap()
            .unwrap();
        let opened: StoredCredentials = stores
            .vault
            .open(&stores.context(), row.payload["sealed"].as_str().unwrap())
            .await
            .unwrap();
        use oauth2::TokenResponse;
        assert_eq!(
            opened.token_response.unwrap().access_token().secret(),
            "new"
        );
    }

    #[tokio::test]
    async fn a_cloned_store_holds_local_guard_until_the_sdk_guard_is_dropped() {
        let stores = setup().await;
        let guard = stores.acquire_refresh_guard().await.unwrap();
        CredentialStore::save(&stores, credentials("new"))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                stores.clone().acquire_refresh_guard()
            )
            .await
            .is_err()
        );
        drop(guard);
        let next = stores.acquire_refresh_guard().await.unwrap();
        drop(next);
    }
}
