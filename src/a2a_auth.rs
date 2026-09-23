//! A2A-only authentication. Owner REST routes deliberately keep their existing
//! owner-key checks and never accept these invocation-only JWTs.

use crate::{
    app::App,
    connectors::OutboundHttp,
    crypto::digest,
    domain::{Agent, agent_pk},
};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const MAX_SKILLS: usize = 64;
const JWKS_TTL: Duration = Duration::from_secs(300);
const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const JWKS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    Owner,
    Invoker {
        caller_id: String,
        skill_ids: Vec<String>,
    },
}

impl Principal {
    pub fn caller_id(&self) -> String {
        match self {
            Self::Owner => "owner".into(),
            Self::Invoker { caller_id, .. } => caller_id.clone(),
        }
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("{message}")]
pub struct AuthError {
    pub status: StatusCode,
    pub message: &'static str,
}

impl AuthError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid_a2a_credentials",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "insufficient_a2a_permissions",
        }
    }

    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "auth_service_unavailable",
        }
    }

    fn missing_agent() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "agent_not_found",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("A2A authentication requires valid A2A_ISSUER, A2A_JWKS_URL and A2A_AUDIENCE settings")]
pub struct AuthConfigError;

#[derive(Default)]
struct JwksCache {
    keys: BTreeMap<String, DecodingKey>,
    valid_until: Option<Instant>,
    last_attempt: Option<Instant>,
    last_forced_refresh: Option<Instant>,
}

/// Trusted operator configuration, shared for all requests in a Lambda runtime.
/// There is no discovery URL or issuer supplied by the bearer token itself.
pub struct A2aAuthConfig {
    issuer: String,
    jwks_url: String,
    audience: String,
    http: OutboundHttp,
    cache: Mutex<JwksCache>,
}

impl A2aAuthConfig {
    pub fn new(
        http: OutboundHttp,
        issuer: String,
        jwks_url: String,
        audience: String,
    ) -> Result<Self, AuthConfigError> {
        let issuer_url = http.validate_url(&issuer).map_err(|_| AuthConfigError)?;
        http.validate_url(&jwks_url).map_err(|_| AuthConfigError)?;
        if issuer.len() > 2048
            || jwks_url.len() > 2048
            || issuer_url.query().is_some()
            || audience.is_empty()
            || audience.len() > 512
            || audience.trim() != audience
        {
            return Err(AuthConfigError);
        }
        Ok(Self {
            issuer,
            jwks_url,
            audience,
            http,
            cache: Mutex::new(JwksCache::default()),
        })
    }

    pub fn from_env(http: OutboundHttp) -> Result<Option<Arc<Self>>, AuthConfigError> {
        let issuer = match std::env::var("A2A_ISSUER") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err(AuthConfigError),
        };
        let jwks = std::env::var("A2A_JWKS_URL").map_err(|_| AuthConfigError)?;
        let audience = std::env::var("A2A_AUDIENCE").map_err(|_| AuthConfigError)?;
        Self::new(http, issuer, jwks, audience).map(|config| Some(Arc::new(config)))
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Holding this mutex through the bounded fetch coalesces concurrent
        // misses. A random kid cannot trigger an unbounded set of cached keys.
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        let fresh = cache.valid_until.is_some_and(|until| now < until);
        if fresh {
            if let Some(key) = cache.keys.get(kid) {
                return Ok(key.clone());
            }
            if cache
                .last_forced_refresh
                .is_some_and(|last| now.duration_since(last) < REFRESH_COOLDOWN)
            {
                return Err(AuthError::unauthorized());
            }
            // An unknown kid can refresh a fresh cache once immediately, to
            // pick up key rotation. Further misses are throttled for 30 seconds.
            cache.last_forced_refresh = Some(now);
        } else if cache
            .last_attempt
            .is_some_and(|last| now.duration_since(last) < REFRESH_COOLDOWN)
        {
            return Err(AuthError::unavailable());
        }
        cache.last_attempt = Some(now);
        let keys = self.fetch_keys().await?;
        cache.keys = keys;
        cache.valid_until = Some(Instant::now() + JWKS_TTL);
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(AuthError::unauthorized)
    }

    async fn fetch_keys(&self) -> Result<BTreeMap<String, DecodingKey>, AuthError> {
        let url = self
            .http
            .validate_url(&self.jwks_url)
            .map_err(|_| AuthError::unavailable())?;
        // OutboundHttp also rejects private DNS results at connection time,
        // ignores environment proxies, and does not follow redirects.
        let mut response = self
            .http
            .client
            .get(url)
            .timeout(JWKS_TIMEOUT)
            .send()
            .await
            .map_err(|_| AuthError::unavailable())?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_JWKS_BYTES as u64)
        {
            return Err(AuthError::unavailable());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthError::unavailable())?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
                return Err(AuthError::unavailable());
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_keys(&bytes)
    }

    async fn verify(&self, token: &str, agent_id: &str) -> Result<Principal, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::unauthorized())?;
        if header.alg != Algorithm::RS256
            || header
                .crit
                .as_ref()
                .is_some_and(|fields| !fields.is_empty())
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.enc.is_some()
            || header.zip.is_some()
            || header
                .typ
                .as_deref()
                .is_some_and(|typ| typ != "JWT" && typ != "at+jwt")
        {
            return Err(AuthError::unauthorized());
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| valid_identifier(kid, 128))
            .ok_or_else(AuthError::unauthorized)?;
        let key = self.key(kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| AuthError::unauthorized())?
            .claims;
        if claims.exp <= jsonwebtoken::get_current_timestamp()
            || !valid_identifier(&claims.sub, 512)
        {
            return Err(AuthError::unauthorized());
        }
        if claims.agent_id != agent_id
            || !claims
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == "a2a:invoke")
            || claims.skill_ids.is_empty()
            || claims.skill_ids.len() > MAX_SKILLS
            || claims
                .skill_ids
                .iter()
                .any(|skill| skill == "*" || !valid_identifier(skill, 128))
        {
            return Err(AuthError::forbidden());
        }
        let skill_ids = claims
            .skill_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Principal::Invoker {
            caller_id: caller_identity(&claims.iss, &claims.sub),
            skill_ids,
        })
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: u64,
    agent_id: String,
    scope: String,
    skill_ids: Vec<String>,
}

fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn caller_identity(issuer: &str, subject: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aithos-a2a-caller-v1\0");
    for field in [issuer, subject] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("aithos:{:x}", hash.finalize())
}

#[derive(Deserialize)]
struct RawJwks {
    keys: Vec<serde_json::Value>,
}

fn parse_keys(bytes: &[u8]) -> Result<BTreeMap<String, DecodingKey>, AuthError> {
    let jwks: RawJwks = serde_json::from_slice(bytes).map_err(|_| AuthError::unavailable())?;
    if jwks.keys.is_empty() || jwks.keys.len() > MAX_JWKS_KEYS {
        return Err(AuthError::unavailable());
    }
    let mut keys = BTreeMap::new();
    for value in jwks.keys {
        let jwk = value.as_object().ok_or_else(AuthError::unavailable)?;
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|field| jwk.contains_key(*field))
        {
            return Err(AuthError::unavailable());
        }
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("RSA")
            || jwk.get("alg").is_some_and(|v| v.as_str() != Some("RS256"))
            || jwk.get("use").is_some_and(|v| v.as_str() != Some("sig"))
            || jwk.get("key_ops").is_some_and(|v| {
                v.as_array().is_none_or(|ops| {
                    ops.is_empty() || ops.iter().any(|op| op.as_str() != Some("verify"))
                })
            })
        {
            continue;
        }
        let field = |name: &str| {
            jwk.get(name)
                .and_then(|v| v.as_str())
                .ok_or_else(AuthError::unavailable)
        };
        let kid = field("kid")?;
        let n = field("n")?;
        let e = field("e")?;
        if !valid_identifier(kid, 128) || n.len() > 1400 || e.len() > 12 {
            return Err(AuthError::unavailable());
        }
        let modulus = URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|_| AuthError::unavailable())?;
        let exponent = URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|_| AuthError::unavailable())?;
        let bits = modulus
            .first()
            .map(|first| (modulus.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
            .unwrap_or(0);
        if !(2048..=8192).contains(&bits) || exponent.is_empty() || exponent.len() > 8 {
            return Err(AuthError::unavailable());
        }
        let exponent = exponent.iter().fold(0_u64, |n, b| (n << 8) | u64::from(*b));
        if exponent < 3 || exponent % 2 == 0 {
            return Err(AuthError::unavailable());
        }
        let key = DecodingKey::from_rsa_components(n, e).map_err(|_| AuthError::unavailable())?;
        if keys.insert(kid.to_owned(), key).is_some() {
            return Err(AuthError::unavailable());
        }
    }
    if keys.is_empty() {
        return Err(AuthError::unavailable());
    }
    Ok(keys)
}

/// Authenticate only the A2A endpoint. Authorization to specific skills and
/// existing tasks remains a server policy check on the returned principal.
pub async fn authenticate(
    app: &App,
    agent_id: &str,
    headers: &HeaderMap,
) -> Result<Principal, AuthError> {
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return Err(AuthError::unauthorized());
    }
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(AuthError::unauthorized)?;
    let (scheme, token) = authorization
        .split_once(' ')
        .ok_or_else(AuthError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || !valid_identifier(token, MAX_TOKEN_BYTES) {
        return Err(AuthError::unauthorized());
    }
    let row = app
        .store
        .get(&agent_pk(agent_id), "META")
        .await
        .map_err(|_| AuthError::unavailable())?
        .ok_or_else(AuthError::missing_agent)?;
    if row.payload.is_null() {
        return Err(AuthError::missing_agent());
    }
    let agent: Agent = serde_json::from_value(row.payload).map_err(|_| AuthError::unavailable())?;
    if agent.deleted || agent.id != agent_id {
        return Err(AuthError::missing_agent());
    }
    let hashed = digest(token);
    // Constant-time equality over the fixed-size digest; no raw owner secret is stored.
    if agent.key_hash.len() == hashed.len()
        && agent
            .key_hash
            .bytes()
            .zip(hashed.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    {
        return Ok(Principal::Owner);
    }
    let config = app.a2a_auth.as_ref().ok_or_else(AuthError::unauthorized)?;
    config.verify(token, agent_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Row;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const ISSUER: &str = "https://auth.aithos.example";
    const AUDIENCE: &str = "https://agents.aithos.app";
    const OWNER_KEY: &str = "disposable-owner-key-for-auth-tests";

    fn claims() -> Value {
        json!({
            "iss": ISSUER, "sub": "alice", "aud": AUDIENCE,
            "exp": jsonwebtoken::get_current_timestamp() + 300,
            "agent_id": "agent-a", "scope": "a2a:invoke",
            "skill_ids": ["calendar"],
        })
    }

    fn jwk(kid: &str, second: bool) -> Value {
        json!({"kid":kid,"kty":"RSA","use":"sig","alg":"RS256","key_ops":["verify"],
            "n":if second { MODULUS_2 } else { MODULUS_1 },"e":"AQAB"})
    }

    fn sign(claims: &Value, kid: &str, second: bool) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let pem = if second { PRIVATE_KEY_2 } else { PRIVATE_KEY_1 };
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers
    }

    async fn fixture() -> (App, MockServer) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"keys":[jwk("key-1",false)]})),
            )
            .mount(&server)
            .await;
        let mut app = App::local().await.unwrap();
        for id in ["agent-a", "agent-b"] {
            let agent = Agent {
                id: id.into(),
                name: id.into(),
                description: String::new(),
                key_hash: digest(OWNER_KEY),
                created_at: 0,
                deleted: false,
            };
            app.store
                .put(Row::new(agent_pk(id), "META", json!(agent)), None)
                .await
                .unwrap();
        }
        app.a2a_auth = Some(Arc::new(
            A2aAuthConfig::new(
                OutboundHttp::for_local_tests(),
                ISSUER.into(),
                format!("{}/jwks", server.uri()),
                AUDIENCE.into(),
            )
            .unwrap(),
        ));
        (app, server)
    }

    #[tokio::test]
    async fn owner_key_works_while_jwt_authentication_is_disabled() {
        let (mut app, server) = fixture().await;
        app.a2a_auth = None;
        let owner = authenticate(&app, "agent-a", &headers(OWNER_KEY))
            .await
            .unwrap();
        assert_eq!(owner, Principal::Owner);
        assert_eq!(owner.caller_id(), "owner");
        assert!(owner.is_owner());
        let token = sign(&claims(), "key-1", false);
        assert_eq!(
            authenticate(&app, "agent-a", &headers(&token))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn valid_jwt_has_only_invoker_permissions_and_stable_non_owner_identity() {
        let (app, server) = fixture().await;
        let mut first = claims();
        first["skill_ids"] = json!(["notion", "calendar", "calendar"]);
        first["role"] = json!("owner");
        first["is_owner"] = json!(true);
        let caller = authenticate(&app, "agent-a", &headers(&sign(&first, "key-1", false)))
            .await
            .unwrap();
        assert!(!caller.is_owner());
        assert_ne!(caller.caller_id(), "owner");
        assert!(!caller.caller_id().contains("alice"));
        assert!(
            matches!(&caller, Principal::Invoker {skill_ids,..} if skill_ids == &vec!["calendar".to_string(), "notion".to_string()])
        );
        let mut renewed = claims();
        renewed["exp"] = json!(jsonwebtoken::get_current_timestamp() + 600);
        let same = authenticate(&app, "agent-a", &headers(&sign(&renewed, "key-1", false)))
            .await
            .unwrap();
        assert_eq!(caller.caller_id(), same.caller_id());
        renewed["sub"] = json!("bob");
        let other = authenticate(&app, "agent-a", &headers(&sign(&renewed, "key-1", false)))
            .await
            .unwrap();
        assert_ne!(caller.caller_id(), other.caller_id());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn jwt_cannot_authenticate_an_owner_rest_route() {
        let (app, _server) = fixture().await;
        let token = sign(&claims(), "key-1", false);
        assert!(
            !authenticate(&app, "agent-a", &headers(&token))
                .await
                .unwrap()
                .is_owner()
        );
        let response = crate::api::router(app)
            .oneshot(
                Request::builder()
                    .uri("/v1/agents/agent-a")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    async fn routed_rpc(app: App, token: &str, method: &str, params: Value) -> (StatusCode, Value) {
        let response = crate::api::router(app)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/agent-a/a2a")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("a2a-version", "1.0")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn signed_jwt_through_real_router_can_invoke_and_read_only_its_own_a2a_task() {
        let (app, server) = fixture().await;
        for id in ["calendar", "notion"] {
            let skill = crate::domain::Skill {
                id: id.into(),
                name: id.into(),
                description: "Test skill".into(),
                instructions: "Return a short response.".into(),
                connector_ids: vec![],
            };
            app.store
                .put(
                    Row::new(agent_pk("agent-a"), format!("SKILL#{id}"), json!(skill)),
                    None,
                )
                .await
                .unwrap();
        }
        let alice = sign(&claims(), "key-1", false);
        let params = json!({
            "configuration":{"returnImmediately":true},
            "message":{"messageId":"signed-jwt-message","role":"ROLE_USER","parts":[{"text":"Prepare a suggestion"}]},
            "metadata":{"skill_ids":["calendar"]},
        });
        let (status, created) =
            routed_rpc(app.clone(), &alice, "SendMessage", params.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(created.get("error").is_none(), "{created}");
        let task = created["result"]["task"]["id"].as_str().unwrap();
        let (status, own) = routed_rpc(app.clone(), &alice, "GetTask", json!({"id":task})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(own["result"]["id"], task, "{own}");
        let mut other_claims = claims();
        other_claims["sub"] = json!("bob");
        let bob = sign(&other_claims, "key-1", false);
        let (_, denied) = routed_rpc(app.clone(), &bob, "GetTask", json!({"id":task})).await;
        assert_eq!(
            denied["error"]["code"],
            a2a_protocol::error_code::TASK_NOT_FOUND
        );
        assert!(denied.get("result").is_none());
        let (_, owner) = routed_rpc(app.clone(), OWNER_KEY, "GetTask", json!({"id":task})).await;
        assert_eq!(owner["result"]["id"], task);
        let mut escalated = params;
        escalated["message"]["messageId"] = json!("signed-jwt-escalation");
        escalated["metadata"]["skill_ids"] = json!(["notion"]);
        let (_, denied) = routed_rpc(app.clone(), &alice, "SendMessage", escalated).await;
        assert_eq!(
            denied["error"]["code"],
            a2a_protocol::error_code::INVALID_PARAMS
        );
        let response = crate::api::router(app.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/agents/agent-a")
                    .header(AUTHORIZATION, format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let stored = app
            .store
            .get(&agent_pk("agent-a"), &format!("TASK#{task}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.payload["status"], "queued");
        assert_eq!(stored.payload["skill_ids"], json!(["calendar"]));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejects_wrong_issuer_audience_expiration_signature_and_not_before() {
        let (app, _server) = fixture().await;
        for (field, value) in [
            ("iss", json!("https://attacker.example")),
            ("aud", json!("another-service")),
            ("exp", json!(jsonwebtoken::get_current_timestamp() - 1)),
            ("nbf", json!(jsonwebtoken::get_current_timestamp() + 60)),
            ("sub", json!("")),
        ] {
            let mut invalid = claims();
            invalid[field] = value;
            let error = authenticate(&app, "agent-a", &headers(&sign(&invalid, "key-1", false)))
                .await
                .unwrap_err();
            assert_eq!(
                error.status,
                StatusCode::UNAUTHORIZED,
                "accepted invalid {field}"
            );
            assert_eq!(error.message, "invalid_a2a_credentials");
        }
        let forged = sign(&claims(), "key-1", true);
        assert_eq!(
            authenticate(&app, "agent-a", &headers(&forged))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn invocation_requires_the_target_agent_exact_scope_and_explicit_skills() {
        let (app, _server) = fixture().await;
        for (field, value) in [
            ("agent_id", json!("agent-b")),
            ("scope", json!("a2a:manage")),
            ("scope", json!("prefix-a2a:invoke")),
            ("skill_ids", json!([])),
            ("skill_ids", json!(["*"])),
            ("skill_ids", json!([" "])),
            ("skill_ids", json!(vec!["calendar"; MAX_SKILLS + 1])),
        ] {
            let mut invalid = claims();
            invalid[field] = value;
            assert_eq!(
                authenticate(&app, "agent-a", &headers(&sign(&invalid, "key-1", false)))
                    .await
                    .unwrap_err()
                    .status,
                StatusCode::FORBIDDEN,
                "accepted invalid {field}"
            );
        }
        for field in ["iss", "sub", "exp", "aud", "agent_id", "scope", "skill_ids"] {
            let mut incomplete = claims();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(
                authenticate(
                    &app,
                    "agent-a",
                    &headers(&sign(&incomplete, "key-1", false))
                )
                .await
                .is_err(),
                "accepted missing {field}"
            );
        }
    }

    #[tokio::test]
    async fn key_rotation_refreshes_once_and_does_not_change_caller_identity() {
        let (app, server) = fixture().await;
        let previous = authenticate(&app, "agent-a", &headers(&sign(&claims(), "key-1", false)))
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"keys":[jwk("key-1",false),jwk("key-2",true)]})),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        let rotated = authenticate(&app, "agent-a", &headers(&sign(&claims(), "key-2", true)))
            .await
            .unwrap();
        assert_eq!(previous.caller_id(), rotated.caller_id());
        for kid in ["unknown-a", "unknown-b", "unknown-c"] {
            assert_eq!(
                authenticate(&app, "agent-a", &headers(&sign(&claims(), kid, false)))
                    .await
                    .unwrap_err()
                    .status,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn expired_cache_fails_closed_when_jwks_is_unavailable_and_backs_off() {
        let (app, server) = fixture().await;
        let token = sign(&claims(), "key-1", false);
        authenticate(&app, "agent-a", &headers(&token))
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .with_priority(1)
            .mount(&server)
            .await;
        {
            let mut cache = app.a2a_auth.as_ref().unwrap().cache.lock().await;
            cache.valid_until = Some(Instant::now() - Duration::from_secs(1));
            cache.last_attempt = Some(Instant::now() - REFRESH_COOLDOWN);
        }
        for _ in 0..2 {
            assert_eq!(
                authenticate(&app, "agent-a", &headers(&token))
                    .await
                    .unwrap_err()
                    .status,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_jwks_fetch() {
        let (app, server) = fixture().await;
        let token = sign(&claims(), "key-1", false);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let app = app.clone();
            let headers = headers(&token);
            tasks.spawn(async move { authenticate(&app, "agent-a", &headers).await });
        }
        while let Some(task) = tasks.join_next().await {
            assert!(task.unwrap().is_ok());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn untrusted_header_keys_algorithms_and_duplicate_authorization_are_rejected_before_fetch()
     {
        let (app, server) = fixture().await;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key-1".into());
        header.jku = Some("http://169.254.169.254/latest/meta-data".into());
        let token = encode(
            &header,
            &claims(),
            &EncodingKey::from_rsa_pem(PRIVATE_KEY_1.as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            authenticate(&app, "agent-a", &headers(&token))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(b"attacker-controlled"),
        )
        .unwrap();
        assert_eq!(
            authenticate(&app, "agent-a", &headers(&token))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let mut duplicated = headers(OWNER_KEY);
        duplicated.append(
            AUTHORIZATION,
            format!("Bearer {OWNER_KEY}").parse().unwrap(),
        );
        assert_eq!(
            authenticate(&app, "agent-a", &duplicated)
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleted_agents_reject_owner_and_invoker() {
        let (app, server) = fixture().await;
        let mut row = app
            .store
            .get(&agent_pk("agent-a"), "META")
            .await
            .unwrap()
            .unwrap();
        let version = row.version;
        row.payload["deleted"] = json!(true);
        app.store.put(row, Some(version)).await.unwrap();
        for token in [OWNER_KEY.to_string(), sign(&claims(), "key-1", false)] {
            assert_eq!(
                authenticate(&app, "agent-a", &headers(&token))
                    .await
                    .unwrap_err()
                    .status,
                StatusCode::NOT_FOUND
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn trusted_endpoints_still_enforce_the_production_network_boundary() {
        for url in [
            "http://example.com/jwks",
            "https://127.0.0.1/jwks",
            "https://169.254.169.254/latest/meta-data",
            "https://user:pass@example.com/jwks",
        ] {
            assert!(
                A2aAuthConfig::new(
                    OutboundHttp::new().unwrap(),
                    ISSUER.into(),
                    url.into(),
                    AUDIENCE.into()
                )
                .is_err()
            );
        }
        assert!(
            A2aAuthConfig::new(
                OutboundHttp::new().unwrap(),
                "http://issuer.example".into(),
                "https://issuer.example/jwks".into(),
                AUDIENCE.into()
            )
            .is_err()
        );
        assert!(
            A2aAuthConfig::new(
                OutboundHttp::new().unwrap(),
                ISSUER.into(),
                "https://issuer.example/jwks".into(),
                "".into()
            )
            .is_err()
        );
        assert_ne!(caller_identity("ab", "c"), caller_identity("a", "bc"));
        assert_ne!(
            caller_identity(ISSUER, "alice"),
            caller_identity("https://other.example", "alice")
        );
    }

    #[test]
    fn jwks_accepts_only_bounded_public_rsa_signing_keys() {
        assert!(
            parse_keys(&serde_json::to_vec(&json!({"keys":[jwk("key-1",false)]})).unwrap()).is_ok()
        );
        let mut private = jwk("key-1", false);
        private["d"] = json!("must-never-be-public");
        let mut weak = jwk("key-1", false);
        weak["n"] = json!(URL_SAFE_NO_PAD.encode([0xff; 128]));
        for keys in [
            vec![],
            vec![private],
            vec![weak],
            vec![jwk("duplicate", false), jwk("duplicate", true)],
            vec![jwk("key-1", false); MAX_JWKS_KEYS + 1],
        ] {
            assert!(parse_keys(&serde_json::to_vec(&json!({"keys":keys})).unwrap()).is_err());
        }
    }

    // Disposable RSA fixtures generated only for these tests; never deployment keys.
    const PRIVATE_KEY_1: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm3I+PmNEMfWRL
9oMzfLgj70Y0NXp54U7iubzivxA2pUpuGhA4xHLv6wza83YtE9t6mnDgouzRkgu+
M3HWWgH8pkkVaa5B6v96WhUA/f/175xjpCGzpkUyJdRtv8SdAr6pJ86DLjKFFXf4
5qWyRJ2QKBAZUyADO3ITHaWPTGNCL46jPeYFvNMdasdAywo/ZslM4/MAg+Ge4otr
EE0yelG6JtvQ4IHnYN2xu/24OWZgL+WMm6Yuz/6K9UcCCJQrF1x/E24ldPqJSHLo
6Zx7ZFeGL+Lov7ujhXSKv9pmb9CIlz5RAW+vg2PMwGWslbpeLseCK+LFBr1Y8Ise
QNk8W+ujAgMBAAECggEACKQvgx5E5UKxKQXxMX9qAeJoXlfOqfUzIqa/03ZVnp7c
xervoCD8WtRva/9jxV3b5fONmPSXExtfJFCBuroalD0AV+2LKrrC1FFJ+S0uTkxE
axya6jTYLIqs/6oIwqDbwuLe3QhNcXr1JZy8RAktp8OLYeReKgywEbFdW5h3I3xB
m3dFa6yf4IIE2+aD3MRJCcVTT9448ppPuBHFr01fB9xN7y7WViIh7x5qxdBKQadw
1iLEQUBoQ8xExiY8JPLauOuDtUCZenak4O8zwsSDd2dhG8PW/nweSVF2/lpWH8bf
M5PDVYna03TcWqUgUwqJgkbF/QhQ4RYAJVedv8vWIQKBgQDS2sAVX3hJkdg8WFD0
oF2lUmM1QSbWrRt70sNgc5dCQmQDuOFlEiWsCsBfP/Edfp1rqp8Fd8TVAb9LZvc+
QBHhA/VCLK7cEMARRauTXcGl7L0YjUZGeWhPn/D8VsIE4RB5gcyvQqLA665+gIYh
0hAZNgDynNxm0OGVfLoGaybqKwKBgQDKln4MxONFH2rqZ7HEhAWI5VsYxglByxBa
FpqiJHuzM+0/65ZOFtFJ/w4uq1eEBTJYRi8ics60wlgvA/x+3HbMgbzSwkrQ2fm5
A6HZTBP3wMHzTazXf0NAkOrnIFLLWBoUbTqQ9XZBoUg5k293WMOsk6bFBvRWujoC
zgvyFqGgaQKBgQCU1yG8dJX+qNsRTe5noEQ6jTvGveTiqXO7Jn4QOchOV3suPXWt
2O+K0FQXaJWVkmkhNWHnhDIHgqI8YcSpxqRYSGj6e3w7j/9ksd95uTcXH1QkXqV6
3fzKKEb+eWef9hehDgUkuk8VC8kzNxp4CUaf5UUp/Zx/X3e+BDt0iHMB3QKBgD8z
FZ2sKm5c78Cymq2Ati1Px8yBs0+YJsDD/neIxCJSl7fyKdCwo5fe/rCmeUXRTTRm
qLupbzzKyDHan4GAC3ufGaXyQN7IsXP7Yxlj93K56oeZess7g2J4EyAJYGrZUEGB
Fd01BjBRPTPg/8wOn/SNl2At3DnWHNTVLLrYPpHJAoGBAJmc2gsP4Z2BQM3rEecb
d11L/WqjSkbqiBSR8sBx9nTRkxdwnntnWZHgQ+93AJZh0YQw1XIF3NfQD5nb3oD3
GrxEp0J0jvPO4k0isQwC0fHgLL1cPbqWzMAcLcv4gBHbGG7BO0GBCb9oa0ofEjLb
+D0rJ6A6sig3CBWjV9LGzEwa
-----END PRIVATE KEY-----
"#;
    const MODULUS_1: &str = "ptyPj5jRDH1kS_aDM3y4I-9GNDV6eeFO4rm84r8QNqVKbhoQOMRy7-sM2vN2LRPbeppw4KLs0ZILvjNx1loB_KZJFWmuQer_eloVAP3_9e-cY6Qhs6ZFMiXUbb_EnQK-qSfOgy4yhRV3-OalskSdkCgQGVMgAztyEx2lj0xjQi-Ooz3mBbzTHWrHQMsKP2bJTOPzAIPhnuKLaxBNMnpRuibb0OCB52Ddsbv9uDlmYC_ljJumLs_-ivVHAgiUKxdcfxNuJXT6iUhy6Omce2RXhi_i6L-7o4V0ir_aZm_QiJc-UQFvr4NjzMBlrJW6Xi7HgivixQa9WPCLHkDZPFvrow";
    const PRIVATE_KEY_2: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpPAP0sjUoEarF
QvsRtGuOFdzVcfwbH/+9ERS9sTvZxmC0wdUa+tzEBKmhtQuUSw6rSqHj5/QRSkAA
SXcs+aF1v6nCEB9R5kjwy3H3h1z/YaInkvRKAEz9T7Z4vKTEWBOMr/dCG2RdygIu
d6d1KMKI/LpOjSDR/VErVzfVqr6JA6iXAVzwldYp6RRSc3dSXDtsYAlazaYBb/Km
somphy1wgCqrnxJDufuvs6RYeOXSMTL5GCxnand2VW/mh4IqKZh1njSFX/NTF9Cp
ekxXhRjTkbmJsKjaC8GJewOFXgA7zGNIbBFrRvftvGM6A1GVFadKUun6687XrfJp
Cd+VPwP9AgMBAAECggEATsC8cIbrgKl0CBbq4irM8FJRMUy5TmAeMLv9pGaRHP8Z
apRW2JbL3DX1QGiRKmGhQmnZG0cKB2+/h8KoQFgsYDCgTUwWXxTkdZWfA9rMlpU3
EeZrYvJv4WNSXS4gGLSJ6GrMi8lWc+S5DimlVjpxCLFe+4XmM4IH3zzXoUkzIGu9
i6MxmQnnrAE+esOQaB8M3F3SjiyfeyKntZfaUQj0FvpgNGRL18JknBaXAflKI9oG
JVHtLjRihLQfkEEkGUIQgMGk2uaFIcV5H2BMFTAUe7cy5/0h5dxc99hnI56UrLDP
Mj7zax/f6aBO/dgWkIEa8EXVOsPno+pQHlgIA3WAqwKBgQDtOIW3OKjJrLVSvH1L
BBqO0D/f1gUNbynP+WDDx7zZORu/0MQ3BnRzPwjj7+63M85Lqti3t1Om0L/Jy5Ur
1C/AmA8C45c2WlyxDrRU4tUblQZwRCxHtyjRyLiXph4ymzzruldCZ4HwFkA/AeYk
Mdw2FTwngFdWtHr5dwSynablxwKBgQC2obFa7uYsFuufEa2auHSK94YJx88orOpx
h4dNmFS/RG26qf8yYwFlC+GV3/CI9IRjQ1oIGJhyqlax3/are4i7/GGhLU/63QAD
1XhN8eJx5jYMB9Ufn9S20FcNW7C8QvuXvvv4EvCIbEtR+oAZRB5Wik3IfyDiBccv
9HuOGZT4GwKBgQDtCjDbb7uBopmhbgXJAvXCxSc+dO6hiPYAApIFsD3t1Zn75xFa
ZpHQYylwEt23pQW8KKDbm030f91VOJ/7ptB8o7VETsVXo53Bsw7RT8RhBl3jqsuQ
cd5RGkASEQVVzjdm2dG94g4+KQ3TqAMfIc+JH1j3o9AiLMBBLQO9s7kFGwKBgHhp
CO7kPbtp7TV2SViOLsCEy8ndA/dUckohyhJd0do9On9sn4XQAtZlS/ktqYASfsqX
WF+oH7LSHdCu0gpjq1YN4yyKHIZQeTcN4oC5bswbtRyfeWOdVHinyg1Tm6W0H/7/
e08m5ZF8nPhSyWxfHgV+sCP1tW9v0dELRv78XNxrAoGAL+guG/KFDWiKr/g3sUaf
U2P1CBpkCRgMRqqR6jW0baf8PPc3JHYnhZCsKTsM0fdGu36XMxLbZUIBKYGUjLnI
Zu73YN0T1jvs6Mwd2wYDu42mz9v9Umxqrrd3iz/JhumKjr/KIevqsgYzL+GQnM5U
+yXOpdUVJBQXS/KOciaxgWs=
-----END PRIVATE KEY-----
"#;
    const MODULUS_2: &str = "qTwD9LI1KBGqxUL7EbRrjhXc1XH8Gx__vREUvbE72cZgtMHVGvrcxASpobULlEsOq0qh4-f0EUpAAEl3LPmhdb-pwhAfUeZI8Mtx94dc_2GiJ5L0SgBM_U-2eLykxFgTjK_3QhtkXcoCLnendSjCiPy6To0g0f1RK1c31aq-iQOolwFc8JXWKekUUnN3Ulw7bGAJWs2mAW_yprKJqYctcIAqq58SQ7n7r7OkWHjl0jEy-RgsZ2p3dlVv5oeCKimYdZ40hV_zUxfQqXpMV4UY05G5ibCo2gvBiXsDhV4AO8xjSGwRa0b37bxjOgNRlRWnSlLp-uvO163yaQnflT8D_Q";
}
