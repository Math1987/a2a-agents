//! A2A card publication uses a platform key, never an owner's bearer credential.
//! Public reads serve a snapshot; signing happens only on configuration writes.
use a2a_card::schema::{AGENT_CARD, Behavior, Msg, Ty};
use anyhow::{Context, ensure};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer},
    pkcs8::DecodePublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[async_trait]
pub trait CardSigner: Send + Sync {
    fn kid(&self) -> &str;
    /// Returns the 64-byte JOSE ES256 r || s representation.
    async fn sign(&self, input: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub struct CardSigning {
    signer: Arc<dyn CardSigner>,
    jwks: Value,
}
impl CardSigning {
    pub fn new(signer: Arc<dyn CardSigner>, keys: Vec<Value>) -> anyhow::Result<Self> {
        ensure!(
            keys.iter().any(|key| key["kid"] == signer.kid()),
            "active key missing from JWKS"
        );
        Ok(Self {
            signer,
            jwks: json!({"keys":keys}),
        })
    }
    pub fn jwks(&self) -> Value {
        self.jwks.clone()
    }
    pub fn local() -> anyhow::Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("signing entropy unavailable"))?;
        let key = SigningKey::from_slice(&bytes)?;
        let kid = uuid::Uuid::new_v4().to_string();
        let jwk = public_jwk(key.verifying_key(), &kid);
        Self::new(Arc::new(LocalSigner { key, kid }), vec![jwk])
    }
    pub async fn kms(
        client: aws_sdk_kms::Client,
        active: String,
        retained: Vec<String>,
    ) -> anyhow::Result<Self> {
        // Use immutable key ARNs/IDs, never an alias that could change between
        // GetPublicKey and Sign. Resolve the active key once at startup.
        let mut keys = Vec::new();
        let mut active_id = None;
        for id in std::iter::once(active).chain(retained) {
            let result = client.get_public_key().key_id(id).send().await?;
            ensure!(
                result.key_spec() == Some(&aws_sdk_kms::types::KeySpec::EccNistP256),
                "expected P-256 key"
            );
            ensure!(
                result.key_usage() == Some(&aws_sdk_kms::types::KeyUsageType::SignVerify),
                "expected signing key"
            );
            let kid = result.key_id().context("missing key ID")?.to_owned();
            let key = VerifyingKey::from_public_key_der(
                result.public_key().context("missing public key")?.as_ref(),
            )?;
            if active_id.is_none() {
                active_id = Some(kid.clone());
            }
            if !keys.iter().any(|key: &Value| key["kid"] == kid) {
                keys.push(public_jwk(&key, &kid));
            }
        }
        Self::new(
            Arc::new(KmsSigner {
                client,
                kid: active_id.context("missing active key")?,
            }),
            keys,
        )
    }
    pub async fn sign_card(&self, mut card: Value, public_url: &str) -> anyhow::Result<Value> {
        let payload = signing_payload(&card)?;
        let protected = B64.encode(serde_json::to_vec(&json!({
            "alg":"ES256", "typ":"JOSE", "kid":self.signer.kid(),
            "jku":format!("{public_url}/.well-known/jwks.json")
        }))?);
        let input = a2a_card::canonical::signing_input(&protected, &payload);
        let signature = self.signer.sign(&input).await?;
        ensure!(signature.len() == 64, "invalid ES256 signature length");
        card["signatures"] = json!([{"protected":protected,"signature":B64.encode(signature)}]);
        // Bound the snapshot below DynamoDB's 400 KiB limit, including row overhead.
        ensure!(
            serde_json::to_vec(&card)?.len() <= 300_000,
            "agent card too large"
        );
        Ok(card)
    }
}

fn public_jwk(key: &VerifyingKey, kid: &str) -> Value {
    let point = key.to_encoded_point(false);
    json!({"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":kid,
        "x":B64.encode(point.x().expect("uncompressed P-256 x")),
        "y":B64.encode(point.y().expect("uncompressed P-256 y"))})
}
struct LocalSigner {
    key: SigningKey,
    kid: String,
}
#[async_trait]
impl CardSigner for LocalSigner {
    fn kid(&self) -> &str {
        &self.kid
    }
    async fn sign(&self, input: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature: Signature = self.key.sign(input);
        Ok(signature.to_bytes().to_vec())
    }
}
struct KmsSigner {
    client: aws_sdk_kms::Client,
    kid: String,
}
#[async_trait]
impl CardSigner for KmsSigner {
    fn kid(&self) -> &str {
        &self.kid
    }
    async fn sign(&self, input: &[u8]) -> anyhow::Result<Vec<u8>> {
        use aws_sdk_kms::{
            primitives::Blob,
            types::{MessageType, SigningAlgorithmSpec},
        };
        // Hash the full JWS signing input once, allowing cards beyond KMS's 4 KiB RAW limit.
        let result = self
            .client
            .sign()
            .key_id(&self.kid)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Digest)
            .message(Blob::new(Sha256::digest(input).to_vec()))
            .send()
            .await?;
        Ok(
            Signature::from_der(result.signature().context("missing signature")?.as_ref())?
                .to_bytes()
                .to_vec(),
        )
    }
}

/// Normalize using the existing pinned A2A schema, not a second hand-written
/// field table. Preserve optional defaults, required defaults and arbitrary Struct
/// contents. The served card retains SDK-compatible StringList {"list":[]}.
pub fn signing_payload(card: &Value) -> anyhow::Result<Vec<u8>> {
    let mut normalized = card.clone();
    normalized
        .as_object_mut()
        .context("card must be an object")?
        .remove("signatures");
    normalize_message(&mut normalized, &AGENT_CARD);
    Ok(a2a_card::validate_value(normalized)?.signing_payload()?)
}
fn normalize_message(value: &mut Value, schema: &Msg) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for field in schema.fields {
        let Some(value) = object.get_mut(field.name) else {
            continue;
        };
        let default = match &field.ty {
            Ty::Str => value.as_str() == Some(""),
            Ty::Bool => value.as_bool() == Some(false),
            Ty::Repeated(_) => value.as_array().is_some_and(Vec::is_empty),
            Ty::Map(_) => value.as_object().is_some_and(serde_json::Map::is_empty),
            Ty::Msg(_) | Ty::Struct => false,
        };
        if field.behavior == Behavior::Implicit && default {
            object.remove(field.name);
        } else {
            normalize_type(value, &field.ty);
        }
    }
}
fn normalize_type(value: &mut Value, ty: &Ty) {
    match ty {
        Ty::Msg(schema) => normalize_message(value, schema),
        Ty::Repeated(inner) => {
            if let Some(items) = value.as_array_mut() {
                for item in items {
                    normalize_type(item, inner);
                }
            }
        }
        Ty::Map(inner) => {
            if let Some(items) = value.as_object_mut() {
                for item in items.values_mut() {
                    normalize_type(item, inner);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::signature::{Verifier, hazmat::PrehashSigner},
        pkcs8::EncodePublicKey,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method},
    };

    #[test]
    fn normalization_preserves_required_optional_and_struct_fields() {
        let card = json!({
            "name":"Example", "description":"", "version":"1", "skills":[],
            "supportedInterfaces":[{"url":"https://example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
            "defaultInputModes":["text/plain"], "defaultOutputModes":["text/plain"],
            "capabilities":{"streaming":false,"extensions":[{"uri":"https://example.com/ext","required":false,"params":{"empty":[],"false":false}}]},
            "securityRequirements":[{"schemes":{"owner":{"list":[]}}}]
        });
        let payload: Value = serde_json::from_slice(&signing_payload(&card).unwrap()).unwrap();
        assert_eq!(payload["description"], "");
        assert_eq!(payload["skills"], json!([]));
        assert_eq!(payload["capabilities"]["streaming"], false);
        assert!(
            payload["capabilities"]["extensions"][0]
                .get("required")
                .is_none()
        );
        assert_eq!(
            payload["capabilities"]["extensions"][0]["params"],
            json!({"empty":[],"false":false})
        );
        assert_eq!(
            payload["securityRequirements"][0]["schemes"]["owner"],
            json!({})
        );
        let mut other = card.clone();
        other["signatures"] = json!([{"ignored":"signatures do not sign each other"}]);
        other["securityRequirements"][0]["schemes"]["owner"] = json!({});
        assert_eq!(
            signing_payload(&card).unwrap(),
            signing_payload(&other).unwrap()
        );
    }

    #[tokio::test]
    async fn kms_sdk_hashes_full_jws_input_and_converts_der_signature() {
        use base64::engine::general_purpose::STANDARD;
        let server = MockServer::start().await;
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let der = key.verifying_key().to_public_key_der().unwrap();
        let arn = "arn:aws:kms:eu-west-3:123456789012:key/test";
        Mock::given(method("POST"))
            .and(header("x-amz-target", "TrentService.GetPublicKey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "KeyId":arn,"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY",
                "PublicKey":STANDARD.encode(der.as_bytes()),"SigningAlgorithms":["ECDSA_SHA_256"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let input = vec![b'x'; 10_000];
        let expected = Sha256::digest(&input).to_vec();
        Mock::given(method("POST")).and(header("x-amz-target", "TrentService.Sign"))
            .respond_with(move |req: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                assert_eq!(body["KeyId"], arn);
                assert_eq!(body["MessageType"], "DIGEST");
                assert_eq!(body["SigningAlgorithm"], "ECDSA_SHA_256");
                let digest = STANDARD.decode(body["Message"].as_str().unwrap()).unwrap();
                assert_eq!(digest, expected);
                let signature: Signature = key.sign_prehash(&digest).unwrap();
                ResponseTemplate::new(200).set_body_json(json!({"KeyId":arn,"SigningAlgorithm":"ECDSA_SHA_256","Signature":STANDARD.encode(signature.to_der().as_bytes())}))
            }).expect(1).mount(&server).await;
        let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new("eu-west-3"))
            .credentials_provider(aws_sdk_kms::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(server.uri())
            .load()
            .await;
        let signing = CardSigning::kms(
            aws_sdk_kms::Client::new(&cfg),
            "alias/resolved-once".into(),
            vec![],
        )
        .await
        .unwrap();
        assert_eq!(signing.jwks()["keys"][0]["kid"], arn);
        let raw = signing.signer.sign(&input).await.unwrap();
        assert_eq!(raw.len(), 64);
        let public = VerifyingKey::from_public_key_der(der.as_bytes()).unwrap();
        public
            .verify(&input, &Signature::from_slice(&raw).unwrap())
            .unwrap();
    }
}
