use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn random_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
pub fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[derive(Clone)]
pub enum Vault {
    Kms {
        client: aws_sdk_kms::Client,
        key_id: String,
    },
    Local([u8; 32]),
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    key: String,
    nonce: String,
    ciphertext: String,
}
impl Vault {
    pub fn ephemeral() -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
        Ok(Self::Local(key))
    }
    pub async fn seal(&self, context: &str, value: &impl Serialize) -> anyhow::Result<String> {
        let (key, wrapped) = match self {
            Self::Local(key) => (key.to_vec(), String::new()),
            Self::Kms { client, key_id } => {
                let out = client
                    .generate_data_key()
                    .key_id(key_id)
                    .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                    .encryption_context("connection", context)
                    .send()
                    .await?;
                (
                    out.plaintext
                        .ok_or_else(|| anyhow::anyhow!("KMS missing key"))?
                        .into_inner(),
                    STANDARD.encode(
                        out.ciphertext_blob
                            .ok_or_else(|| anyhow::anyhow!("KMS missing ciphertext"))?
                            .as_ref(),
                    ),
                )
            }
        };
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
        let plaintext = serde_json::to_vec(value)?;
        let ciphertext = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("invalid key"))?
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        Ok(serde_json::to_string(&Envelope {
            key: wrapped,
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })?)
    }
    pub async fn open<T: serde::de::DeserializeOwned>(
        &self,
        context: &str,
        sealed: &str,
    ) -> anyhow::Result<T> {
        let e: Envelope = serde_json::from_str(sealed)?;
        let key = match self {
            Self::Local(k) => k.to_vec(),
            Self::Kms { client, key_id } => client
                .decrypt()
                .key_id(key_id)
                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(STANDARD.decode(e.key)?))
                .encryption_context("connection", context)
                .send()
                .await?
                .plaintext
                .ok_or_else(|| anyhow::anyhow!("KMS missing plaintext"))?
                .into_inner(),
        };
        let nonce = STANDARD.decode(e.nonce)?;
        anyhow::ensure!(nonce.len() == 12, "invalid nonce");
        let bytes = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("invalid key"))?
            .decrypt(
                nonce.as_slice().into(),
                Payload {
                    msg: &STANDARD.decode(e.ciphertext)?,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("decryption failed"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn encrypted_data_is_bound_to_connection() {
        let v = Vault::ephemeral().unwrap();
        let e = v.seal("agent/a", &"secret").await.unwrap();
        assert!(!e.contains("secret"));
        assert_eq!(v.open::<String>("agent/a", &e).await.unwrap(), "secret");
        assert!(v.open::<String>("agent/b", &e).await.is_err());
    }
}
