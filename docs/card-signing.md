# Agent Card signing

Every newly created agent has a signed public card. Metadata and skill writes
publish a replacement automatically. No extra request parameter or owner action
is needed. The existing owner bearer key still authorizes management/invocation;
it is never a signing key. Signing attests that Aithos published the card. It does
not verify an anonymous owner's identity or endorse the agent's skills.

Cards use A2A 1.0 JWS `signatures`, ES256, a protected `kid`, `typ: JOSE` and `jku`.
The public key set is `/.well-known/jwks.json`. Clients must establish trust in
that issuer independently, not follow arbitrary card-supplied key URLs. The
signature covers all public card content except `signatures`; it does not encrypt
anything, authorize invocation, sign task outputs, or establish freshness.

## Publication and failure handling

`src/cards.rs` isolates signing behind `CardSigner`. Production uses the official
AWS SDK with a dedicated P-256 SIGN_VERIFY KMS key; its private key never leaves
KMS. The API role can Sign with ES256 and GetPublicKey only for configured keys.
The worker has neither permission. Local mode uses an ephemeral P-256 key.

Before signing, normalize the public card using the pinned schema in
`aithos-a2a-card` 0.2.0, then validate and canonicalize through that library's RFC
8785 implementation (`serde_jcs`). Required and explicitly present optional
fields retain their default values. Implicit defaults are omitted; arbitrary
Struct data is preserved. In particular, the wire-compatible `{"list":[]}`
security scope wrapper becomes `{}` in the signing payload. Consumers must apply
A2A §8.4.1 normalization rather than hash raw JSON or use a plain JWT decoder.
Do not change the wire contract to accommodate an older nonconforming parser.

KMS receives SHA-256 of the full JWS signing input using MessageType DIGEST, so
cards above the RAW API's 4 KiB limit work. RustCrypto p256 converts KMS's DER
signature into JOSE's 64-byte r||s representation. Signed snapshots are bounded
to 300,000 encoded JSON bytes, below DynamoDB's 400 KiB record limit.

The META version is the shared concurrency fence. Read it before skills, build
and sign the proposed snapshot, then transactionally save META, the changed skill
(if any), and CARD. Concurrent changes return 409 for the caller to retry; failed
signing returns 503 without committing configuration. A failed creation returns
no usable owner key or partial agent. Network loss after a successful creation
still has the existing one-time-owner-key limitation; this does not add creation
idempotency or key recovery.

Public GETs read stored CARD snapshots, never call KMS, and retain the API's
`Cache-Control: no-store` policy. Deleted agents return 404. Legacy agents without
a snapshot return 503 `card_publication_pending` until migrated; there is no
unsigned fallback. Creating an agent with zero skills signs its initial metadata;
it does not make the agent ready for useful invocation.

## Deployment, backfill and global configuration changes

1. Run Rust tests, Clippy, Python interoperability and Terraform validation.
2. Build the Linux Lambda artifact and the local operator binary from the same
   revision: `bash scripts/build-lambda.sh` and `cargo build --locked`.
3. Apply the reviewed Terraform plan. It adds a dedicated KMS key, scoped API IAM
   policy, signing configuration and the matching Lambda code. Do not deploy
   code alone before the signing environment exists.
4. Immediately run the operator backfill:

   ```sh
   python3 scripts/with-env.py python3 scripts/publish-cards.py
   ```

   This paginated scan projects only META partition keys, skips deleted agents,
   reads agent metadata/skills, and republishes signed cards with transaction
   conflict checks. It does not read connector credentials or invoke any agent.
   Safe to rerun if interrupted. Existing public card reads can return 503 during
   the initial migration window. New agents are signed immediately.
5. Verify an existing card and run the disposable smoke test:

   ```sh
   .build/interop/bin/python scripts/smoke.py https://agents.aithos.app --verify-signatures
   ```

   This checks real KMS signing on creation and updates, then deletes the test
   agent. No model/calendar calls are made. Repeat publication
   whenever APP_PUBLIC_URL, advertised authentication settings, the signing key,
   or the card serializer changes. Stored cards do not silently track those
   settings. A global rollout is per agent, not atomic across the fleet.

## Key rotation and revocation

KMS asymmetric keys require explicit rotation; automatic symmetric-key rotation
is not applicable. The initial Terraform key is protected against destruction.

1. Provision a new P-256 SIGN_VERIFY KMS key in the same account/region through
   reviewed infrastructure. Add its immutable ARN to `card_retained_key_arns` and
   apply to publish the new verification key before signing with it.
2. Set `card_signing_key_arn` to the new immutable key ARN and keep the old ARN in
   `card_retained_key_arns`. Apply and run `scripts/publish-cards.py`.
3. Verify that all live cards use the new kid. Retain the previous public key for
   the agreed client transition period, then remove it from the published JWKS.
   Coordinate disabling/scheduling deletion of retired keys separately.

In a compromise, replace the key, republish cards, and revoke the old kid without
normal overlap; notify trusting clients to refresh/reject it. A signature alone
cannot revoke already downloaded cards or prevent replay. Clients must fetch the
current card/key set and enforce their trust/freshness policy. HTTP no-store
reduces caching but is not a cryptographic expiration mechanism.

## Verification

Install `scripts/interop-requirements.txt` in the project Python environment:

```sh
.build/interop/bin/python scripts/verify-card.py \
  https://agents.aithos.app/agents/AGENT_ID/agent-card.json \
  --trusted-origin https://agents.aithos.app
```

This uses official Python A2A descriptors for field normalization, Python RFC
8785 canonicalization and cryptography/OpenSSL to verify independently of Rust.
It never needs an owner key, follows no redirects and fetches keys only from the
explicitly trusted origin. `scripts/a2a-interop.py --start-server` also verifies
signatures and rejects tampering alongside the existing SDK discovery/invocation
checks. The verifier is a diagnostic for this service's single-signature ES256
profile, not a universal A2A trust engine.

Standing KMS key and per-signature request charges are infrastructure costs,
outside the shared model-spend cap. There is no KMS signing charge on card reads.
