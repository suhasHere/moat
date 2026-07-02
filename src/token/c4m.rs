use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cat_token::{CatTokenBuilder, CryptographicAlgorithm, Es256Algorithm, MoqtAction, MoqtScopeBuilder};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

use super::{MintRequest, MintedToken, TokenMinter, TokenRole};

const C4M_TOKEN_TYPE: u64 = 6501485;

pub struct C4mMinter {
    signing_key: Es256Algorithm,
    raw_signing_key: SigningKey,
    issuer: String,
    audience: String,
    default_lifetime: u64,
}

impl C4mMinter {
    pub fn new(
        private_key_pem: &str,
        issuer: String,
        audience: String,
        default_lifetime: u64,
    ) -> anyhow::Result<Self> {
        let sk = SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| anyhow::anyhow!("invalid ES256 private key PEM: {e}"))?;
        let vk = sk.verifying_key().clone();
        let signing_key = Es256Algorithm::from_key_pair(sk.clone(), vk);

        Ok(Self {
            signing_key,
            raw_signing_key: sk,
            issuer,
            audience,
            default_lifetime,
        })
    }
}

impl TokenMinter for C4mMinter {
    fn mint(&self, request: &MintRequest) -> anyhow::Result<MintedToken> {
        let lifetime = if request.lifetime_secs > 0 {
            request.lifetime_secs
        } else {
            self.default_lifetime
        };

        let setup_scope = MoqtScopeBuilder::new()
            .action(MoqtAction::ClientSetup)
            .build();

        let mut scopes = vec![setup_scope];

        match request.role {
            TokenRole::Publisher | TokenRole::PubSub => {
                let mut builder = MoqtScopeBuilder::new().publisher();
                for part in &request.namespace_parts {
                    builder = builder.namespace_prefix(part);
                }
                scopes.push(builder.track_prefix(b"").build());
            }
            _ => {}
        }

        match request.role {
            TokenRole::Subscriber | TokenRole::PubSub => {
                let mut builder = MoqtScopeBuilder::new().subscriber();
                for part in &request.namespace_parts {
                    builder = builder.namespace_prefix(part);
                }
                scopes.push(builder.track_prefix(b"").build());
            }
            _ => {}
        }

        let mut token_builder = CatTokenBuilder::new()
            .issuer(&self.issuer)
            .single_audience(&self.audience)
            .subject(&request.subject)
            .expires_in(lifetime as i64);

        for scope in scopes {
            token_builder = token_builder.moqt_scope(scope);
        }

        let token = token_builder.build();

        // Encode as standard COSE_Sign1 CBOR (compatible with catapult/moxygen relay)
        let token_string = encode_cose_sign1(&token, &self.signing_key, &self.raw_signing_key)?;

        Ok(MintedToken {
            token: token_string,
            token_type: C4M_TOKEN_TYPE,
            expires_in: lifetime,
        })
    }

    fn token_type_name(&self) -> &'static str {
        "c4m"
    }
}

/// Encode a CatToken as base64url(COSE_Sign1 CBOR).
/// COSE_Sign1 = [protected_header_bstr, unprotected_header_map, payload_bstr, signature_bstr]
/// Signing input = Sig_structure = ["Signature1", protected_header_bstr, external_aad, payload_bstr]
fn encode_cose_sign1(
    token: &cat_token::CatToken,
    algorithm: &Es256Algorithm,
    raw_key: &SigningKey,
) -> anyhow::Result<String> {
    use cat_token::Cwt;
    use ciborium::Value;

    let alg_id = algorithm.algorithm_id();

    // Build protected header CBOR
    let cwt = Cwt::new(alg_id, token.clone());
    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, Value::Integer(alg_id.into()));
    if let Some(ref typ) = cwt.header.typ {
        header_map.insert(16i64, Value::Text(typ.clone()));
    }

    let header_cbor_map: Vec<(Value, Value)> = header_map
        .into_iter()
        .map(|(k, v)| (Value::Integer(k.into()), v))
        .collect();

    let mut protected_header = Vec::new();
    ciborium::ser::into_writer(&Value::Map(header_cbor_map), &mut protected_header)
        .map_err(|e| anyhow::anyhow!("header CBOR encode failed: {e}"))?;

    // Build payload CBOR, then fix CLAIM_MOQT key (cat-token uses 327, catapult expects 65000)
    let payload_raw = cwt
        .encode_payload()
        .map_err(|e| anyhow::anyhow!("payload encode failed: {e}"))?;

    let payload = remap_claim_key(&payload_raw, 327, 65000)?;

    // Build COSE Sig_structure for COSE_Sign1:
    // ["Signature1", protected_header_bstr, external_aad_bstr, payload_bstr]
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_header.clone()),
        Value::Bytes(vec![]), // empty external AAD
        Value::Bytes(payload.clone()),
    ]);

    let mut signing_input = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut signing_input)
        .map_err(|e| anyhow::anyhow!("sig_structure CBOR encode failed: {e}"))?;

    // Sign with ES256 (P-256 ECDSA) — output DER-encoded signature for OpenSSL compatibility
    let signature: Signature = raw_key.sign(&signing_input);
    let sig_der = signature.to_der();

    // Build COSE_Sign1 structure:
    // [bstr(protected_header), map(unprotected_header), bstr(payload), bstr(signature)]
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header),
        Value::Map(vec![]), // empty unprotected header
        Value::Bytes(payload),
        Value::Bytes(sig_der.as_bytes().to_vec()),
    ]);

    let mut cose_bytes = Vec::new();
    ciborium::ser::into_writer(&cose_sign1, &mut cose_bytes)
        .map_err(|e| anyhow::anyhow!("COSE_Sign1 CBOR encode failed: {e}"))?;

    // Return as base64url (single blob, no dots)
    Ok(URL_SAFE_NO_PAD.encode(&cose_bytes))
}

/// Decode a CBOR map, rename key `from` to `to`, and bstr-wrap its value
/// (catapult expects the MoQT claim as a bytestring containing CBOR).
fn remap_claim_key(cbor: &[u8], from: i64, to: i64) -> anyhow::Result<Vec<u8>> {
    use ciborium::Value;

    let value: Value = ciborium::de::from_reader(cbor)
        .map_err(|e| anyhow::anyhow!("CBOR decode for key remap failed: {e}"))?;

    let map = match value {
        Value::Map(entries) => entries,
        _ => anyhow::bail!("expected CBOR map in payload"),
    };

    let remapped: Vec<(Value, Value)> = map
        .into_iter()
        .map(|(k, v)| {
            if k == Value::Integer(from.into()) {
                // Serialize the array value to CBOR bytes, then wrap as bstr
                let mut inner = Vec::new();
                ciborium::ser::into_writer(&v, &mut inner).unwrap();
                (Value::Integer(to.into()), Value::Bytes(inner))
            } else {
                (k, v)
            }
        })
        .collect();

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(remapped), &mut out)
        .map_err(|e| anyhow::anyhow!("CBOR re-encode after key remap failed: {e}"))?;
    Ok(out)
}
