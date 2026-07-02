use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cat_token::{CatTokenBuilder, CryptographicAlgorithm, Es256Algorithm};
use ciborium::Value;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

use super::{MintRequest, MintedToken, TokenMinter, TokenRole};

const C4M_TOKEN_TYPE: u64 = 6501485;
const CLAIM_MOQT: i64 = 65000;

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

        // The relay canonicalizes namespaces as [4-byte-BE-len][field]... for each element,
        // then applies match rules against that single byte string.
        let canonical_ns = canonical_namespace(&request.namespace_parts);

        let mut moqt_scopes: Vec<Value> = Vec::new();

        // Scope 0: ClientSetup (no namespace constraint)
        moqt_scopes.push(Value::Array(vec![
            Value::Array(vec![Value::Integer(0.into())]),
        ]));

        // Publisher scope: actions [2 (PublishNamespace), 6 (Publish)]
        if matches!(request.role, TokenRole::Publisher | TokenRole::PubSub) {
            moqt_scopes.push(build_scope(&[2, 6], &canonical_ns));
        }

        // Subscriber scope: actions [3 (SubscribeNamespace), 4 (Subscribe), 7 (Fetch)]
        if matches!(request.role, TokenRole::Subscriber | TokenRole::PubSub) {
            moqt_scopes.push(build_scope(&[3, 4, 7], &canonical_ns));
        }

        // Build base token (without MoQT scopes — we inject those manually)
        let token = CatTokenBuilder::new()
            .issuer(&self.issuer)
            .single_audience(&self.audience)
            .subject(&request.subject)
            .expires_in(lifetime as i64)
            .build();

        let token_string =
            encode_cose_sign1(&token, &self.signing_key, &self.raw_signing_key, &moqt_scopes)?;

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

/// Build a scope entry: [[actions...], [ns_prefix_match], track_match]
fn build_scope(actions: &[i64], canonical_ns: &[u8]) -> Value {
    let actions_arr = Value::Array(actions.iter().map(|&a| Value::Integer(a.into())).collect());
    // Single prefix match on the canonical namespace bytes
    let ns_match = Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()), // PREFIX match type
        Value::Bytes(canonical_ns.to_vec()),
    ])]);
    // Empty track match = matches any track
    let track_match = Value::Bytes(vec![]);
    Value::Array(vec![actions_arr, ns_match, track_match])
}

/// Encode namespace parts as the relay's canonical form: [4-byte-BE-len][bytes]...
fn canonical_namespace(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        let len = part.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Encode a CatToken + MoQT scopes as base64url(COSE_Sign1 CBOR).
fn encode_cose_sign1(
    token: &cat_token::CatToken,
    algorithm: &Es256Algorithm,
    raw_key: &SigningKey,
    moqt_scopes: &[Value],
) -> anyhow::Result<String> {
    use cat_token::Cwt;

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

    // Build payload: use cat-token for standard CWT claims, then inject MoQT scopes
    let payload = build_payload(&cwt, moqt_scopes)?;

    // Build COSE Sig_structure for signing:
    // ["Signature1", bstr(protected_header), bstr(external_aad), bstr(payload)]
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_header.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.clone()),
    ]);

    let mut signing_input = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut signing_input)
        .map_err(|e| anyhow::anyhow!("sig_structure CBOR encode failed: {e}"))?;

    // Sign with ES256 — DER-encoded for OpenSSL compatibility
    let signature: Signature = raw_key.sign(&signing_input);
    let sig_der = signature.to_der();

    // COSE_Sign1 = [bstr(protected), map(unprotected), bstr(payload), bstr(signature)]
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header),
        Value::Map(vec![]),
        Value::Bytes(payload),
        Value::Bytes(sig_der.as_bytes().to_vec()),
    ]);

    let mut cose_bytes = Vec::new();
    ciborium::ser::into_writer(&cose_sign1, &mut cose_bytes)
        .map_err(|e| anyhow::anyhow!("COSE_Sign1 CBOR encode failed: {e}"))?;

    Ok(URL_SAFE_NO_PAD.encode(&cose_bytes))
}

/// Build the CWT payload CBOR map with standard claims + MoQT scopes (key 65000, bstr-wrapped).
fn build_payload(cwt: &cat_token::Cwt, moqt_scopes: &[Value]) -> anyhow::Result<Vec<u8>> {
    // Get base claims from cat-token (excludes MoQT since we didn't add any scopes to token)
    let base_raw = cwt
        .encode_payload()
        .map_err(|e| anyhow::anyhow!("payload encode failed: {e}"))?;

    let base: Value = ciborium::de::from_reader(&base_raw[..])
        .map_err(|e| anyhow::anyhow!("CBOR decode payload failed: {e}"))?;

    let mut map = match base {
        Value::Map(entries) => entries,
        _ => anyhow::bail!("expected CBOR map in payload"),
    };

    // Encode MoQT scopes array to bytes, then add as bstr under key 65000
    let scopes_value = Value::Array(moqt_scopes.to_vec());
    let mut scopes_bytes = Vec::new();
    ciborium::ser::into_writer(&scopes_value, &mut scopes_bytes)
        .map_err(|e| anyhow::anyhow!("MoQT scopes CBOR encode failed: {e}"))?;

    map.push((
        Value::Integer(CLAIM_MOQT.into()),
        Value::Bytes(scopes_bytes),
    ));

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out)
        .map_err(|e| anyhow::anyhow!("payload CBOR encode failed: {e}"))?;
    Ok(out)
}
