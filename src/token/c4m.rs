use cat_token::{
    CatTokenBuilder, Es256Algorithm, MoqtAction, MoqtScopeBuilder, encode_token,
};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

use super::{MintRequest, MintedToken, TokenMinter, TokenRole};

const C4M_TOKEN_TYPE: u64 = 6501485;

pub struct C4mMinter {
    signing_key: Es256Algorithm,
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
        let signing_key = Es256Algorithm::from_key_pair(sk, vk);

        Ok(Self {
            signing_key,
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
        let token_string = encode_token(&token, &self.signing_key)
            .map_err(|e| anyhow::anyhow!("token encoding failed: {e}"))?;

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
