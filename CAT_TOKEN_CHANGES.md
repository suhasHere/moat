# cat-token API changes needed

## 1. Add `from_private_key_pem` to `Es256Algorithm`

Currently the crate only exposes:
- `new_with_key_pair()` — generates a fresh random key pair
- `from_key_pair(signing_key, verifying_key)` — from pre-constructed p256 types
- `from_public_key_pem(pem)` — verifier only
- `from_public_key_der(der)` — verifier only

**Missing:** `from_private_key_pem(pem) -> Result<Self, CatError>`

This would load a PEM-encoded PKCS#8 private key and derive the verifying key
from it, returning a full signing+verifying `Es256Algorithm`. This is the most
natural way for a token service to load its signing key from a file.

**Workaround (current):** Parse with `p256::ecdsa::SigningKey::from_pkcs8_pem`
then call `Es256Algorithm::from_key_pair(sk, sk.verifying_key().clone())`.
Works but forces the consumer to depend on `p256` directly.

## 2. `expires_in` should accept `u64` (or impl `Into<i64>`)

`CatTokenBuilder::expires_in(self, seconds: i64)` takes `i64`. Lifetimes are
always positive — accepting `u64` (or `impl Into<i64>`) would be more ergonomic
and avoid the `as i64` cast at call sites.

## 3. Consider re-exporting `p256::ecdsa::{SigningKey, VerifyingKey}`

The `from_key_pair` constructor takes `p256` types but doesn't re-export them.
Consumers must add `p256` as a direct dependency at the exact same version to
avoid type mismatches. Either re-export the types or accept `&[u8]` (raw key bytes).

## 4. (Nice to have) Add `from_private_key_der`

Symmetric with `from_public_key_der`. Some deployments store keys in DER format
(e.g., fetched from secret managers as raw bytes).
