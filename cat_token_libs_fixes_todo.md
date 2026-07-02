# CAT Token Libraries — Fixes Needed

## cat-token (Rust crate, v0.1.3)

1. **CLAIM_MOQT key value**: Currently uses `327`. Should be `65000` (or whatever value the final RFC assigns). File: `src/claims.rs`

2. **CLAIM_MOQT_REVAL key value**: Currently uses `328`. Should be `65001`. File: `src/claims.rs`

3. **MoQT claim encoding**: `Cwt::encode_payload()` encodes the MoQT scopes as a direct CBOR array in the claims map. Should encode as a **bytestring** wrapping the CBOR-serialized array (bstr-wrapped). File: `src/cwt.rs`, line 262 — change from:
   ```rust
   claims_map.insert(CLAIM_MOQT, Value::Array(scopes_array));
   ```
   to:
   ```rust
   let mut moqt_bytes = Vec::new();
   ciborium::ser::into_writer(&Value::Array(scopes_array), &mut moqt_bytes)?;
   claims_map.insert(CLAIM_MOQT, Value::Bytes(moqt_bytes));
   ```

4. **Namespace match encoding**: `MoqtScopeBuilder::namespace_prefix()` adds each namespace element as a separate prefix match condition in the namespace_matches array (e.g., `[[1, b"mocha"], [1, b"auth-demo"]]`). The relay's `allowsImpl()` canonicalizes the full namespace tuple as `[4-byte-BE-length][bytes]...` for each element, then applies ALL match rules against that single concatenated string. This means per-element prefix matches will never match. 
   
   **Fix needed**: `MoqtScopeBuilder` should encode the namespace as a single prefix match on the canonical form (length-prefixed concatenation of all elements), not as multiple per-element matches. Alternatively, document that the namespace match is against the canonical binary form and let the user build the match manually.

## catapult (C++ library)

1. **CLAIM_MOQT key value**: Uses `65000`. This is a provisional value chosen to "avoid conflicts." Once the RFC assigns a final value, update. File: `include/catapult/moqt_claims.hpp`

2. **MoQT claim decoding**: Expects MoQT value as a bytestring (`cbor_isa_bytestring`), then parses the inner bytes as CBOR. This is non-standard — CWT claims should be typed CBOR values directly in the map, not bstr-wrapped. Should also accept a direct CBOR array for spec compliance. File: `src/cwt.cpp`, around line 715:
   ```cpp
   case CLAIM_MOQT:
       // Currently only handles bytestring. Should also handle direct array:
       if (cbor_isa_bytestring(value_item)) {
           // existing path...
       } else if (cbor_isa_array(value_item)) {
           // parse directly as scopes array
       }
   ```

3. **Namespace canonicalization mismatch with spec**: `Auth.cpp::canonicalNamespace()` converts namespace tuples to `[4-byte-BE-len][field]...` format, then the `allowsImpl()` function applies namespace match rules against this canonical byte string. But the C4M spec (draft-law-moq-cat4moqt) defines namespace matching as per-element binary matching — each element in the `namespace_matches` array should match the corresponding element in the namespace tuple independently.
   
   **Fix needed**: `allowsImpl()` should iterate over namespace elements and match rules in parallel (element-by-element), not flatten the namespace into a single canonical string and apply all rules against it.

4. **ECDSA signature format**: The `crypto.cpp` verification uses OpenSSL `EVP_DigestVerify` which expects DER-encoded signatures (variable 68-72 bytes). The C4M/COSE spec uses raw `r||s` format (fixed 64 bytes for ES256). Catapult should convert raw signatures to DER before passing to OpenSSL, or use a verification path that accepts raw format.

## Workarounds in moat (current state)

Until both libraries are fixed, `moat/src/token/c4m.rs` applies these workarounds:

1. **Bypasses cat-token MoQT scope encoding entirely** — builds MoQT scopes CBOR manually with correct key (65000) and bstr wrapping
2. **Canonical namespace encoding** — encodes namespace as `[4-byte-BE-len][field]...` to match relay's `canonicalNamespace()` function, then uses a single prefix match
3. **DER signature encoding** — uses `signature.to_der()` instead of raw `r||s`
4. **Standard CWT claims still use cat-token** — issuer, audience, subject, expiry via `CatTokenBuilder` + `Cwt::encode_payload()`

These workarounds can be removed once cat-token and catapult are aligned.

## Summary of incompatibilities

| Issue | cat-token (Rust) | catapult (C++) | Spec (C4M draft) |
|-------|-----------------|----------------|-------------------|
| MOQT claim key | 327 | 65000 | TBD (unassigned) |
| MOQT claim encoding | direct CBOR array | bstr-wrapped CBOR | direct CBOR array |
| Namespace matching | per-element prefix matches | canonical-form single-string match | per-element |
| ECDSA signature | raw r\|\|s (64 bytes) | DER (68-72 bytes) | raw r\|\|s |
