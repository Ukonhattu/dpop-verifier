
# Dpop Verifier

A tiny DPoP proof verifier for Rust:
- ES256 over P-256 only (per spec’s MTI)
- Manual claim checks (htm/htu/iat/ath)
- Pluggable replay store (DB/Redis/etc.)
- Optional Actix helper to canonicalize request URL

Not yet implemented, but planned:
- EdDSA/PS256 support
- DPoP-Nonce support

Made this small crate for my own needs. If you feel it's lacking or is missing something and/or does not actually follow the spec etc. feel free to open an issue.

## Install

Crates.io
```toml
[dependencies]
dpop-verifier = "0.1"
```

Git 
```toml
[dependencies]
dpop-verifier = { git = "https://github.com/ukonhattu/dpop-verifier"}
```

## Quick start (framework-agnostic)

```rust
use dpop_verifier::{verify_proof, VerifyOptions, ReplayStore, ReplayContext, DpopError};

struct MyStore;

#[async_trait::async_trait]
impl ReplayStore for MyStore {
    async fn insert_once(
        &mut self,
        _jti_hash: [u8; 32],
        _ctx: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        // Return true if first time seeing this jti_hash within your TTL, else false.
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Read the DPoP header value from the inbound HTTP request
    let dpop = "..."; // compact JWS from `DPoP:` header

    // 2) Provide the *externally visible* request target (scheme/host[:port]/path) and method
    let expected_htu = "https://example.com/api/token";
    let expected_htm = "POST";

    // 3) If verifying at a Resource Server with an access token, pass it here (binds `ath`)
    let maybe_access_token = None::<&str>;

    // 4) Verify proof and record its `jti` (via your `ReplayStore`)
    let mut store = MyStore;
    let verified = verify_proof(
        &mut store,
        dpop,
        expected_htu,
        expected_htm,
        maybe_access_token,
        VerifyOptions::default(), // 300s max age, 5s future skew
    ).await?;

    println!("DPoP key thumbprint (jkt): {}", verified.jkt);
    Ok(())
}
```

## Actix helpers

Enable ["actix-web"] feature

```rust
use dpop_verifier::{verify_proof, VerifyOptions};
use dpop_verifier::actix_helpers::{dpop_header_str, expected_htu_from_actix};

async fn handler(req: actix_web::HttpRequest) -> actix_web::Result<()> {
    let dpop = dpop_header_str(&req).map_err(|_| actix_web::error::ErrorUnauthorized("DPoP"))?;
    let expected_htu = expected_htu_from_actix(&req, /* trust_proxies */ false); //(see proxy trust note)
    let expected_htm = req.method().as_str();

    // ... get your ReplayStore
    // let mut store = ...

    verify_proof(&mut store, dpop, &expected_htu, expected_htm, None, VerifyOptions::default())
        .await
        .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?;

    Ok(())
}
```

> Proxy trust note: Only use X-Forwarded-* (true option) when you explicitly trust your proxy/load-balancer. Otherwise prefer connection info (false option).

## Api Surface
```rust
pub async fn verify_proof<S: ReplayStore + ?Sized>(
    store: &mut S,
    dpop_compact_jws: &str,
    expected_htu: &str,
    expected_htm: &str,
    maybe_access_token: Option<&str>,
    opts: VerifyOptions,             // { max_age_secs: i64, future_skew_secs: i64 } (Default: 300 / 5..120)
) -> Result<VerifiedDpop, DpopError>;

pub struct VerifiedDpop {
    pub jkt: String, // JWK SHA-256 thumbprint (base64url, no pad)
    pub jti: String,
    pub iat: i64,
}

```

### Replay store
Provide a store that return `true` only the first time it sees jti withint TTL window:
```rust
#[async_trait::async_trait]
pub trait ReplayStore {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],         // SHA-256 of jti
        ctx: ReplayContext<'_>,     // { jkt, htm, htu, iat }
    ) -> Result<bool, DpopError>;
}
```

### Actix helpers
```

pub fn dpop_header_str<'a>(req: &'a actix_web::HttpRequest) -> Result<&'a str, DpopError>;
pub fn expected_htu_from_actix(req: &actix_web::HttpRequest, trust_proxies: bool) -> String;
```

## Issues

- Issues & PRs welcome, please notify me if you find any security vulnerability
- Feel like the crate is missing something, butchers the spec, is not working as it should? -> Make an issue and I will investigate

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

