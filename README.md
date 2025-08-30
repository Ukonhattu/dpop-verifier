
# Dpop Verifier

A tiny DPoP proof verifier for Rust:
- ES256 over P-256 only (per spec’s MTI)
- Manual claim checks (htm/htu/iat/ath)
- Pluggable replay store (DB/Redis/etc.)
- Optional Actix helper to canonicalize request URL

## Quick start

```toml
[dependencies]
oauth-dpop = { git = "https://github.com/ukonhattu/dpop-verifier"}
```
```rust
use oauth_dpop::{verify_proof, VerifyOptions, ReplayStore, ReplayContext, DpopError};

# struct MyStore;
# #[async_trait::async_trait]
# impl ReplayStore for MyStore {
#   async fn insert_once(&mut self, _jti_hash: [u8;32], _ctx: ReplayContext<'_>) -> Result<bool, DpopError> { Ok(true) }
# }

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let dpop = "..."; // compact JWS from DPoP header
let expected_htu = "https://example.com/api/token";
let expected_htm = "POST";
let mut store = MyStore;

let verified = verify_proof(&mut store, dpop, expected_htu, expected_htm, None, VerifyOptions::default()).await?;
println!("jkt = {}", verified.jkt);
# Ok(()) }
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

