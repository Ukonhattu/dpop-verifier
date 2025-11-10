use async_trait::async_trait;
use dpop_verifier::{DpopError, DpopVerifier, ReplayContext, ReplayStore};
use std::collections::HashSet;
use std::io::{self, Read};

struct MemoryStore(HashSet<[u8; 32]>);

#[async_trait]
impl ReplayStore for MemoryStore {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],
        _ctx: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        Ok(self.0.insert(jti_hash))
    }
}

/// Usage:
///   ACCESS_TOKEN="..." HTU="https://api.example.com/resource" HTM="GET" \
///     cargo run --example verify_rs --quiet <<< "$DPOP_JWS"
///
/// - Reads the compact DPoP JWS from STDIN
/// - Expects `ACCESS_TOKEN` env var for `ath` verification
/// - Accepts HTU/HTM via env (defaults shown below)
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read DPoP JWT
    let mut dpop = String::new();
    io::stdin().read_to_string(&mut dpop)?;
    let dpop = dpop.trim();

    let expected_htu = std::env::var("HTU").unwrap_or_else(|_| "http://localhost/resource".into());
    let expected_htm = std::env::var("HTM").unwrap_or_else(|_| "GET".into());
    let access_token =
        std::env::var("ACCESS_TOKEN").expect("set ACCESS_TOKEN env var for RS verification");

    let mut store = MemoryStore(HashSet::new());

    // Use the new DpopVerifier API with builder pattern
    let mut verifier = DpopVerifier::new().with_max_age(300).with_future_skew(5);

    if let Ok(client_id) = std::env::var("CLIENT_ID") {
        verifier = verifier.with_client_binding(client_id);
    }

    let verified = verifier
        .verify(
            &mut store,
            dpop,
            &expected_htu,
            &expected_htm,
            Some(&access_token), // Require and verify `ath`
        )
        .await?;

    eprintln!("Verified RS call:");
    eprintln!("  jkt = {}", verified.jkt);
    eprintln!("  jti = {}", verified.jti);
    eprintln!("  iat = {}", verified.iat);
    Ok(())
}
