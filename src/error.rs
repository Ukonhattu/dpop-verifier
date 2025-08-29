use thiserror::Error;

#[derive(Debug, Error)]
pub enum DpopError {
    #[error("missing DPoP header")]
    MissingHeader,
    #[error("malformed DPoP JWT")]
    MalformedJws,
    #[error("unsupported DPoP alg")]
    UnsupportedAlg,
    #[error("invalid DPoP signature")]
    InvalidSignature,
    #[error("bad JWK: {0}")]
    BadJwk(&'static str),
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    #[error("htm mismatch")]
    HtmMismatch,
    #[error("htu mismatch")]
    HtuMismatch,
    #[error("missing ath")]
    MissingAth,
    #[error("ath mismatch")]
    AthMismatch,
    #[error("iat too far in future")]
    FutureSkew,
    #[error("DPoP proof too old")]
    Stale,
    #[error("DPoP replay detected")]
    Replay,
    #[error("storage error: {0}")]
    Store(Box<dyn std::error::Error + Send + Sync>),
}
