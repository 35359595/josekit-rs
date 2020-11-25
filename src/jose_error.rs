use thiserror::Error;

#[derive(Error, Debug)]
pub enum JoseError {
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(#[source] anyhow::Error),

    #[error("Invalid JWT format: {0}")]
    InvalidJwtFormat(#[source] anyhow::Error),

    #[error("Invalid JWK format: {0}")]
    InvalidJwkFormat(#[source] anyhow::Error),

    #[error("Invalid JWS format: {0}")]
    InvalidJwsFormat(#[source] anyhow::Error),

    #[error("Invalid JWE format: {0}")]
    InvalidJweFormat(#[source] anyhow::Error),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(#[source] anyhow::Error),

    #[error("Invalid json: {0}")]
    InvalidJson(#[source] anyhow::Error),

    #[error("Invalid claim: {0}")]
    InvalidClaim(#[source] anyhow::Error),

    #[error("Invalid signature: {0}")]
    InvalidSignature(#[source] anyhow::Error),

    #[error(transparent)]
    KeyRejectedRingError(#[from] ring::error::KeyRejected),

    #[error(transparent)]
    UnspecifiedRingErorr(#[from] ring::error::Unspecified),

    #[error(transparent)]
    DecodeError(#[from] base64::DecodeError),

    #[error("Generic error occured: {0}")]
    Generic(String),
}
