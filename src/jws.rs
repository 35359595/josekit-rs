pub mod alg_hmac;
pub mod alg_rsa;
pub mod alg_rsapss;
pub mod alg_ecdsa;
pub mod alg_eddsa;
pub mod multi_signer;
pub mod multi_verifier;

use anyhow::bail;
use serde_json::{Map, Value};

use crate::error::JoseError;
use crate::jwk::Jwk;

pub use crate::jws::alg_hmac::HmacJwsAlgorithm::HS256;
pub use crate::jws::alg_hmac::HmacJwsAlgorithm::HS384;
pub use crate::jws::alg_hmac::HmacJwsAlgorithm::HS512;

pub use crate::jws::alg_rsa::RsaJwsAlgorithm::RS256;
pub use crate::jws::alg_rsa::RsaJwsAlgorithm::RS384;
pub use crate::jws::alg_rsa::RsaJwsAlgorithm::RS512;

pub use crate::jws::alg_rsapss::RsaPssJwsAlgorithm::PS256;
pub use crate::jws::alg_rsapss::RsaPssJwsAlgorithm::PS384;
pub use crate::jws::alg_rsapss::RsaPssJwsAlgorithm::PS512;

pub use crate::jws::alg_ecdsa::EcdsaJwsAlgorithm::ES256;
pub use crate::jws::alg_ecdsa::EcdsaJwsAlgorithm::ES384;
pub use crate::jws::alg_ecdsa::EcdsaJwsAlgorithm::ES512;
pub use crate::jws::alg_ecdsa::EcdsaJwsAlgorithm::ES256K;

pub use crate::jws::alg_eddsa::EddsaJwsAlgorithm::EDDSA;

pub trait JwsHeader {
    /// Return the value for algorithm header claim (alg).
    fn algorithm(&self) -> Option<&str>;

    /// Return the value for token type header claim (typ).
    fn token_type(&self) -> Option<&str>;

    /// Return the value for content type header claim (cty).
    fn content_type(&self) -> Option<&str>;

    /// Return the value for key ID header claim (kid).
    fn key_id(&self) -> Option<&str>;

    /// Return the value for URL header claim (url).
    fn url(&self) -> Option<&str>;

    /// Return the value of header claim of the specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of header claim
    fn header_claim(&self, key: &str) -> Option<&Value>;
}

pub trait JwsAlgorithm {
    /// Return the "alg" (algorithm) header parameter value of JWS.
    fn name(&self) -> &str;

    /// Return the "kty" (key type) header parameter value of JWS.
    fn key_type(&self) -> &str;

    /// Return the signature length of JWS.
    fn signature_len(&self) -> usize;

    /// Return the signer from a JWK private key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK private key.
    fn signer_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JwsSigner>, JoseError>;

    /// Return the verifier from a JWK key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK key.
    fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JwsVerifier>, JoseError>;
}

pub trait JwsSigner {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a signature of the data.
    ///
    /// # Arguments
    /// * `message` - The message data to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn serialize_compact(
        &self,
        header: &Map<String, Value>,
        payload: &[u8],
    ) -> Result<String, JoseError> {
        (|| -> anyhow::Result<String> {
            let mut b64 = true;
            if let Some(Value::Bool(false)) = header.get("b64") {
                if let Some(Value::Array(vals)) = header.get("crit") {
                    if vals.iter().any(|e| e == "b64") {
                        b64 = false;
                    } else {
                        bail!("The b64 header claim name must be in critical.");
                    }
                }
            }

            let payload_base64;
            let payload = if b64 {
                payload_base64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
                &payload_base64
            } else {
                match std::str::from_utf8(payload) {
                    Ok(val) => {
                        if val.contains(".") {
                            bail!("A JWS payload cannot contain dot.");
                        }
                        val
                    }
                    Err(err) => bail!("{}", err),
                }
            };

            let header = serde_json::to_string(&header).unwrap();
            let header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);

            let mut message = String::with_capacity(
                header.len() + payload.len() + self.algorithm().signature_len() + 2,
            );

            message.push_str(&header);
            message.push_str(".");
            message.push_str(&payload);

            let signature = self.sign(message.as_bytes())?;

            let signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
            message.push_str(".");
            message.push_str(&signature);

            Ok(message)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }
}

pub trait JwsVerifier {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Unset a compared value for a kid header claim (kid).
    fn unset_key_id(&mut self);

    /// Verify the data by the signature.
    ///
    /// # Arguments
    /// * `message` - a message data to verify.
    /// * `signature` - a signature data.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError>;

    fn deserialize_compact(
        &self,
        header: &Map<String, Value>,
        input: &str,
    ) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let indexies: Vec<usize> = input
                .char_indices()
                .filter(|(_, c)| c == &'.')
                .map(|(i, _)| i)
                .collect();
            if indexies.len() != 2 {
                bail!("The signed JWT must be three parts separated by colon.");
            }

            let expected_alg = self.algorithm().name();
            match header.get("alg") {
                Some(Value::String(val)) if val == expected_alg => {}
                Some(Value::String(val)) => {
                    bail!("The JWT alg header claim is not {}: {}", expected_alg, val)
                }
                Some(_) => bail!("The JWT alg header claim must be a string."),
                None => bail!("The JWT alg header claim is required."),
            }

            let expected_kid = self.key_id();
            match (expected_kid, header.get("kid")) {
                (Some(expected), Some(actual)) if expected == actual => {}
                (None, None) => {}
                (Some(_), Some(actual)) => {
                    bail!("The JWT kid header claim is mismatched: {}", actual)
                }
                _ => bail!("The JWT kid header claim is missing."),
            }

            let mut b64 = true;
            if let Some(Value::Bool(false)) = header.get("b64") {
                if let Some(Value::Array(vals)) = header.get("crit") {
                    if vals.iter().any(|e| e == "b64") {
                        b64 = false;
                    } else {
                        bail!("The b64 header claim name must be in critical.");
                    }
                }
            }

            let message = &input[..(indexies[1])];

            let payload = &input[(indexies[0] + 1)..(indexies[1])];
            let payload = if b64 {
                base64::decode_config(payload, base64::URL_SAFE_NO_PAD)?
            } else {
                payload.as_bytes().to_vec()
            };

            let signature = &input[(indexies[1] + 1)..];
            let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;

            self.verify(message.as_bytes(), &signature)?;

            Ok(payload)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }
}