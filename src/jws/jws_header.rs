use std::fmt::{Debug, Display};
use std::ops::{Deref, DerefMut};

use anyhow::bail;
use serde_json::{Map, Value};

use crate::jwk::Jwk;
use crate::util;
use crate::{JoseError, JoseHeader};

/// Represent JWS header claims
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwsHeader {
    claims: Map<String, Value>,
}

impl JwsHeader {
    /// Return a JwsHeader instance.
    pub fn new() -> Self {
        Self { claims: Map::new() }
    }

    /// Return a new header instance from json style header.
    ///
    /// # Arguments
    ///
    /// * `value` - The json style header claims
    pub fn from_bytes(value: &[u8]) -> Result<Self, JoseError> {
        let claims = (|| -> anyhow::Result<Map<String, Value>> {
            let claims: Map<String, Value> = serde_json::from_slice(value)?;
            Ok(claims)
        })()
        .map_err(|err| JoseError::InvalidJson(err))?;

        let header = Self::from_map(claims)?;
        Ok(header)
    }

    /// Return a new header instance from map.
    ///
    /// # Arguments
    ///
    /// * `map` - JWT header claims.
    pub fn from_map(map: impl Into<Map<String, Value>>) -> Result<Self, JoseError> {
        let map: Map<String, Value> = map.into();
        for (key, value) in &map {
            Self::check_claim(key, value)?;
        }

        (|| -> anyhow::Result<()> {
            if let Some(Value::Bool(false)) = map.get("b64") {
                if let Some(Value::Array(vals)) = map.get("crit") {
                    if !vals.iter().any(|e| e == "b64") {
                        bail!("The b64 header claim name must be in critical.");
                    }
                }
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwsFormat(err))?;

        Ok(Self { claims: map })
    }

    /// Set a value for algorithm header claim (alg).
    ///
    /// # Arguments
    ///
    /// * `value` - a algorithm
    pub fn set_algorithm(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("alg".to_string(), Value::String(value));
    }

    /// Set a value for JWK set URL header claim (jku).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK set URL
    pub fn set_jwk_set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("jku".to_string(), Value::String(value));
    }

    /// Return the value for JWK set URL header claim (jku).
    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.claims.get("jku") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for JWK header claim (jwk).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK
    pub fn set_jwk(&mut self, value: Jwk) {
        let key = "jwk".to_string();
        let value: Map<String, Value> = value.into();
        self.claims.insert(key.clone(), Value::Object(value));
    }

    /// Return the value for JWK header claim (jwk).
    pub fn jwk(&self) -> Option<Jwk> {
        match self.claims.get("jwk") {
            Some(Value::Object(vals)) => match Jwk::from_map(vals.clone()) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set a value for X.509 URL header claim (x5u).
    ///
    /// # Arguments
    ///
    /// * `value` - a X.509 URL
    pub fn set_x509_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("x5u".to_string(), Value::String(value));
    }

    /// Return a value for a X.509 URL header claim (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.claims.get("x5u") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for X.509 certificate chain header claim (x5c).
    ///
    /// # Arguments
    ///
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: &Vec<impl AsRef<[u8]>>) {
        let key = "x5c".to_string();
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            vec.push(Value::String(base64::encode_config(
                val.as_ref(),
                base64::URL_SAFE_NO_PAD,
            )));
        }
        self.claims.insert(key.clone(), Value::Array(vec));
    }

    /// Return values for a X.509 certificate chain header claim (x5c).
    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.claims.get("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => {
                            match base64::decode_config(val2, base64::URL_SAFE_NO_PAD) {
                                Ok(val3) => vec.push(val3.clone()),
                                Err(_) => return None,
                            }
                        }
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    ///
    /// # Arguments
    ///
    /// * `value` - A X.509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        let key = "x5t".to_string();
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.clone(), Value::String(val));
    }

    /// Return the value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claims.get("x5t") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint header claim (x5t#S256).
    ///
    /// # Arguments
    ///
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        let key = "x5t#S256".to_string();
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.clone(), Value::String(val));
    }

    /// Return the value for X.509 certificate SHA-256 thumbprint header claim (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claims.get("x5t#S256") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set a value for key ID header claim (kid).
    ///
    /// # Arguments
    ///
    /// * `value` - a key ID
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("kid".to_string(), Value::String(value));
    }

    /// Return the value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.claims.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    ///
    /// * `value` - a token type (e.g. "JWT")
    pub fn set_token_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("typ".to_string(), Value::String(value));
    }

    /// Return the value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.claims.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    ///
    /// * `value` - a content type (e.g. "JWT")
    pub fn set_content_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("cty".to_string(), Value::String(value));
    }

    /// Return the value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.claims.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for critical header claim (crit).
    ///
    /// # Arguments
    ///
    /// * `values` - critical claim names
    pub fn set_critical(&mut self, values: &Vec<impl AsRef<str>>) {
        let key = "crit".to_string();
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            let val: String = val.as_ref().to_string();
            vec.push(Value::String(val));
        }
        self.claims.insert(key.clone(), Value::Array(vec));
    }

    /// Return values for critical header claim (crit).
    pub fn critical(&self) -> Option<Vec<&str>> {
        match self.claims.get("crit") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(val2.as_str()),
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for base64url-encode payload header claim (b64).
    ///
    /// # Arguments
    ///
    /// * `value` - is base64url-encode payload
    pub fn set_base64url_encode_payload(&mut self, value: bool) {
        self.claims.insert("b64".to_string(), Value::Bool(value));
    }

    /// Return the value for base64url-encode payload header claim (b64).
    pub fn base64url_encode_payload(&self) -> Option<bool> {
        match self.claims.get("b64") {
            Some(Value::Bool(val)) => Some(*val),
            _ => None,
        }
    }

    /// Set a value for url header claim (url).
    ///
    /// # Arguments
    ///
    /// * `value` - a url
    pub fn set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("url".to_string(), Value::String(value));
    }

    /// Return the value for url header claim (url).
    pub fn url(&self) -> Option<&str> {
        match self.claims.get("url") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a nonce header claim (nonce).
    ///
    /// # Arguments
    ///
    /// * `value` - A nonce
    pub fn set_nonce(&mut self, value: impl AsRef<[u8]>) {
        let key = "nonce".to_string();
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.clone(), Value::String(val));
    }

    /// Return the value for nonce header claim (nonce).
    pub fn nonce(&self) -> Option<Vec<u8>> {
        match self.claims.get("nonce") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    fn check_claim(key: &str, value: &Value) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" | "jku" | "x5u" | "kid" | "typ" | "cty" | "url" => match &value {
                    Value::String(_) => {}
                    _ => bail!("The JWS {} header claim must be string.", key),
                },
                "crit" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWS {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWS {} header claim must be a array.", key),
                },
                "x5t" | "x5t#S256" | "nonce" => match &value {
                    Value::String(val) => {
                        if !util::is_base64_url_safe_nopad(val) {
                            bail!("The JWS {} header claim must be a base64 string.", key);
                        }
                    }
                    _ => bail!("The JWS {} header claim must be a string.", key),
                },
                "x5c" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    if !util::is_base64_url_safe_nopad(val) {
                                        bail!(
                                            "The JWS {} header claim must be a base64 string.",
                                            key
                                        );
                                    }
                                }
                                _ => bail!(
                                    "An element of the JWS {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWS {} header claim must be a array.", key),
                },
                "jwk" => match &value {
                    Value::Object(vals) => Jwk::check_map(vals)?,
                    _ => bail!("The JWS {} header claim must be a string.", key),
                },
                _ => {}
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }
}

impl JoseHeader for JwsHeader {
    fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        match value {
            Some(val) => {
                Self::check_claim(key, &val)?;
                self.claims.insert(key.to_string(), val);
            }
            None => {
                self.claims.remove(key);
            }
        }

        Ok(())
    }

    fn box_clone(&self) -> Box<dyn JoseHeader> {
        Box::new(self.clone())
    }

    fn into_map(self) -> Map<String, Value> {
        self.claims
    }
}

impl AsRef<Map<String, Value>> for JwsHeader {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl Into<Map<String, Value>> for JwsHeader {
    fn into(self) -> Map<String, Value> {
        self.into_map()
    }
}

impl Display for JwsHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(self.claims_set()).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

impl Deref for JwsHeader {
    type Target = dyn JoseHeader;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for JwsHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}