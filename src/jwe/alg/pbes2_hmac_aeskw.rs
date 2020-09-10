use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::aes::{self, AesKey};
use openssl::pkcs5;
use serde_json::{Number, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::Jwk;
use crate::util::{self, HashAlgorithm};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Pbes2HmacJweAlgorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    Pbes2HS256A128Kw,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    Pbes2HS384A192Kw,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    Pbes2HS512A256Kw,
}

impl Pbes2HmacJweAlgorithm {
    pub fn encrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Pbes2HmacJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweEncrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() == 0 {
                bail!("The key size must not be empty.");
            }

            Ok(Pbes2HmacJweEncrypter {
                algorithm: self.clone(),
                private_key,
                salt_len: 8,
                iter_count: 1000,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweEncrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("deriveKey") {
                bail!("A parameter key_ops must contains deriveKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() == 0 {
                bail!("The key size must not be empty.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                salt_len: 8,
                iter_count: 1000,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Pbes2HmacJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweDecrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() == 0 {
                bail!("The key size must not be empty.");
            }

            Ok(Pbes2HmacJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweDecrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("deriveKey") {
                bail!("A parameter key_ops must contains deriveKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() == 0 {
                bail!("The key size must not be empty.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Pbes2HS256A128Kw => HashAlgorithm::Sha256,
            Self::Pbes2HS384A192Kw => HashAlgorithm::Sha384,
            Self::Pbes2HS512A256Kw => HashAlgorithm::Sha512,
        }
    }

    fn derived_key_len(&self) -> usize {
        match self {
            Self::Pbes2HS256A128Kw => 16,
            Self::Pbes2HS384A192Kw => 24,
            Self::Pbes2HS512A256Kw => 32,
        }
    }
}

impl JweAlgorithm for Pbes2HmacJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Pbes2HS256A128Kw => "PBES2-HS256+A128KW",
            Self::Pbes2HS384A192Kw => "PBES2-HS384+A192KW",
            Self::Pbes2HS512A256Kw => "PBES2-HS512+A256KW",
        }
    }

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for Pbes2HmacJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for Pbes2HmacJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacJweEncrypter {
    algorithm: Pbes2HmacJweAlgorithm,
    private_key: Vec<u8>,
    salt_len: usize,
    iter_count: usize,
    key_id: Option<String>,
}

impl Pbes2HmacJweEncrypter {
    pub fn set_salt_len(&mut self, salt_len: usize) {
        if salt_len < 8 {
            panic!("salt_len must be 8 or more: {}", salt_len);
        }
        self.salt_len = salt_len;
    }

    pub fn set_iter_count(&mut self, iter_count: usize) {
        if iter_count < 1000 {
            panic!("iter_count must be 1000 or more: {}", iter_count);
        }
        self.iter_count = iter_count;
    }

    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
    }
}

impl JweEncrypter for Pbes2HmacJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn encrypt(
        &self,
        header: &mut JweHeader,
        key_len: usize,
    ) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Cow<[u8]>, Option<Vec<u8>>)> {
            let p2s = match header.claim("p2s") {
                Some(Value::String(val)) => {
                    let p2s = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                    if p2s.len() < 8 {
                        bail!("The decoded value of p2s header claim must be 8 or more.");
                    }
                    p2s
                },
                Some(_) => bail!("The p2s header claim must be string."),
                None => {
                    let p2s = util::rand_bytes(self.salt_len);
                    let p2s_b64 = base64::encode_config(&p2s, base64::URL_SAFE_NO_PAD);
                    header.set_claim("p2s", Some(Value::String(p2s_b64)))?;
                    p2s
                }
            };
            let p2c = match header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The apv header claim must be string."),
                None => {
                    let p2c = self.iter_count;
                    header.set_claim("p2c", Some(Value::Number(Number::from(p2c))))?;
                    p2c
                }
            };

            let mut salt = Vec::with_capacity(self.algorithm().name().len() + 1 + p2s.len());
            salt.extend_from_slice(self.algorithm().name().as_bytes());
            salt.push(0);
            salt.extend_from_slice(&p2s);

            let md = self.algorithm.hash_algorithm().message_digest();
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            pkcs5::pbkdf2_hmac(&self.private_key, &salt, p2c, md, &mut derived_key)?;

            let aes = match AesKey::new_encrypt(&derived_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set a encryption key."),
            };

            let key = util::rand_bytes(key_len);
            let mut encrypted_key = vec![0; key_len + 8];
            match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                Ok(val) => if val < encrypted_key.len() {
                    encrypted_key.truncate(val);
                },
                Err(_) => bail!("Failed to wrap a key."),
            }

            header.set_algorithm(self.algorithm.name());
            Ok((Cow::Owned(key), Some(encrypted_key)))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for Pbes2HmacJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacJweDecrypter {
    algorithm: Pbes2HmacJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl Pbes2HmacJweDecrypter {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
    }
}

impl JweDecrypter for Pbes2HmacJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn decrypt(
        &self,
        header: &JweHeader,
        encrypted_key: Option<&[u8]>,
        key_len: usize,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key value is required."),
            };

            let p2s = match header.claim("p2s") {
                Some(Value::String(val)) => {
                    let p2s = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                    if p2s.len() < 8 {
                        bail!("The decoded value of p2s header claim must be 8 or more.");
                    }
                    p2s
                }
                Some(_) => bail!("The p2s header claim must be string."),
                None => bail!("The p2s header claim is required."),
            };
            let p2c = match header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The p2s header claim must be string."),
                None => bail!("The p2c header claim is required."),
            };

            let mut salt = Vec::with_capacity(self.algorithm().name().len() + 1 + p2s.len());
            salt.extend_from_slice(self.algorithm().name().as_bytes());
            salt.push(0);
            salt.extend_from_slice(&p2s);

            let md = self.algorithm.hash_algorithm().message_digest();
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            pkcs5::pbkdf2_hmac(&self.private_key, &salt, p2c, md, &mut derived_key)?;

            let aes = match AesKey::new_decrypt(&derived_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set a decryption key."),
            };

            let mut key = vec![0; key_len];
            match aes::unwrap_key(&aes, None, &mut key, &encrypted_key) {
                Ok(val) => if val < key.len() {
                    key.truncate(val);
                },
                Err(_) => bail!("Failed to unwrap a key."),
            }

            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for Pbes2HmacJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use base64;
    use serde_json::json;

    use super::Pbes2HmacJweAlgorithm;
    use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::Jwk;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_pbes2_hmac() -> Result<()> {
        let enc = AesCbcHmacJweEncryption::A128CbcHS256;

        for alg in vec![
            Pbes2HmacJweAlgorithm::Pbes2HS256A128Kw,
            Pbes2HmacJweAlgorithm::Pbes2HS384A192Kw,
            Pbes2HmacJweAlgorithm::Pbes2HS512A256Kw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let key = util::rand_bytes(8);
                let key = base64::encode_config(&key, base64::URL_SAFE_NO_PAD);

                let mut jwk = Jwk::new("oct");
                jwk.set_key_use("enc");
                jwk.set_parameter("k", Some(json!(key)))?;
                jwk
            };

            let encrypter = alg.encrypter_from_jwk(&jwk)?;
            let (src_key, encrypted_key) = encrypter.encrypt(&mut header, enc.key_len())?;

            let decrypter = alg.decrypter_from_jwk(&jwk)?;

            let dst_key = decrypter.decrypt(&header, encrypted_key.as_deref(), enc.key_len())?;

            assert_eq!(&src_key, &dst_key);
        }

        Ok(())
    }
}