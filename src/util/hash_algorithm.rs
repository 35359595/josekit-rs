#[cfg(feature = "open-ssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "native")]
use ring::digest::{
    Algorithm,
    SHA1_FOR_LEGACY_USE_ONLY,
    SHA256,
    SHA384,
    SHA512
};
use std::fmt::Display;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn name(&self) -> &str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    pub fn output_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    #[cfg(feature = "open-ssl")]
    pub(crate) fn message_digest(&self) -> MessageDigest {
        match self {
            Self::Sha1 => MessageDigest::sha1(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }
    #[cfg(feature = "native")]
    pub(crate) fn message_digest(&self) -> Algorithm {
        match self {
            Self::Sha1 => SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => SHA256,
            Self::Sha384 => SHA384,
            Self::Sha512 => SHA512,
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}
