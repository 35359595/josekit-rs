use aes::{
    Aes128,
    Aes192,
    Aes256,
    cipher::{
        BlockCipher,
        NewBlockCipher,
        generic_array::GenericArray,
    },
};
use crate::JoseError;

pub(crate) fn encrypt_aeskw(
    key_length: usize,
    pk: &[u8],
    data: &[u8]
) -> Result<Vec<u8>, JoseError> {
    let mut out = GenericArray::clone_from_slice(data);
        match key_length {
            16 =>
                Aes128::new(&GenericArray::from_slice(&pk))
                    .encrypt_block(&mut out),
            24 =>
                Aes192::new(GenericArray::from_slice(&pk))
                    .encrypt_block(&mut out),
            32 =>
                Aes256::new(GenericArray::from_slice(&pk))
                    .encrypt_block(&mut out),
            _ => return Err(JoseError::Generic("Unsupported key length.".into()))
        };
    Ok(out.to_vec())
}

pub(crate) fn decrypt_aeskw(
    key_length: usize,
    pk: &[u8],
    data: &[u8]
) -> Result<Vec<u8>, JoseError> {
    let mut out = GenericArray::clone_from_slice(data);
        match key_length {
            16 =>
                Aes128::new(&GenericArray::from_slice(&pk))
                    .decrypt_block(&mut out),
            24 =>
                Aes192::new(GenericArray::from_slice(&pk))
                    .decrypt_block(&mut out),
            32 =>
                Aes256::new(GenericArray::from_slice(&pk))
                    .decrypt_block(&mut out),
            _ => return Err(JoseError::Generic("Unsupported key length.".into()))
        };
    Ok(out.to_vec())
}