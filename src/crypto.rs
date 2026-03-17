use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::error::ValidationErrors;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);

    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut *key)?;

    Ok(key)
}

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(message: &str, password: &str) -> Result<(Vec<u8>, [u8; 16], [u8; 12])> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), message.as_bytes())
        .map_err(|_| ValidationErrors::EncryptionFailed)?;

    Ok((ciphertext, salt, nonce))
}

pub fn decrypt(ciphertext: &[u8], password: &str, salt: &[u8], nonce: &[u8]) -> Result<String> {
    if password.is_empty() {
        return Err(ValidationErrors::EmptyCharacters);
    }

    let key = derive_key(password, salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));

    let plaintext_bytes = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| ValidationErrors::PlainTextDecryptationFailed)?;

    String::from_utf8(plaintext_bytes).map_err(|_| ValidationErrors::StringConversionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salts_are_unique() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn encrypt_valid_input_returns_ok() {
        let result = encrypt("hello", "password123");
        assert!(result.is_ok());
    }

    #[test]
    fn encrypt_same_password_twice() {
        let first_result = encrypt("cat", "john_doe").unwrap();
        let second_result = encrypt("cat", "john_doe").unwrap();

        assert_ne!(first_result, second_result);
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let message = "Hello World";
        let password = "password123";

        let (ciphertext, salt, nonce) = encrypt(message, password).unwrap();
        let result = decrypt(&ciphertext, password, &salt, &nonce).unwrap();

        assert_eq!(result, message);
    }
}
