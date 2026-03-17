mod crypto;
mod error;
mod payload;
mod sga;

use crate::error::Result;

pub fn encrypt(message: &str, password: &str) -> Result<String> {
    let sga_encoded = sga::encode(message);
    let (ciphertext, salt, nonce) = crypto::encrypt(&sga_encoded, password)?;

    Ok(payload::encode_payload(&ciphertext, &salt, &nonce))
}

pub fn decrypt(message: &str, password: &str) -> Result<String> {
    let (ciphertext, salt, nonce) = payload::decode_payload(message)?;
    let decrypted = crypto::decrypt(&ciphertext, password, &salt, &nonce)?;

    let decoded = sga::decode(&decrypted)?;

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default() {
        let message = "hello world";
        let password = "ultra_super_secret_password";

        let encrypted = encrypt(message, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();

        assert_eq!(decrypted, message);
    }
}
