mod crypto;
mod error;
mod payload;
mod sga;

use crate::error::Result;

/// Encrypts a message using a password and returns a Base64-encoded payload.
///
/// Internally runs the message through three stages:
/// 1. **SGA encoding** — substitutes each letter with its Standard Galactic Alphabet symbol.
/// 2. **AES-256-GCM** — encrypts the encoded text. A random salt and nonce are generated on
///    every call, so two calls with identical inputs will always produce different outputs.
/// 3. **Base64** — packs `salt + nonce + ciphertext` into a single portable string.
///
/// # Errors
///
/// Returns an error if encryption fails.
///
/// # Example
///
/// ```
/// let ciphertext = ender_eye::encrypt("hello world", "my-password").unwrap();
/// ```
pub fn encrypt(message: &str, password: &str) -> Result<String> {
    let sga_encoded = sga::encode(message);
    let (ciphertext, salt, nonce) = crypto::encrypt(&sga_encoded, password)?;

    Ok(payload::encode_payload(&ciphertext, &salt, &nonce))
}

/// Decrypts a Base64-encoded payload produced by [`encrypt`] and returns the original message.
///
/// Reverses the three stages of [`encrypt`]:
/// 1. **Base64 decode** — unpacks the payload back into `salt`, `nonce`, and `ciphertext`.
/// 2. **AES-256-GCM** — decrypts and authenticates the ciphertext. Fails if the payload was
///    tampered with or if the wrong password is provided.
/// 3. **SGA decode** — converts SGA symbols back to plain ASCII letters.
///
/// # Errors
///
/// Returns an error if the payload is malformed, authentication fails, or decoding fails.
///
/// # Example
///
/// ```
/// # let ciphertext = ender_eye::encrypt("hello world", "my-password").unwrap();
/// let plaintext = ender_eye::decrypt(&ciphertext, "my-password").unwrap();
/// assert_eq!(plaintext, "hello world");
/// ```
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
