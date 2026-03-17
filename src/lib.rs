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
    if password.is_empty() {
        return Err(error::ValidationErrors::EmptyPassword);
    }
    if message.is_empty() {
        return Err(error::ValidationErrors::EmptyCharacters);
    }

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
    use base64::Engine;

    #[test]
    fn roundtrip_default() {
        let encrypted = encrypt("hello world", "ultra_super_secret_password").unwrap();
        let decrypted = decrypt(&encrypted, "ultra_super_secret_password").unwrap();
        assert_eq!(decrypted, "hello world");
    }

    #[test]
    fn roundtrip_special_characters() {
        let message = "hello world 123";
        let encrypted = encrypt(message, "password").unwrap();
        let decrypted = decrypt(&encrypted, "password").unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn roundtrip_long_message() {
        let message = "a".repeat(500);
        let encrypted = encrypt(&message, "password").unwrap();
        let decrypted = decrypt(&encrypted, "password").unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn encrypt_empty_password_returns_err() {
        assert!(encrypt("hello world", "").is_err());
    }

    #[test]
    fn encrypt_empty_message_returns_err() {
        assert!(encrypt("", "password").is_err());
    }

    #[test]
    fn decrypt_wrong_password_returns_err() {
        let encrypted = encrypt("hello world", "correct-password").unwrap();
        assert!(decrypt(&encrypted, "wrong-password").is_err());
    }

    #[test]
    fn decrypt_corrupted_payload_returns_err() {
        assert!(decrypt("this-is-not-a-valid-payload", "password").is_err());
    }

    #[test]
    fn decrypt_payload_too_short_returns_err() {
        // Valid Base64 but fewer than 29 bytes when decoded
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        assert!(decrypt(&short, "password").is_err());
    }
}
