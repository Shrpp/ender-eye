use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationErrors {
    #[error("message cannot be empty")]
    EmptyCharacters,

    #[error("message contains characters that are not supported — only lowercase letters and spaces are allowed")]
    NonAllowedCharacters,

    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("encryption failed — could not produce a valid ciphertext")]
    EncryptionFailed,

    #[error("payload is not valid Base64")]
    Base64DecodingFailed,

    #[error("could not extract salt from payload — data may be corrupted")]
    Base64SaltDecodingFailed,

    #[error("could not extract nonce from payload — data may be corrupted")]
    Base64NonceDecodingFailed,

    #[error("could not extract ciphertext from payload — data may be corrupted")]
    Base64CiphertextDecodingFailed,

    #[error("decryption failed — the password is incorrect or the payload has been tampered with")]
    PlainTextDecryptationFailed,

    #[error("decrypted bytes are not valid UTF-8")]
    StringConversionFailed,

    #[error("password cannot be empty")]
    EmptyPassword,

    #[error("payload is too short to be valid — expected at least 29 bytes")]
    PayloadTooShort,
}

impl From<argon2::Error> for ValidationErrors {
    fn from(e: argon2::Error) -> Self {
        ValidationErrors::KeyDerivationFailed(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ValidationErrors>;
