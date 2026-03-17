use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationErrors {
    #[error("Empty characters")]
    EmptyCharacters,

    #[error("Non-allowed characters detected")]
    NonAllowedCharacters,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decode Failed")]
    Base64DecodingFailed,

    #[error("Salt decode failed")]
    Base64SaltDecodingFailed,

    #[error("Nonce decode failed")]
    Base64NonceDecodingFailed,

    #[error("Ciphertext decode failed")]
    Base64CiphertextDecodingFailed,

    #[error("Plain text decrypt failed")]
    PlainTextDecryptationFailed,

    #[error("String conversion failed")]
    StringConversionFailed,

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("Payload too short to be valid")]
    PayloadTooShort,
}

impl From<argon2::Error> for ValidationErrors {
    fn from(e: argon2::Error) -> Self {
        ValidationErrors::KeyDerivationFailed(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ValidationErrors>;
