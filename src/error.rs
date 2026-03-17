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
}

impl From<argon2::Error> for ValidationErrors {
    fn from(e: argon2::Error) -> Self {
        ValidationErrors::KeyDerivationFailed(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ValidationErrors>;
