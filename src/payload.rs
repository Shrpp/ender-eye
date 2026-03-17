use crate::error::{Result, ValidationErrors};
use base64::{Engine, engine::general_purpose::STANDARD};

pub fn encode_payload(ciphertext: &[u8], salt: &[u8; 16], nonce: &[u8; 12]) -> String {
    let mut payload = Vec::new();

    payload.extend_from_slice(salt);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(ciphertext);

    STANDARD.encode(&payload)
}

pub fn decode_payload(payload: &str) -> Result<(Vec<u8>, [u8; 16], [u8; 12])> {
    let bytes = STANDARD
        .decode(payload)
        .map_err(|_| ValidationErrors::Base64DecodingFailed)?;

    let salt: [u8; 16] = bytes[0..16]
        .try_into()
        .map_err(|_| ValidationErrors::Base64SaltDecodingFailed)?;

    let nonce: [u8; 12] = bytes[16..28]
        .try_into()
        .map_err(|_| ValidationErrors::Base64NonceDecodingFailed)?;

    let ciphertext: Vec<u8> = bytes[28..]
        .try_into()
        .map_err(|_| ValidationErrors::Base64CiphertextDecodingFailed)?;

    Ok((ciphertext, salt, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default() {
        let salt: [u8; 16] = [1u8; 16];
        let nonce: [u8; 12] = [1u8; 12];
        let ciphertext: Vec<u8> = vec![3u8; 32];

        let encoded = encode_payload(&ciphertext, &salt, &nonce);
        let (decoded_cipher, decoded_salt, decoded_nonce) = decode_payload(&encoded).unwrap();

        assert_eq!(decoded_salt, salt);
        assert_eq!(decoded_nonce, nonce);
        assert_eq!(decoded_cipher, ciphertext);
    }
}
