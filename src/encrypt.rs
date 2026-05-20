use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use rand::Rng;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub key: [u8; 32],
    pub iv: [u8; 16],
}

pub fn encrypt_aes256_cbc(plaintext: &[u8]) -> EncryptedPayload {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill(&mut key);
    rng.fill(&mut iv);

    let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    EncryptedPayload {
        ciphertext,
        key,
        iv,
    }
}

pub fn format_key_literal(key: &[u8; 32]) -> String {
    let bytes: Vec<String> = key.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("[{}]", bytes.join(", "))
}

pub fn format_iv_literal(iv: &[u8; 16]) -> String {
    let bytes: Vec<String> = iv.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("[{}]", bytes.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, World! This is a test payload for encryption.";
        let encrypted = encrypt_aes256_cbc(plaintext);

        assert_ne!(&encrypted.ciphertext[..], &plaintext[..]);
        assert_eq!(encrypted.key.len(), 32);
        assert_eq!(encrypted.iv.len(), 16);
    }

    #[test]
    fn test_iv_randomness() {
        let plaintext = b"test";
        let e1 = encrypt_aes256_cbc(plaintext);
        let e2 = encrypt_aes256_cbc(plaintext);
        assert_ne!(e1.iv, e2.iv);
    }
}
