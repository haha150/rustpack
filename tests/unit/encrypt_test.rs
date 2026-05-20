use rustpack::encrypt::*;

#[test]
fn test_aes256_cbc_roundtrip() {
    let plaintext = b"This is a test payload for AES-256-CBC encryption roundtrip testing.";
    let encrypted = encrypt_aes256_cbc(plaintext);

    // Decrypt to verify
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let decryptor = Aes256CbcDec::new(&encrypted.key.into(), &encrypted.iv.into());
    let decrypted = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted.ciphertext)
        .expect("Decryption failed");

    assert_eq!(&decrypted[..], &plaintext[..]);
}

#[test]
fn test_iv_randomness() {
    let plaintext = b"test data";
    let e1 = encrypt_aes256_cbc(plaintext);
    let e2 = encrypt_aes256_cbc(plaintext);

    // IVs must be different
    assert_ne!(e1.iv, e2.iv);
    // Keys must be different
    assert_ne!(e1.key, e2.key);
    // Ciphertexts must be different (due to different key/IV)
    assert_ne!(e1.ciphertext, e2.ciphertext);
}

#[test]
fn test_key_format() {
    let key = [0x41u8; 32];
    let formatted = format_key_literal(&key);
    assert!(formatted.starts_with('['));
    assert!(formatted.ends_with(']'));
    assert!(formatted.contains("0x41"));
}

#[test]
fn test_iv_format() {
    let iv = [0xBBu8; 16];
    let formatted = format_iv_literal(&iv);
    assert!(formatted.starts_with('['));
    assert!(formatted.ends_with(']'));
    assert!(formatted.contains("0xbb"));
}
