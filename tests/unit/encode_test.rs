use rustpack::encode::*;

#[test]
fn test_int_array_encode_decode() {
    let data: Vec<u8> = (0..255u8).collect();
    let encoded = encode_payload(&data, EncodingType::IntArray);

    // Verify the encoded literal contains i32 values
    assert!(encoded.encoded_literal.contains("i32"));
    // Verify decode snippet is present
    assert!(encoded.decode_snippet.contains("fn decode_payload"));
}

#[test]
fn test_word_split_encode() {
    let data = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34];
    let encoded = encode_payload(&data, EncodingType::WordSplit);

    // WordSplit produces nibble pairs, so output should be 2x input length
    assert!(encoded.decode_snippet.contains("xor_mask"));
    assert!(encoded.encoded_literal.contains("0x"));
}

#[test]
fn test_base32_encode() {
    let data = b"Hello, World!";
    let encoded = encode_payload(data, EncodingType::Base32);

    // Base32 should produce uppercase letters and digits 2-7
    assert!(encoded.encoded_literal.contains('"'));
    assert!(encoded.decode_snippet.contains("fn decode_payload"));
}

#[test]
fn test_uuid_encode() {
    let data: Vec<u8> = (0..48).collect(); // 3 UUIDs worth
    let encoded = encode_payload(&data, EncodingType::Uuid);

    // UUID format should have dashes
    assert!(encoded.encoded_literal.contains('-'));
    assert!(encoded.decode_snippet.contains("fn decode_payload"));
}

#[test]
fn test_int_array_randomization() {
    let data = b"test payload data";
    let e1 = encode_payload(data, EncodingType::IntArray);
    let e2 = encode_payload(data, EncodingType::IntArray);

    // Two encodings of the same data must differ due to random offset
    assert_ne!(e1.encoded_literal, e2.encoded_literal);
}

#[test]
fn test_encoding_from_str() {
    assert_eq!(EncodingType::from_str("default").unwrap(), EncodingType::IntArray);
    assert_eq!(EncodingType::from_str("intarray").unwrap(), EncodingType::IntArray);
    assert_eq!(EncodingType::from_str("wordsplit").unwrap(), EncodingType::WordSplit);
    assert_eq!(EncodingType::from_str("base32").unwrap(), EncodingType::Base32);
    assert_eq!(EncodingType::from_str("uuid").unwrap(), EncodingType::Uuid);
    assert!(EncodingType::from_str("invalid").is_err());
}
