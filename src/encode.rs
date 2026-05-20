use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncodingType {
    IntArray,
    WordSplit,
    Base32,
    Uuid,
}

impl EncodingType {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "default" | "intarray" => Ok(Self::IntArray),
            "wordsplit" => Ok(Self::WordSplit),
            "base32" => Ok(Self::Base32),
            "uuid" => Ok(Self::Uuid),
            _ => anyhow::bail!("Unknown encoding type: {}", s),
        }
    }
}

pub struct EncodedPayload {
    pub encoded_literal: String,
    pub decode_snippet: String,
    #[allow(dead_code)]
    pub encoding_type: EncodingType,
}

pub fn encode_payload(data: &[u8], encoding: EncodingType) -> EncodedPayload {
    let mut rng = rand::thread_rng();
    match encoding {
        EncodingType::IntArray => encode_int_array(data, &mut rng),
        EncodingType::WordSplit => encode_word_split(data, &mut rng),
        EncodingType::Base32 => encode_base32(data),
        EncodingType::Uuid => encode_uuid(data),
    }
}

fn encode_int_array(data: &[u8], rng: &mut impl Rng) -> EncodedPayload {
    let offset: i32 = rng.gen_range(100..900);
    let encoded: Vec<i32> = data.iter().map(|&b| (b as i32) + offset).collect();
    let literal = emit_int_array_rust_literal(&encoded);

    let decode_snippet = format!(
        r#"fn decode_payload(encoded: &[i32]) -> Vec<u8> {{
    encoded.iter().map(|&v| (v - {offset}) as u8).collect()
}}"#,
        offset = offset
    );

    EncodedPayload {
        encoded_literal: literal,
        decode_snippet,
        encoding_type: EncodingType::IntArray,
    }
}

fn emit_int_array_rust_literal(encoded: &[i32]) -> String {
    let items: Vec<String> = encoded.iter().map(|v| format!("{}i32", v)).collect();
    format!("&[{}]", items.join(", "))
}

fn encode_word_split(data: &[u8], rng: &mut impl Rng) -> EncodedPayload {
    let xor_mask: u8 = rng.gen_range(1..255);
    let mut nibbles: Vec<u8> = Vec::with_capacity(data.len() * 2);
    for &b in data {
        let high = (b >> 4) ^ xor_mask;
        let low = (b & 0x0F) ^ xor_mask;
        nibbles.push(high);
        nibbles.push(low);
    }

    let literal = format!(
        "&[{}]",
        nibbles
            .iter()
            .map(|b| format!("0x{:02x}u8", b))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let decode_snippet = format!(
        r#"fn decode_payload(encoded: &[u8]) -> Vec<u8> {{
    let xor_mask: u8 = 0x{mask:02x};
    let mut result = Vec::with_capacity(encoded.len() / 2);
    for chunk in encoded.chunks_exact(2) {{
        let high = (chunk[0] ^ xor_mask) & 0x0F;
        let low = (chunk[1] ^ xor_mask) & 0x0F;
        result.push((high << 4) | low);
    }}
    result
}}"#,
        mask = xor_mask
    );

    EncodedPayload {
        encoded_literal: literal,
        decode_snippet,
        encoding_type: EncodingType::WordSplit,
    }
}

fn encode_base32(data: &[u8]) -> EncodedPayload {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut encoded = String::new();

    let mut bits: u64 = 0;
    let mut num_bits: u32 = 0;

    for &byte in data {
        bits = (bits << 8) | byte as u64;
        num_bits += 8;
        while num_bits >= 5 {
            num_bits -= 5;
            let idx = ((bits >> num_bits) & 0x1F) as usize;
            encoded.push(alphabet[idx] as char);
        }
    }
    if num_bits > 0 {
        let idx = ((bits << (5 - num_bits)) & 0x1F) as usize;
        encoded.push(alphabet[idx] as char);
    }
    while encoded.len() % 8 != 0 {
        encoded.push('=');
    }

    let literal = format!("\"{}\"", encoded);

    let decode_snippet = r#"fn decode_payload(encoded: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = Vec::new();
    let mut bits: u64 = 0;
    let mut num_bits: u32 = 0;
    for c in encoded.bytes() {
        if c == b'=' { break; }
        let val = alphabet.iter().position(|&a| a == c).unwrap_or(0) as u64;
        bits = (bits << 5) | val;
        num_bits += 5;
        if num_bits >= 8 {
            num_bits -= 8;
            result.push((bits >> num_bits) as u8);
            bits &= (1u64 << num_bits) - 1;
        }
    }
    result
}"#
    .to_string();

    EncodedPayload {
        encoded_literal: literal,
        decode_snippet,
        encoding_type: EncodingType::Base32,
    }
}

fn encode_uuid(data: &[u8]) -> EncodedPayload {
    let mut uuids: Vec<String> = Vec::new();
    let chunks: Vec<&[u8]> = data.chunks(16).collect();

    for chunk in &chunks {
        let mut padded = [0u8; 16];
        padded[..chunk.len()].copy_from_slice(chunk);
        let uuid = format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]),
            u16::from_be_bytes([padded[4], padded[5]]),
            u16::from_be_bytes([padded[6], padded[7]]),
            u16::from_be_bytes([padded[8], padded[9]]),
            u64::from_be_bytes([0, 0, padded[10], padded[11], padded[12], padded[13], padded[14], padded[15]])
        );
        uuids.push(uuid);
    }

    let literal = format!(
        "&[{}]",
        uuids
            .iter()
            .map(|u| format!("\"{}\"", u))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let total_len = data.len();
    let decode_snippet = format!(
        r#"fn decode_payload(uuids: &[&str]) -> Vec<u8> {{
    let total_len: usize = {total_len};
    let mut result = Vec::with_capacity(total_len);
    for uuid in uuids {{
        let hex: String = uuid.chars().filter(|c| *c != '-').collect();
        for i in (0..32).step_by(2) {{
            if result.len() >= total_len {{ break; }}
            let byte = u8::from_str_radix(&hex[i..i+2], 16).unwrap_or(0);
            result.push(byte);
        }}
    }}
    result.truncate(total_len);
    result
}}"#,
        total_len = total_len
    );

    EncodedPayload {
        encoded_literal: literal,
        decode_snippet,
        encoding_type: EncodingType::Uuid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_array_roundtrip() {
        let data = b"Hello, World! Test payload bytes.";
        let mut rng = rand::thread_rng();
        let encoded_payload = encode_int_array(data, &mut rng);
        assert!(encoded_payload.encoded_literal.contains("i32"));
    }

    #[test]
    fn test_word_split_roundtrip() {
        let data = b"\x00\x01\x02\xFF\xFE";
        let mut rng = rand::thread_rng();
        let _encoded = encode_word_split(data, &mut rng);
    }

    #[test]
    fn test_int_array_different_offsets() {
        let data = b"test";
        let mut rng = rand::thread_rng();
        let e1 = encode_int_array(data, &mut rng);
        let e2 = encode_int_array(data, &mut rng);
        assert_ne!(e1.encoded_literal, e2.encoded_literal);
    }
}
