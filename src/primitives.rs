use base64::prelude::*;
use openssl::symm::Cipher;

pub fn hex_decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn b64_decode(b64_str: &str) -> Vec<u8> {
    BASE64_STANDARD.decode(b64_str).unwrap()
}

pub fn b64_encode(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub fn xor(bytes_1: &[u8], bytes_2: &[u8]) -> Vec<u8> {
    bytes_1
        .iter()
        .zip(bytes_2)
        .map(|(b1, b2)| b1 ^ b2)
        .collect()
}

pub fn repeating_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    xor(bytes, &key.repeat(bytes.len() / key.len() + 1))
}

pub fn hamming_distance(bytes_1: &[u8], bytes_2: &[u8]) -> u32 {
    xor(bytes_1, bytes_2)
        .iter()
        .map(|b| b.count_ones())
        .reduce(|acc, e| acc + e)
        .unwrap_or(0)
}

pub fn aes_128_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() == 16);
    let cipher = Cipher::aes_128_ecb();
    openssl::symm::decrypt(cipher, key, None, bytes).unwrap()
}
