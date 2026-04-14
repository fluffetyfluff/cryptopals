use aes::{
    Aes128,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::prelude::*;

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

pub fn aes_128_encrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() == 16);
    assert!(bytes.len() == 16);
    let mut block = Array::try_from(bytes).unwrap();
    let cipher = Aes128::new_from_slice(key).unwrap();
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

pub fn aes_128_decrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() == 16);
    assert!(bytes.len() == 16);
    let mut block = Array::try_from(bytes).unwrap();
    let cipher = Aes128::new_from_slice(key).unwrap();
    cipher.decrypt_block(&mut block);
    block.to_vec()
}

pub fn aes_128_ecb_encrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);

    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(&bytes) {
        let mut block = aes_128_encrypt(&block, key);
        output.append(&mut block);
    }
    output
}

pub fn aes_128_ecb_decrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);

    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(&bytes) {
        let mut block = aes_128_decrypt(&block, key);
        output.append(&mut block);
    }
    output
}

pub fn aes_128_cbc_encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);
    assert!(iv.len() == 16);

    let mut prev_block = iv.to_vec();
    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(bytes) {
        let block = xor(block, &prev_block);
        let mut block = aes_128_encrypt(&block, key);
        prev_block = block.clone();
        output.append(&mut block);
    }
    output
}

pub fn aes_128_cbc_decrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);
    assert!(iv.len() == 16);

    let mut prev_ciphertext = iv.to_vec();
    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(bytes) {
        let decrypted_block = aes_128_decrypt(block, key);
        let mut decrypted_block = xor(&decrypted_block, &prev_ciphertext);
        prev_ciphertext = block.to_vec();
        output.append(&mut decrypted_block);
    }
    output
}

pub fn split_blocks(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.chunks(16).collect()
}

pub fn pkcs_pad_length(bytes: &[u8], length: usize) -> Vec<u8> {
    let mut block = bytes.to_vec();
    block.resize(length, (length - bytes.len()) as u8);
    block
}

pub fn pkcs_pad(bytes: &[u8]) -> Vec<u8> {
    let length = (bytes.len() / 16) * 16 + 16;
    pkcs_pad_length(bytes, length)
}
