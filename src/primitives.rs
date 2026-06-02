use aes::{
    Aes128,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::prelude::*;

pub type Block = [u8; 16];
pub type Nonce = [u8; 8];

pub struct Mt19937 {
    state_array: [u32; 624],
    state_index: usize,
}

impl Mt19937 {
    pub fn new(mut seed: u32) -> Self {
        let mut mt = Self {
            state_array: [0; 624],
            state_index: 0,
        };
        mt.state_array[0] = seed;
        for i in 1..624 {
            seed = 1812433253u32.wrapping_mul(seed ^ (seed >> 30)) + i as u32;
            mt.state_array[i] = seed;
        }
        mt.state_index = 0;
        mt
    }

    pub fn rand(&mut self) -> u32 {
        let k = self.state_index;
        let j = (k + 1) % 624;
        let umask = 0xFFFFFFFF << 31;
        let rmask = 0xFFFFFFFF >> 1;
        let x = (self.state_array[k] & umask) | (self.state_array[j] & rmask);
        let mut x_a = x >> 1;
        if x & 1 == 1 {
            x_a = x_a ^ 0x9908B0DF;
        };
        let j = (k + 397) % 624;
        let x = self.state_array[j] ^ x_a;
        self.state_array[k] = x;
        self.state_index = (k + 1) % 624;

        let y = x ^ (x >> 11);
        let y = y ^ ((y << 7) & 0x9D2C5680);
        let y = y ^ ((y << 15) & 0xEFC60000);
        y ^ (y >> 18)
    }
}

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

pub fn xor_block(block_1: &Block, block_2: &Block) -> Block {
    std::array::from_fn(|i| block_1[i] ^ block_2[i])
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

pub fn aes_128_encrypt(bytes: &Block, key: &Block) -> Block {
    let mut block = Array::try_from(bytes.as_slice()).unwrap();
    let cipher = Aes128::new_from_slice(key).unwrap();
    cipher.encrypt_block(&mut block);
    block.into()
}

pub fn aes_128_decrypt(bytes: &Block, key: &Block) -> Block {
    let mut block = Array::try_from(bytes.as_slice()).unwrap();
    let cipher = Aes128::new_from_slice(key).unwrap();
    cipher.decrypt_block(&mut block);
    block.into()
}

pub fn aes_128_ecb_encrypt(bytes: &[u8], key: &Block) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);

    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(&bytes) {
        let block = aes_128_encrypt(&block, key);
        output.extend(block);
    }
    output
}

pub fn aes_128_ecb_decrypt(bytes: &[u8], key: &Block) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);

    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(&bytes) {
        let block = aes_128_decrypt(&block, key);
        output.extend(block);
    }
    output
}

pub fn aes_128_cbc_encrypt(bytes: &[u8], key: &Block, iv: &Block) -> (Vec<u8>, Block) {
    assert!(bytes.len() % 16 == 0);

    let mut prev_block = iv;
    let mut encrypted_block: Block;
    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(bytes) {
        let block = xor_block(&block, prev_block).try_into().unwrap();
        encrypted_block = aes_128_encrypt(&block, key);
        prev_block = &encrypted_block;
        output.extend(encrypted_block);
    }
    (output, iv.clone())
}

pub fn aes_128_cbc_decrypt(bytes: &[u8], key: &Block, iv: &Block) -> Vec<u8> {
    assert!(bytes.len() % 16 == 0);

    let mut prev_ciphertext = iv.to_vec();
    let mut output: Vec<u8> = Vec::new();
    for block in split_blocks(bytes) {
        let decrypted_block = aes_128_decrypt(&block, key);
        let mut decrypted_block = xor(&decrypted_block, &prev_ciphertext);
        prev_ciphertext = block.to_vec();
        output.append(&mut decrypted_block);
    }
    output
}

pub fn aes_128_ctr_keystream(len: usize, key: &Block, nonce: &Nonce) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(len);
    let mut nonce_le: Nonce = [0x0; 8];
    nonce_le.copy_from_slice(nonce);
    nonce_le.reverse();
    let mut input: Block = [0x0; 16];
    input[..8].copy_from_slice(&nonce_le);
    for ctr in 0..len as u64 / 16 {
        let ctr_bytes: Nonce = ctr.to_le_bytes();
        input[8..].copy_from_slice(&ctr_bytes);
        let keystream_block = aes_128_encrypt(&input, key);
        output.extend(keystream_block);
    }

    let ctr_bytes: Nonce = (len as u64 / 16).to_le_bytes();
    input[8..].copy_from_slice(&ctr_bytes);
    let final_block = aes_128_encrypt(&input, key);
    output.extend(&final_block[..len % 16]);
    output
}

pub fn split_blocks(bytes: &[u8]) -> Vec<Block> {
    bytes.as_chunks::<16>().0.to_vec()
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

pub fn pkcs_unpad(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let end_byte = bytes[bytes.len() - 1];
    if end_byte as usize > bytes.len() {
        return Err(());
    }
    let mut bytes = bytes.to_vec();
    let mut padding = bytes.split_off(bytes.len() - end_byte as usize);
    padding.dedup();
    if padding.len() == 1 {
        Ok(bytes)
    } else {
        Err(())
    }
}
