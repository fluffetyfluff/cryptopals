use std::sync::LazyLock;

use crate::primitives::*;
use rand::{random, random_bool, random_range};

static RANDOM_KEY: LazyLock<[u8; 16]> = LazyLock::new(|| random_block());

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for _ in 0..n {
        bytes.push(random())
    }
    bytes
}

pub fn random_block() -> Block {
    random()
}

pub fn ecb_or_cbc_encrypt_oracle(input: &[u8]) -> (Vec<u8>, bool) {
    let decision = random_bool(0.5);
    let mut random_padding_before = random_bytes(random_range(5..=10));
    let mut input = input.to_vec();
    let mut random_padding_after = random_bytes(random_range(5..=10));
    random_padding_before.append(&mut input);
    random_padding_before.append(&mut random_padding_after);
    let input = pkcs_pad(&random_padding_before);

    if decision {
        let iv = random_block();
        (aes_128_cbc_encrypt(&input, &RANDOM_KEY, &iv), decision)
    } else {
        (aes_128_ecb_encrypt(&input, &RANDOM_KEY), decision)
    }
}

pub fn ecb_prefix_oracle(input: &[u8]) -> Vec<u8> {
    let content = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                   YnkK";
    let mut content = b64_decode(content);
    let mut input = input.to_vec();
    input.append(&mut content);
    let input = pkcs_pad(&input);
    aes_128_ecb_decrypt(&input, &RANDOM_KEY)
}
