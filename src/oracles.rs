use crate::primitives::*;
use rand::{random, random_bool, random_range};

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for _ in 0..n {
        bytes.push(random())
    }
    bytes
}

pub fn ecb_or_cbc_encrypt_oracle(input: &[u8]) -> Vec<u8> {
    let key = random_bytes(16);
    let decision = random_bool(0.5);
    let mut random_padding_before = random_bytes(random_range(5..=10));
    let mut input = input.to_vec();
    let mut random_padding_after = random_bytes(random_range(5..=10));
    random_padding_before.append(&mut input);
    random_padding_before.append(&mut random_padding_after);
    let input = pkcs_pad(&random_padding_before);

    if decision {
        let iv = random_bytes(16);
        aes_128_cbc_encrypt(&input, &key, &iv)
    } else {
        aes_128_ecb_encrypt(&input, &key)
    }
}
