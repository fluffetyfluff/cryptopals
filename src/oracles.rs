use crate::primitives::*;
use itertools::Itertools;
use rand::{random, random_bool, random_range};
use std::collections::HashMap;
use std::sync::LazyLock;

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

pub fn kv_decode(string: &str) -> Result<HashMap<String, String>, ()> {
    let kv_pairs = string.split('&');
    let mut map = HashMap::new();
    for pair in kv_pairs {
        let (key, value) = pair.split('=').collect_tuple().ok_or(())?;
        map.insert(String::from(key), String::from(value));
    }
    Ok(map)
}

pub fn create_profile(user_email: &str) -> String {
    let mut user_email = String::from(user_email);
    user_email.retain(|c| !(c == '&' || c == '='));
    format!("email={0}&uid={1}&role={2}", user_email, 10, "user")
}

pub fn profile_oracle(user_email: &str) -> Vec<u8> {
    let profile = create_profile(user_email);
    let profile = pkcs_pad(profile.as_bytes());
    aes_128_ecb_encrypt(&profile, &RANDOM_KEY)
}

pub fn profile_decrypt_oracle(profile: &[u8]) -> Result<HashMap<String, String>, ()> {
    let profile = aes_128_ecb_decrypt(profile, &RANDOM_KEY);
    let profile = pkcs_unpad(&profile);
    kv_decode(str::from_utf8(&profile).unwrap())
}
