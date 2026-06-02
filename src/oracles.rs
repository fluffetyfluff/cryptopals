use crate::primitives::*;
use itertools::Itertools;
use rand::seq::IteratorRandom;
use rand::{random, random_bool, random_range, rng};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

static RANDOM_KEY: LazyLock<[u8; 16]> = LazyLock::new(|| random_block());
static RANDOM_BYTES: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let num_bytes: usize = random_range(0..64);
    random_bytes(num_bytes)
});

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
        (aes_128_cbc_encrypt(&input, &RANDOM_KEY, &iv).0, decision)
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

pub fn ecb_prefix_postfix_oracle(input: &[u8]) -> Vec<u8> {
    let mut rand_bytes = RANDOM_BYTES.clone();
    rand_bytes.append(&mut input.to_vec());
    ecb_prefix_oracle(&rand_bytes)
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
    kv_decode(str::from_utf8(&profile.unwrap()).unwrap())
}

pub fn cbc_encrypt_oracle(user_data: &[u8]) -> (Vec<u8>, Block) {
    let user_data = String::from_utf8(user_data.to_vec())
        .unwrap()
        .replace(";", "%3B")
        .replace("=", "%3D");
    let input = [
        b"comment1=cooking%20MCs;userdata=",
        user_data.as_bytes(),
        b";comment2=%20like%20a%20pound%20of%20bacon",
    ]
    .concat();
    let input = pkcs_pad(&input);
    aes_128_cbc_encrypt(&input, &RANDOM_KEY, &random_block())
}

pub fn cbc_decrypt_oracle(input: &[u8], iv: &Block) -> bool {
    let decryption = aes_128_cbc_decrypt(input, &RANDOM_KEY, iv);
    let decryption = String::from_utf8_lossy(&decryption);
    decryption.contains(";admin=true;")
}

pub fn padding_cbc_encrypt_oracle() -> (Vec<u8>, Block) {
    let ciphertext_set = HashSet::from([
        b64_decode("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
        b64_decode("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
        b64_decode("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
        b64_decode("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
        b64_decode("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
        b64_decode("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
        b64_decode("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
        b64_decode("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
        b64_decode("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
        b64_decode("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
    ]);
    let mut rng = rng();
    let ciphertext = ciphertext_set.iter().choose(&mut rng).unwrap();
    let ciphertext = pkcs_pad(ciphertext);
    aes_128_cbc_encrypt(&ciphertext, &RANDOM_KEY, &random_block())
}

pub fn padding_cbc_decrypt_oracle(bytes: &[u8], iv: &Block) -> Result<Vec<u8>, ()> {
    let plaintext = aes_128_cbc_decrypt(bytes, &RANDOM_KEY, iv);
    pkcs_unpad(&plaintext)
}

pub fn unix_seeded_mt_oracle() -> u32 {
    let delay = random_range(0..1000);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    Mt19937::new(current_timestamp - delay).rand()
}
