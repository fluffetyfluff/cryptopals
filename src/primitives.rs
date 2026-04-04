use base64::prelude::*;
use hex;

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
