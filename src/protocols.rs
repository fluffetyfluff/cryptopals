use crypto_bigint::U2048;

use crate::{oracles::*, primitives::*};

pub struct DhEchoServer {
    key: Block,
}

impl DhEchoServer {
    pub fn new(p: U2048, g: U2048, ga: U2048) -> (Self, U2048) {
        let b = random_biguint(p);
        let s = modexp(ga, b, p);
        let gb = modexp(g, b, p);
        let key: [u8; 16] = sha_1(&s.to_be_bytes())[..16].try_into().unwrap();
        let server = DhEchoServer { key };
        (server, gb)
    }

    pub fn echo(&self, message: &[u8], iv: Block) -> (Vec<u8>, Block) {
        let plaintext = aes_128_cbc_decrypt(message, &self.key, &iv);
        let new_iv = random_block();
        aes_128_cbc_encrypt(&plaintext, &self.key, &new_iv)
    }
}
