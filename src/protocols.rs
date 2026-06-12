use std::collections::HashMap;

use crypto_bigint::{NonZero, U2048};
use openssl::sha::sha256;

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

pub struct SrpServer {
    n: U2048,
    g: U2048,
    k: U2048,
    users: HashMap<Vec<u8>, (Block, U2048)>,
}

impl SrpServer {
    pub fn new(n: U2048, g: U2048, k: U2048) -> Self {
        SrpServer {
            n,
            g,
            k,
            users: HashMap::new(),
        }
    }

    pub fn register_user(&mut self, i: &[u8], p: &[u8]) {
        let salt = random_block();
        let xh = sha256(&[&salt, p].concat());
        let x = bigint_hex(&hex_encode(&xh));
        let v = modexp(self.g, x, self.n);
        self.users.insert(i.to_vec(), (salt, v));
    }

    pub fn handshake(&mut self, i: &[u8], ga: U2048) -> (Block, U2048, [u8; 32]) {
        let (salt, v) = *self.users.get(&i.to_vec()).unwrap();
        let b = random_biguint(self.n);
        let nz = NonZero::new(self.n).unwrap();

        let kv = self.k.mul_mod(&v, &nz);
        let gb = kv.add_mod(&modexp(self.g, b, self.n), &nz);
        let uh = sha256(&[ga.to_be_bytes().as_slice(), gb.to_be_bytes().as_slice()].concat());
        let u = bigint_hex(&hex_encode(&uh));

        let vu = modexp(v, u, self.n);
        let gavu = ga.mul_mod(&vu, &nz);
        let s = modexp(gavu, b, self.n);
        let key = sha256(s.to_be_bytes().as_slice());

        (salt, gb, key)
    }
}

pub struct SimpleSrpServer {
    n: U2048,
    g: U2048,
    v: U2048,
    salt: Vec<u8>,
}

impl SimpleSrpServer {
    pub fn new(n: U2048, g: U2048, p: &[u8]) -> Self {
        let salt = random_bytes(16);
        let xh = sha256(&[&salt, p].concat());
        let x = bigint_hex(&hex_encode(&xh));
        let v = modexp(g, x, n);
        SimpleSrpServer { n, g, v, salt }
    }

    pub fn handshake(&self, ga: U2048) -> (Vec<u8>, U2048, U2048, [u8; 32]) {
        let nz = NonZero::new(self.n).unwrap();
        let u = bigint_hex(&hex_encode(&random_bytes(16)));
        let b = random_biguint(self.n);
        let gb = modexp(self.g, b, self.n);
        let vu = modexp(self.v, u, self.n);
        let gavu = ga.mul_mod(&vu, &nz);
        let s = modexp(gavu, b, self.n);
        let key = sha256(s.to_be_bytes().as_slice());
        (self.salt.clone(), gb, u, key)
    }
}
