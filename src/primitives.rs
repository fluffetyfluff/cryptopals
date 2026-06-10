use aes::{
    Aes128,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::prelude::*;
use crypto_bigint::{
    OddUint, U2048,
    modular::{FixedMontyForm, FixedMontyParams},
};

pub type Block = [u8; 16];
pub type Nonce = [u8; 8];
pub type Sha1Digest = [u8; 20];
pub type Md4Digest = [u8; 16];

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
            seed = 1812433253u32
                .wrapping_mul(seed ^ (seed >> 30))
                .wrapping_add(i as u32); // seed 7974 makes this crash if not wrapping!
            mt.state_array[i] = seed;
        }
        mt.state_index = 0;
        mt
    }

    pub fn from_state(state: [u32; 624]) -> Self {
        Self {
            state_array: state,
            state_index: 0,
        }
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

pub fn sha_1(bytes: &[u8]) -> Sha1Digest {
    let h0 = 0x67452301u32;
    let h1 = 0xEFCDAB89u32;
    let h2 = 0x98BADCFEu32;
    let h3 = 0x10325476u32;
    let h4 = 0xC3D2E1F0u32;
    sha_1_extend(bytes, 0, h0, h1, h2, h3, h4)
}

pub fn sha_1_extend(
    bytes: &[u8],
    prev_length: usize,
    mut h0: u32,
    mut h1: u32,
    mut h2: u32,
    mut h3: u32,
    mut h4: u32,
) -> Sha1Digest {
    let ml = (prev_length + bytes.len()) * 8;
    let target_length = ml + 1 + (448 - (ml + 1) as i32).rem_euclid(512) as usize;
    let mut preprocessed_bytes: Vec<u8> = Vec::with_capacity(target_length / 8 + 64);
    preprocessed_bytes.extend_from_slice(bytes);
    preprocessed_bytes.push(0x80);
    preprocessed_bytes.resize(target_length / 8 - prev_length, 0x0);
    preprocessed_bytes.extend_from_slice(&(ml as u64).to_be_bytes());

    for chunk in preprocessed_bytes.chunks(64) {
        let mut w: Vec<u32> = Vec::with_capacity(80);
        for i in 0..16 {
            w.push(u32::from_be_bytes(
                chunk[4 * i..4 * i + 4].try_into().unwrap(),
            ));
        }
        for i in 16..80 {
            w.push((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1));
        }
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let f = match i {
                0..20 => (b & c) | (!b & d),
                20..40 => b ^ c ^ d,
                40..60 => (b & c) | (b & d) | (c & d),
                60..80 => b ^ c ^ d,
                _ => panic!("how did we get here? sha1"),
            };
            let k = match i {
                0..20 => 0x5A827999u32,
                20..40 => 0x6ED9EBA1u32,
                40..60 => 0x8F1BBCDCu32,
                60..80 => 0xCA62C1D6u32,
                _ => panic!("how did we get here? sha1"),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut hh = [0x0; 20];
    hh[0..4].copy_from_slice(&h0.to_be_bytes());
    hh[4..8].copy_from_slice(&h1.to_be_bytes());
    hh[8..12].copy_from_slice(&h2.to_be_bytes());
    hh[12..16].copy_from_slice(&h3.to_be_bytes());
    hh[16..20].copy_from_slice(&h4.to_be_bytes());
    hh
}

pub fn md4(bytes: &[u8]) -> Md4Digest {
    md4_extend(bytes, 0, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
}

pub fn md4_extend(
    bytes: &[u8],
    prev_length: usize,
    mut h0: u32,
    mut h1: u32,
    mut h2: u32,
    mut h3: u32,
) -> Md4Digest {
    let ml = (prev_length + bytes.len()) * 8;
    let target_length = ml + 1 + (448 - (ml + 1) as i32).rem_euclid(512) as usize;
    let mut preprocessed_bytes: Vec<u8> = Vec::with_capacity(target_length / 8 + 64);
    preprocessed_bytes.extend_from_slice(bytes);
    preprocessed_bytes.push(0x80);
    preprocessed_bytes.resize(target_length / 8 - prev_length, 0x0);
    preprocessed_bytes.extend_from_slice(&(ml as u64).to_le_bytes());

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (y & z) | (x & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    for chunk in preprocessed_bytes.chunks(64) {
        let mut x: Vec<u32> = Vec::with_capacity(16);
        for i in 0..16 {
            x.push(u32::from_le_bytes(
                chunk[4 * i..4 * i + 4].try_into().unwrap(),
            ));
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;

        // round 1
        a = (a.wrapping_add(f(b, c, d)).wrapping_add(x[0])).rotate_left(3);
        d = (d.wrapping_add(f(a, b, c)).wrapping_add(x[1])).rotate_left(7);
        c = (c.wrapping_add(f(d, a, b)).wrapping_add(x[2])).rotate_left(11);
        b = (b.wrapping_add(f(c, d, a)).wrapping_add(x[3])).rotate_left(19);
        a = (a.wrapping_add(f(b, c, d)).wrapping_add(x[4])).rotate_left(3);
        d = (d.wrapping_add(f(a, b, c)).wrapping_add(x[5])).rotate_left(7);
        c = (c.wrapping_add(f(d, a, b)).wrapping_add(x[6])).rotate_left(11);
        b = (b.wrapping_add(f(c, d, a)).wrapping_add(x[7])).rotate_left(19);
        a = (a.wrapping_add(f(b, c, d)).wrapping_add(x[8])).rotate_left(3);
        d = (d.wrapping_add(f(a, b, c)).wrapping_add(x[9])).rotate_left(7);
        c = (c.wrapping_add(f(d, a, b)).wrapping_add(x[10])).rotate_left(11);
        b = (b.wrapping_add(f(c, d, a)).wrapping_add(x[11])).rotate_left(19);
        a = (a.wrapping_add(f(b, c, d)).wrapping_add(x[12])).rotate_left(3);
        d = (d.wrapping_add(f(a, b, c)).wrapping_add(x[13])).rotate_left(7);
        c = (c.wrapping_add(f(d, a, b)).wrapping_add(x[14])).rotate_left(11);
        b = (b.wrapping_add(f(c, d, a)).wrapping_add(x[15])).rotate_left(19);

        // round 2
        a = (a.wrapping_add(g(b, c, d).wrapping_add(x[0]).wrapping_add(0x5A827999))).rotate_left(3);
        d = (d.wrapping_add(g(a, b, c).wrapping_add(x[4]).wrapping_add(0x5A827999))).rotate_left(5);
        c = (c.wrapping_add(g(d, a, b).wrapping_add(x[8]).wrapping_add(0x5A827999))).rotate_left(9);
        b = (b.wrapping_add(g(c, d, a).wrapping_add(x[12]).wrapping_add(0x5A827999)))
            .rotate_left(13);
        a = (a.wrapping_add(g(b, c, d).wrapping_add(x[1]).wrapping_add(0x5A827999))).rotate_left(3);
        d = (d.wrapping_add(g(a, b, c).wrapping_add(x[5]).wrapping_add(0x5A827999))).rotate_left(5);
        c = (c.wrapping_add(g(d, a, b).wrapping_add(x[9]).wrapping_add(0x5A827999))).rotate_left(9);
        b = (b.wrapping_add(g(c, d, a).wrapping_add(x[13]).wrapping_add(0x5A827999)))
            .rotate_left(13);
        a = (a.wrapping_add(g(b, c, d).wrapping_add(x[2]).wrapping_add(0x5A827999))).rotate_left(3);
        d = (d.wrapping_add(g(a, b, c).wrapping_add(x[6]).wrapping_add(0x5A827999))).rotate_left(5);
        c = (c.wrapping_add(g(d, a, b).wrapping_add(x[10]).wrapping_add(0x5A827999)))
            .rotate_left(9);
        b = (b.wrapping_add(g(c, d, a).wrapping_add(x[14]).wrapping_add(0x5A827999)))
            .rotate_left(13);
        a = (a.wrapping_add(g(b, c, d).wrapping_add(x[3]).wrapping_add(0x5A827999))).rotate_left(3);
        d = (d.wrapping_add(g(a, b, c).wrapping_add(x[7]).wrapping_add(0x5A827999))).rotate_left(5);
        c = (c.wrapping_add(g(d, a, b).wrapping_add(x[11]).wrapping_add(0x5A827999)))
            .rotate_left(9);
        b = (b.wrapping_add(g(c, d, a).wrapping_add(x[15]).wrapping_add(0x5A827999)))
            .rotate_left(13);

        // round 3
        a = (a.wrapping_add(h(b, c, d).wrapping_add(x[0]).wrapping_add(0x6ED9EBA1))).rotate_left(3);
        d = (d.wrapping_add(h(a, b, c).wrapping_add(x[8]).wrapping_add(0x6ED9EBA1))).rotate_left(9);
        c = (c.wrapping_add(h(d, a, b).wrapping_add(x[4]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(11);
        b = (b.wrapping_add(h(c, d, a).wrapping_add(x[12]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(15);
        a = (a.wrapping_add(h(b, c, d).wrapping_add(x[2]).wrapping_add(0x6ED9EBA1))).rotate_left(3);
        d = (d.wrapping_add(h(a, b, c).wrapping_add(x[10]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(9);
        c = (c.wrapping_add(h(d, a, b).wrapping_add(x[6]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(11);
        b = (b.wrapping_add(h(c, d, a).wrapping_add(x[14]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(15);
        a = (a.wrapping_add(h(b, c, d).wrapping_add(x[1]).wrapping_add(0x6ED9EBA1))).rotate_left(3);
        d = (d.wrapping_add(h(a, b, c).wrapping_add(x[9]).wrapping_add(0x6ED9EBA1))).rotate_left(9);
        c = (c.wrapping_add(h(d, a, b).wrapping_add(x[5]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(11);
        b = (b.wrapping_add(h(c, d, a).wrapping_add(x[13]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(15);
        a = (a.wrapping_add(h(b, c, d).wrapping_add(x[3]).wrapping_add(0x6ED9EBA1))).rotate_left(3);
        d = (d.wrapping_add(h(a, b, c).wrapping_add(x[11]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(9);
        c = (c.wrapping_add(h(d, a, b).wrapping_add(x[7]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(11);
        b = (b.wrapping_add(h(c, d, a).wrapping_add(x[15]).wrapping_add(0x6ED9EBA1)))
            .rotate_left(15);

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }
    let mut hh = [0x0; 16];
    hh[0..4].copy_from_slice(&h0.to_le_bytes());
    hh[4..8].copy_from_slice(&h1.to_le_bytes());
    hh[8..12].copy_from_slice(&h2.to_le_bytes());
    hh[12..16].copy_from_slice(&h3.to_le_bytes());
    hh
}

pub fn bigint(i: u64) -> U2048 {
    U2048::from(i)
}

pub fn bigint_hex(i: &str) -> U2048 {
    U2048::from_be_hex(&format!("{:0>512}", i))
}

pub fn modexp(base: U2048, pow: U2048, modulus: U2048) -> U2048 {
    let modulus = OddUint::new(modulus).unwrap();
    let params = FixedMontyParams::new(modulus);
    let base = FixedMontyForm::new(&base, &params);
    base.pow(&pow).retrieve()
}
