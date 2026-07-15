use crypto_bigint::OddUint;
use crypto_bigint::{NonZero, U2048};
use std::collections::HashMap;

use crate::language::*;
use crate::oracles::*;
use crate::primitives::*;

pub fn one_byte_xor(input: &[u8]) -> (String, u8, f32) {
    (0x00u8..=0xffu8)
        .map(|byte| {
            if let Ok(output_str) = String::from_utf8(repeating_xor(input, &[byte])) {
                let score = english_score(&output_str);
                (output_str, byte, score)
            } else {
                (String::from("no good match"), 0x00, -1.0f32)
            }
        })
        .max_by(|(_, _, a), (_, _, b)| a.total_cmp(b))
        .unwrap_or((String::from("no good match"), 0x00, -1.0))
}

pub fn untemper_mt19937(output: u32) -> u32 {
    let left_18 = output & 0xFFFFC000;
    let right_14 = (output & 0x00003FFF) ^ (left_18 >> 18);
    let output = left_18 | right_14;

    let right_15 = output & 0x00007FFF;
    let middle_15 = (output & 0x3FFF8000) ^ ((right_15 << 15) & 0xEFC60000);
    let left_2 = (output & 0xC0000000) ^ ((middle_15 << 15) & 0xEFC60000);
    let output = left_2 | middle_15 | right_15;

    let right_7 = output & 0x0000007F;
    let mid_right_7 = (output & 0x00003F80) ^ ((right_7 << 7) & 0x9D2C5680);
    let mid_mid_7 = (output & 0x001FC000) ^ ((mid_right_7 << 7) & 0x9D2C5680);
    let mid_left_7 = (output & 0x0FE00000) ^ ((mid_mid_7 << 7) & 0x9D2C5680);
    let left_4 = (output & 0xF0000000) ^ ((mid_left_7 << 7) & 0x9D2C5680);
    let output = left_4 | mid_left_7 | mid_mid_7 | mid_right_7 | right_7;

    let left_11 = output & 0xFFE00000;
    let middle_11 = (output & 0x001FFC00) ^ (left_11 >> 11);
    let right_10 = (output & 0x000003FF) ^ (middle_11 >> 11);
    let output = left_11 | middle_11 | right_10;
    output
}

pub fn cube_root(n: &U2048) -> U2048 {
    let one = U2048::ONE;
    let zero = U2048::ZERO;
    if *n == zero || *n == one {
        return *n;
    }

    let bits = n.bits();
    let mut x = one.shl((bits + 2) / 3);

    if x == zero {
        x = one;
    }

    let mut x_old = U2048::MAX;

    let two = bigint(2);
    let three = bigint(3);

    while x < x_old {
        x_old = x;

        let x_2 = x.wrapping_mul(&x);
        let n_x_2 = n.wrapping_div(&NonZero::new(x_2).unwrap());

        let sum = x.wrapping_mul(&two).wrapping_add(&n_x_2);

        x = sum.wrapping_div(&NonZero::new(three).unwrap());
    }

    x_old
}

pub fn dsa_key_recovery(r: &U2048, s: &U2048, k: &U2048, hash: &U2048) -> U2048 {
    let q = bigint_hex("f4f47f05794b256174bba6e9b396a7707e563c5b");
    let q = &NonZero::new(q).unwrap();
    let r_1 = modinv(r, q).unwrap();
    let sk = s.mul_mod(k, q);
    r_1.mul_mod(&sk.sub_mod(hash, q), q)
}

pub fn bleichenbacher(
    c: &U2048,
    e: &U2048,
    n: &OddUint<{ U2048::LIMBS }>,
    oracle: impl Fn(&U2048) -> bool,
    bit_length: u32,
) -> U2048 {
    assert!(bit_length % 8 == 0);
    let one = U2048::ONE;
    let two = bigint(2);
    let three = bigint(3);

    let big_b = U2048::ONE.shl(bit_length - 16);
    let b2 = big_b.wrapping_mul(&two);
    let b3 = big_b.wrapping_mul(&three);
    let b3_1 = b3.wrapping_sub(&one);

    // can assume message already conforms here, skip step 1
    let mut s_i1 = one;
    let c_0 = c;
    let mut m_i1 = vec![(b2, b3_1)];

    let mut i = 1;

    loop {
        let s_i;

        if i == 1 {
            // 2.a
            let mut s_temp = n.get().wrapping_div(&NonZero::new(b3).unwrap());
            loop {
                let s_e = modexp(&s_temp, e, n);
                let cs_e = c_0.mul_mod(&s_e, n.as_nz_ref());
                if oracle(&cs_e) {
                    s_i = s_temp;
                    break;
                }
                s_temp = s_temp.wrapping_add(&one);
            }
        } else if m_i1.len() > 1 {
            // 2.b
            let mut s_temp = s_i1;
            loop {
                s_temp = s_temp.wrapping_add(&one);
                let s_e = modexp(&s_temp, e, n);
                let cs_e = c_0.mul_mod(&s_e, n.as_nz_ref());
                if oracle(&cs_e) {
                    s_i = s_temp;
                    break;
                }
            }
        } else {
            // 2.c
            let (a, b) = m_i1[0];
            let a_nz = NonZero::new(a).unwrap();
            let b_nz = NonZero::new(b).unwrap();
            let bs_i1b2 = b.wrapping_mul(&s_i1).wrapping_sub(&b2).wrapping_mul(&two);
            let mut r_i = ceil_div(&bs_i1b2, n.as_nz_ref());
            's: loop {
                let r_in = r_i.wrapping_mul(&n);
                let mut s_temp = r_in.wrapping_add(&b2).wrapping_div(&b_nz);
                let upper_bound = r_in.wrapping_add(&b3).wrapping_div(&a_nz);

                while s_temp <= upper_bound {
                    let s_e = modexp(&s_temp, e, n);
                    let cs_e = c_0.mul_mod(&s_e, n.as_nz_ref());
                    if oracle(&cs_e) {
                        s_i = s_temp;
                        break 's;
                    }
                    s_temp = s_temp.wrapping_add(&one);
                }
                r_i = r_i.wrapping_add(&one);
            }
        }

        // 3
        let mut m_i = Vec::new();
        let s_inz = NonZero::new(s_i).unwrap();
        i += 1;

        for interval in m_i1 {
            let (a, b) = interval;
            let as_i = a.wrapping_mul(&s_i);
            let bs_i = b.wrapping_mul(&s_i);
            let mut r = as_i.wrapping_sub(&b3_1).wrapping_div(n.as_nz_ref());
            let upper_bound = bs_i.wrapping_sub(&b2).wrapping_div(n.as_nz_ref());

            while r <= upper_bound {
                let rn = r.wrapping_mul(&n);
                let a_temp = ceil_div(&b2.wrapping_add(&rn), &s_inz);
                let b_temp = b3.wrapping_add(&rn).wrapping_div(&s_inz);
                let new_a = if a_temp > a { a_temp } else { a };
                let new_b = if b_temp < b { b_temp } else { b };
                if new_a <= new_b {
                    m_i.push((new_a, new_b));
                }
                r = r.wrapping_add(&one);
            }
        }

        m_i1 = merge_intervals(m_i);
        s_i1 = s_i;

        if m_i1.len() == 1 && m_i1[0].0 == m_i1[0].1 {
            return m_i1[0].0;
        }
    }
}

fn merge_intervals(mut list: Vec<(U2048, U2048)>) -> Vec<(U2048, U2048)> {
    if list.is_empty() {
        return list;
    }

    list.sort_by(|x, y| x.0.cmp_vartime(&y.0));

    let mut merged = vec![list[0].clone()];
    for entry in list.into_iter().skip(1) {
        let last = merged.last_mut().unwrap();
        if entry.0 <= last.1.wrapping_add(&U2048::ONE) {
            if entry.1 > last.1 {
                last.1 = entry.1;
            }
        } else {
            merged.push(entry);
        }
    }
    merged
}

fn ceil_div(num: &U2048, denom: &NonZero<U2048>) -> U2048 {
    let (quot, rem) = num.div_rem(denom);
    if rem == U2048::ZERO {
        quot
    } else {
        quot.wrapping_add(&U2048::ONE)
    }
}

pub fn find_collisions<const N: usize>(length: usize) -> Vec<(u64, u64)> {
    let mut colliding_pairs: Vec<(u64, u64)> = Vec::new();
    let mut state = [0x00u8; N];
    let mut prev_len = 0;
    for _ in 0..length {
        let mut map: HashMap<[u8; N], u64> = HashMap::new();
        let mut attempt: u64 = 0;
        loop {
            let hash: [u8; N] = aes_md_extend(&attempt.to_be_bytes(), prev_len, state);
            if let Some(collision) = map.insert(hash, attempt) {
                colliding_pairs.push((attempt, collision));
                state = hash;
                prev_len += 16;
                break;
            }
            attempt += 1;
        }
    }
    colliding_pairs
}

pub fn repad_collision(data: &[u64]) -> Vec<u8> {
    let mut ans = Vec::new();
    let mut prev_len = 0;

    for block in data {
        let padded = md_pad(&block.to_be_bytes(), 16, 4, prev_len);
        ans.extend(padded);
        prev_len += 16;
    }

    ans.resize(ans.len() - 8, 0x00);
    ans
}

pub fn find_expandable_collisions<const N: usize>(k: usize) -> Vec<(u128, u128)> {
    let mut colliding_pairs: Vec<(u128, u128)> = Vec::new();
    let mut state = [0x00u8; N];
    for i in 0..k as u128 {
        let mut map: HashMap<[u8; N], u128> = HashMap::new();
        let mut attempt = 0u128;
        let mut extended_state = state.clone();
        for _ in 0..(1 << i) {
            extended_state = aes_md_extend_block(&[0; 16], &extended_state);
        }
        loop {
            let attempt_bytes = &attempt.to_be_bytes();
            let single_hash: [u8; N] = aes_md_extend_block(attempt_bytes, &state);
            let extended_hash: [u8; N] = aes_md_extend_block(attempt_bytes, &extended_state);
            map.insert(single_hash, attempt);
            if let Some(single) = map.get(&extended_hash) {
                colliding_pairs.push((*single, attempt));
                state = extended_hash;
                break;
            }
            attempt += 1;
        }
    }
    colliding_pairs
}

pub fn expandable_message(collisions: &Vec<(u128, u128)>, len: usize) -> Vec<u8> {
    let k = collisions.len();
    assert!(k <= len && len < (1 << k) - 1 + k);
    let mut target = len - k;
    let mut ans: Vec<u8> = Vec::new();
    for i in 0..k {
        let (single, extended) = collisions[i];
        if target % 2 == 0 {
            ans.extend_from_slice(&single.to_be_bytes());
        } else {
            for _ in 0..(1 << i) {
                ans.extend_from_slice(&[0; 16]);
            }
            ans.extend_from_slice(&extended.to_be_bytes());
        }
        target = target >> 1;
    }
    ans
}

pub struct NostradamusFunnel<const N: usize> {
    k: usize,
    maps: Vec<HashMap<[u8; N], u128>>,
    final_state: [u8; N],
}

impl NostradamusFunnel<2> {
    pub fn new(k: usize) -> Self {
        let mut maps: Vec<HashMap<[u8; 2], u128>> = Vec::new();
        let mut states: Vec<[u8; 2]> = (0u16..(1 << k))
            .map(|u| u.to_be_bytes().try_into().unwrap())
            .collect();

        for _ in 0..k {
            let mut new_states: Vec<[u8; 2]> = Vec::new();
            let mut map: HashMap<[u8; 2], u128> = HashMap::new();

            for chunk in states.chunks_exact(2) {
                let first = chunk[0];
                let second = chunk[1];
                let mut collision_map: HashMap<[u8; 2], u128> = HashMap::new();
                let mut attempt = 0u128;
                loop {
                    let first_state = aes_md_extend_block(&attempt.to_be_bytes(), &first);
                    let second_state = aes_md_extend_block(&attempt.to_be_bytes(), &second);
                    if let Some(&collision) = collision_map.get(&second_state) {
                        new_states.push(second_state);
                        map.insert(first, collision);
                        map.insert(second, attempt);
                        break;
                    }
                    collision_map.insert(first_state, attempt);
                    attempt += 1;
                }
            }
            maps.push(map);
            states = new_states;
        }

        assert!(states.len() == 1);
        let final_state = states[0];

        Self {
            k,
            maps,
            final_state,
        }
    }

    pub fn in_collision_surface(&self, state: &[u8; 2]) -> bool {
        self.maps[0].contains_key(state)
    }

    pub fn collision_surface(&self) -> Vec<&[u8; 2]> {
        self.maps[0].keys().collect()
    }

    pub fn final_state(&self) -> [u8; 2] {
        self.final_state
    }

    pub fn construct_collision_chain(&self, state: &[u8; 2]) -> Vec<u8> {
        let mut ans: Vec<u8> = Vec::new();
        let mut state = *state;
        for i in 0..self.k {
            let bridge = self.maps[i].get(&state).unwrap().to_be_bytes();

            ans.extend_from_slice(&bridge);
            state = aes_md_extend_block(&bridge, &state);
        }
        ans
    }
}

enum ConstraintType {
    Eq,
    Zero,
    One,
}

struct Constraint(ConstraintType, u32);

pub fn weak_message() -> Vec<u32> {
    use ConstraintType::*;

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn phi1(a: u32, b: u32, c: u32, d: u32, m: u32, s: u32) -> u32 {
        a.wrapping_add(f(b, c, d)).wrapping_add(m).rotate_left(s)
    }
    fn phi2(a: u32, b: u32, c: u32, d: u32, m: u32, s: u32) -> u32 {
        a.wrapping_add(g(b, c, d))
            .wrapping_add(m)
            .wrapping_add(0x5a827999)
            .rotate_left(s)
    }

    fn phi1_inv(a: u32, b: u32, c: u32, d: u32, next_a: u32, s: u32) -> u32 {
        next_a
            .rotate_right(s)
            .wrapping_sub(a)
            .wrapping_sub(f(b, c, d))
    }
    fn phi2_inv(a: u32, b: u32, c: u32, d: u32, next_a: u32, s: u32) -> u32 {
        next_a
            .rotate_right(s)
            .wrapping_sub(a)
            .wrapping_sub(g(b, c, d))
            .wrapping_sub(0x5A827999)
    }

    fn constrain(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        m: &mut Vec<u32>,
        i: usize,
        s: u32,
        constraints: &[Constraint],
    ) -> u32 {
        let mut next_a = phi1(a, b, c, d, m[i], s);
        for Constraint(t, i) in constraints.iter() {
            match t {
                Eq => next_a ^= (next_a & (1 << i)) ^ (b & (1 << i)),
                Zero => next_a ^= (next_a & (1 << i)) ^ 0,
                One => next_a ^= (next_a & (1 << i)) ^ (1 << i),
            }
        }
        m[i] = phi1_inv(a, b, c, d, next_a, s);
        next_a
    }

    let random_message = random_bytes(64);
    let mut m: Vec<u32> = Vec::new();
    for chunk in random_message.as_chunks::<4>().0 {
        let u = u32::from_le_bytes(*chunk);
        m.push(u);
    }

    let a = 0x67452301u32;
    let b = 0xefcdab89u32;
    let c = 0x98badcfeu32;
    let d = 0x10325476u32;
    let mut a_vec: Vec<u32> = vec![a];
    let mut b_vec: Vec<u32> = vec![b];
    let mut c_vec: Vec<u32> = vec![c];
    let mut d_vec: Vec<u32> = vec![d];

    // round 1
    let constraints = vec![Constraint(Eq, 6)];
    let a = constrain(a, b, c, d, &mut m, 0, 3, &constraints);
    a_vec.push(a);

    // round 2
    let constraints = vec![Constraint(Zero, 6), Constraint(Eq, 7), Constraint(Eq, 10)];
    let d = constrain(d, a, b, c, &mut m, 1, 7, &constraints);
    d_vec.push(d);

    // round 3
    let constraints = vec![
        Constraint(One, 6),
        Constraint(One, 7),
        Constraint(Zero, 10),
        Constraint(Eq, 25),
    ];
    let c = constrain(c, d, a, b, &mut m, 2, 11, &constraints);
    c_vec.push(c);

    // round 4
    let constraints = vec![
        Constraint(One, 6),
        Constraint(Zero, 7),
        Constraint(Zero, 10),
        Constraint(Zero, 25),
    ];
    let b = constrain(b, c, d, a, &mut m, 3, 19, &constraints);
    b_vec.push(b);

    // round 5
    let constraints = vec![
        Constraint(One, 7),
        Constraint(One, 10),
        Constraint(Eq, 13),
        Constraint(Zero, 25),
    ];
    let a = constrain(a, b, c, d, &mut m, 4, 3, &constraints);
    a_vec.push(a);

    // round 6
    let constraints = vec![
        Constraint(Zero, 13),
        Constraint(Eq, 18),
        Constraint(Eq, 19),
        Constraint(Eq, 20),
        Constraint(Eq, 21),
        Constraint(One, 25),
    ];
    let d = constrain(d, a, b, c, &mut m, 5, 7, &constraints);
    d_vec.push(d);

    // round 7
    let constraints = vec![
        Constraint(Eq, 12),
        Constraint(Zero, 13),
        Constraint(Eq, 14),
        Constraint(Zero, 18),
        Constraint(Zero, 19),
        Constraint(One, 20),
        Constraint(Zero, 21),
    ];
    let c = constrain(c, d, a, b, &mut m, 6, 11, &constraints);
    c_vec.push(c);

    // round 8
    let constraints = vec![
        Constraint(One, 12),
        Constraint(One, 13),
        Constraint(Zero, 14),
        Constraint(Eq, 16),
        Constraint(Zero, 18),
        Constraint(Zero, 19),
        Constraint(Zero, 20),
        Constraint(Zero, 21),
    ];
    let b = constrain(b, c, d, a, &mut m, 7, 19, &constraints);
    b_vec.push(b);

    // round 9
    let constraints = vec![
        Constraint(One, 12),
        Constraint(One, 13),
        Constraint(One, 14),
        Constraint(Zero, 16),
        Constraint(Zero, 18),
        Constraint(Zero, 19),
        Constraint(Zero, 20),
        Constraint(One, 21),
        Constraint(Eq, 22),
        Constraint(Eq, 25),
    ];
    let a = constrain(a, b, c, d, &mut m, 8, 3, &constraints);
    a_vec.push(a);

    // round 10
    let constraints = vec![
        Constraint(One, 12),
        Constraint(One, 13),
        Constraint(One, 14),
        Constraint(Zero, 16),
        Constraint(Zero, 19),
        Constraint(One, 20),
        Constraint(One, 21),
        Constraint(Zero, 22),
        Constraint(One, 25),
        Constraint(Eq, 29),
    ];
    let d = constrain(d, a, b, c, &mut m, 9, 7, &constraints);
    d_vec.push(d);

    // round 11
    let constraints = vec![
        Constraint(One, 16),
        Constraint(Zero, 19),
        Constraint(Zero, 20),
        Constraint(Zero, 21),
        Constraint(Zero, 22),
        Constraint(Zero, 25),
        Constraint(One, 29),
        Constraint(Eq, 31),
    ];
    let c = constrain(c, d, a, b, &mut m, 10, 11, &constraints);
    c_vec.push(c);

    // round 12
    let constraints = vec![
        Constraint(Zero, 19),
        Constraint(One, 20),
        Constraint(One, 21),
        Constraint(Eq, 22),
        Constraint(One, 25),
        Constraint(Zero, 29),
        Constraint(Zero, 31),
    ];
    let b = constrain(b, c, d, a, &mut m, 11, 19, &constraints);
    b_vec.push(b);

    // round 13
    let constraints = vec![
        Constraint(Zero, 22),
        Constraint(Zero, 25),
        Constraint(Eq, 26),
        Constraint(Eq, 28),
        Constraint(One, 29),
        Constraint(Zero, 31),
    ];
    let a = constrain(a, b, c, d, &mut m, 12, 3, &constraints);
    a_vec.push(a);

    // round 14
    let constraints = vec![
        Constraint(Zero, 22),
        Constraint(Zero, 25),
        Constraint(One, 26),
        Constraint(One, 28),
        Constraint(Zero, 29),
        Constraint(One, 31),
    ];
    let d = constrain(d, a, b, c, &mut m, 13, 7, &constraints);
    d_vec.push(d);

    // round 15
    let constraints = vec![
        Constraint(Eq, 18),
        Constraint(One, 22),
        Constraint(One, 25),
        Constraint(Zero, 26),
        Constraint(Zero, 28),
        Constraint(Zero, 29),
    ];
    let c = constrain(c, d, a, b, &mut m, 14, 11, &constraints);
    c_vec.push(c);

    // round 16
    let constraints = vec![
        Constraint(Zero, 18),
        Constraint(Eq, 25),
        Constraint(One, 26),
        Constraint(One, 28),
        Constraint(Zero, 29),
        Constraint(Eq, 31),
    ];
    let b = constrain(b, c, d, a, &mut m, 15, 19, &constraints);
    b_vec.push(b);

    // a5
    let mut a5 = phi2(a, b, c, d, m[0], 3);
    a5 ^= (a5 & (1 << 18)) ^ (c & (1 << 18));
    a5 ^= (a5 & (1 << 25)) ^ (1 << 25);
    a5 ^= (a5 & (1 << 26)) ^ 0;
    a5 ^= (a5 & (1 << 28)) ^ (1 << 28);
    a5 ^= (a5 & (1 << 31)) ^ (1 << 31);
    m[0] = phi2_inv(a, b, c, d, a5, 3);
    a_vec[1] = phi1(a_vec[0], b_vec[0], c_vec[0], d_vec[0], m[0], 3);

    m[1] = phi1_inv(d_vec[0], a_vec[1], b_vec[0], c_vec[0], d_vec[1], 7);
    m[2] = phi1_inv(c_vec[0], d_vec[1], a_vec[1], b_vec[0], c_vec[1], 11);
    m[3] = phi1_inv(b_vec[0], c_vec[1], d_vec[1], a_vec[1], b_vec[1], 19);
    m[4] = phi1_inv(a_vec[1], b_vec[1], c_vec[1], d_vec[1], a_vec[2], 3);
    a_vec.push(a5);
    let a = a5;

    // d5
    let mut d5 = phi2(d, a, b, c, m[4], 5);
    d5 ^= (d5 & (1 << 18)) ^ (a & (1 << 18));
    d5 ^= (d5 & (1 << 25)) ^ (b & (1 << 25));
    d5 ^= (d5 & (1 << 26)) ^ (b & (1 << 26));
    d5 ^= (d5 & (1 << 28)) ^ (b & (1 << 28));
    d5 ^= (d5 & (1 << 31)) ^ (b & (1 << 31));
    m[4] = phi2_inv(d, a, b, c, d5, 5);
    a_vec[2] = phi1(a_vec[1], b_vec[1], c_vec[1], d_vec[1], m[4], 3);

    m[5] = phi1_inv(d_vec[1], a_vec[2], b_vec[1], c_vec[1], d_vec[2], 7);
    m[6] = phi1_inv(c_vec[1], d_vec[2], a_vec[2], b_vec[1], c_vec[2], 11);
    m[7] = phi1_inv(b_vec[1], c_vec[2], d_vec[2], a_vec[2], b_vec[2], 19);
    m[8] = phi1_inv(a_vec[2], b_vec[2], c_vec[2], d_vec[2], a_vec[3], 3);
    d_vec.push(d5);
    let d = d5;

    // c5
    let mut c5 = phi2(c, d, a, b, m[8], 9);
    c5 ^= (c5 & (1 << 25)) ^ (d & (1 << 25));
    c5 ^= (c5 & (1 << 26)) ^ (d & (1 << 26));
    c5 ^= (c5 & (1 << 28)) ^ (d & (1 << 28));
    c5 ^= (c5 & (1 << 29)) ^ (d & (1 << 29));
    c5 ^= (c5 & (1 << 31)) ^ (d & (1 << 31));
    m[8] = phi2_inv(c, d, a, b, c5, 9);
    a_vec[3] = phi1(a_vec[2], b_vec[2], c_vec[2], d_vec[2], m[8], 3);

    m[9] = phi1_inv(d_vec[2], a_vec[3], b_vec[2], c_vec[2], d_vec[3], 7);
    m[10] = phi1_inv(c_vec[2], d_vec[3], a_vec[3], b_vec[2], c_vec[3], 11);
    m[11] = phi1_inv(b_vec[2], c_vec[3], d_vec[3], a_vec[3], b_vec[3], 19);
    m[12] = phi1_inv(a_vec[3], b_vec[3], c_vec[3], d_vec[3], a_vec[4], 3);
    c_vec.push(c5);
    let c = c5;

    m
}
