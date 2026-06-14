use crypto_bigint::{CheckedAdd, U2048};

use crate::language::*;
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
    if *n == U2048::ZERO || *n == U2048::ONE {
        return *n;
    }

    let bits = n.bits();
    let mut x = U2048::ONE << ((bits + 2) / 3);

    if x == U2048::ZERO {
        x = U2048::ONE;
    }

    let mut x_old = U2048::MAX;

    let two = bigint(2);
    let three = bigint(3);

    while x < x_old {
        x_old = x;

        let x2 = x.checked_mul(&x).unwrap();
        let n_over_x2 = n.checked_div(&x2).unwrap();

        let sum = x
            .checked_mul(&two)
            .unwrap()
            .checked_add(&n_over_x2)
            .unwrap();

        x = sum.checked_div(&three).unwrap();
    }

    x_old
}
