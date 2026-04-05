use crate::language::*;
use crate::primitives::*;

pub fn one_byte_xor(input: &[u8]) -> (String, f32) {
    let mut best: String = String::from("no good match");
    let mut best_score: f32 = -1.0;
    for byte in 0x00u8..=0xffu8 {
        let mask = vec![byte; input.len()];
        let output = xor(input, &mask);
        if let Ok(output_str) = String::from_utf8(output) {
            let score = english_score(&output_str);
            if score > best_score {
                best = output_str;
                best_score = score;
            }
        }
    }
    (best, best_score)
}
