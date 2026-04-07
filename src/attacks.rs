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
