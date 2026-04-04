use phf::phf_map;

const ENGLISH_FREQ: phf::Map<u8, f32> = phf_map! {
    0x0u8  | 0x20u8 => 25.404, // space/null
    0x41u8 | 0x61u8 =>  8.167, // a
    0x42u8 | 0x62u8 =>  1.492, // b
    0x43u8 | 0x63u8 =>  2.782, // c
    0x44u8 | 0x64u8 =>  4.253, // d
    0x45u8 | 0x65u8 => 12.702, // e
    0x46u8 | 0x66u8 =>  2.228, // f
    0x47u8 | 0x67u8 =>  2.015, // g
    0x48u8 | 0x68u8 =>  6.094, // h
    0x49u8 | 0x69u8 =>  6.966, // i
    0x4au8 | 0x6au8 =>  0.153, // j
    0x4bu8 | 0x6bu8 =>  0.772, // k
    0x4cu8 | 0x6cu8 =>  4.025, // l
    0x4du8 | 0x6du8 =>  2.406, // m
    0x4eu8 | 0x6eu8 =>  6.749, // n
    0x4fu8 | 0x6fu8 =>  7.507, // o
    0x50u8 | 0x70u8 =>  1.929, // p
    0x51u8 | 0x71u8 =>  0.095, // q
    0x52u8 | 0x72u8 =>  5.987, // r
    0x53u8 | 0x73u8 =>  6.327, // s
    0x54u8 | 0x74u8 =>  9.056, // t
    0x55u8 | 0x75u8 =>  2.758, // u
    0x56u8 | 0x76u8 =>  0.978, // v
    0x57u8 | 0x77u8 =>  2.360, // w
    0x58u8 | 0x78u8 =>  0.150, // x
    0x59u8 | 0x79u8 =>  1.974, // y
    0x5au8 | 0x7au8 =>  0.074, // z
};

pub fn english_score(str: &str) -> f32 {
    str.bytes()
        .map(|c| ENGLISH_FREQ.get(&c).copied().unwrap_or(0.0))
        .reduce(|acc, e| acc + e)
        .unwrap_or(0.0)
}
