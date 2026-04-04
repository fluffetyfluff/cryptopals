const ENGLISH_LETTER_FREQ: [f32; 26] = [
    8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.16, 0.77, 4.0, 2.4, 6.7, 7.5, 1.0, 0.12, 6.0,
    6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074,
];

fn cos_similarity(freq1: &[f32], freq2: &[f32]) -> f32 {
    assert!(freq1.len() == 26);
    assert!(freq2.len() == 26);
    freq1
        .iter()
        .zip(freq2)
        .map(|(f1, f2)| f1 * f2)
        .reduce(|acc, e| acc + e)
        .unwrap_or(0.0)
}

pub fn english_score(str: &str) -> f32 {
    let mut letter_freqs = vec![0.0 as f32; 26];
    str.to_ascii_lowercase()
        .bytes()
        .filter(|&c| c >= 0x61 && c <= 0x7a)
        .for_each(|c| letter_freqs[(c - 0x61) as usize] += 1.0);
    cos_similarity(&ENGLISH_LETTER_FREQ, &letter_freqs)
}
