use cryptopals::language::*;
use cryptopals::primitives::*;

fn main() {
    set_1_problem_1();
    set_1_problem_2();
    set_1_problem_3();
    println!("all ok");
}

fn set_1_problem_1() {
    assert!(
        b64_encode(&hex_decode(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
    println!("set 1 problem 1: ok");
}

fn set_1_problem_2() {
    assert!(
        hex_encode(&xor(
            &hex_decode("1c0111001f010100061a024b53535009181c"),
            &hex_decode("686974207468652062756c6c277320657965")
        )) == "746865206b696420646f6e277420706c6179"
    );
    println!("set 1 problem 2: ok");
}

fn set_1_problem_3() {
    let input = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let mut best: String = String::from("no good match");
    let mut best_similarity: f32 = -1.0;
    for byte in 0x61u8..=0x7au8 {
        let mask = vec![byte; input.len()];
        let output = xor(&input, &mask);
        if let Ok(output_str) = String::from_utf8(output) {
            let similarity = english_score(&output_str);
            if similarity > best_similarity {
                best = output_str;
                best_similarity = similarity;
            }
        }
    }
    println!("set 1 problem 3: {0}", best);
}
