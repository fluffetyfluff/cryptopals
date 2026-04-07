use cryptopals::attacks::*;
use cryptopals::primitives::*;

fn main() {
    set_1_problem_1();
    set_1_problem_2();
    set_1_problem_3();
    set_1_problem_4();
    set_1_problem_5();
    set_1_problem_6();
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
    let (output, _, _) = one_byte_xor(&input);
    println!("set 1 problem 3: {0}", output);
}

fn set_1_problem_4() {
    let input = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/4.txt")
        .unwrap()
        .text()
        .unwrap();
    let (best, _, _) = input
        .lines()
        .map(|line| one_byte_xor(&hex_decode(&line)))
        .max_by(|(_, _, a), (_, _, b)| a.total_cmp(b))
        .unwrap_or((String::from("no good match"), 0x00, -1.0));
    println!("set 1 problem 4: {0}", best);
}

fn set_1_problem_5() {
    let input =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
    let key = "ICE".as_bytes();
    assert!(
        hex_encode(&repeating_xor(input, key))
            == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e\
            2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
    println!("set 1 problem 5: ok");
}

fn set_1_problem_6() {
    assert!(hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()) == 37);

    let input = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/6.txt")
        .unwrap()
        .text()
        .unwrap()
        .replace("\n", "");
    let input = b64_decode(&input);

    let (key_size, _) = (1..=40)
        .map(|key_size| {
            let num_blocks = input.len() / key_size;
            let score = (0..num_blocks - 1)
                .map(|i| {
                    hamming_distance(
                        &input[i * key_size..(i + 1) * key_size],
                        &input[(i + 1) * key_size..(i + 2) * key_size],
                    )
                })
                .sum::<u32>() as f32
                / ((num_blocks - 1) * key_size) as f32;
            (key_size, score)
        })
        .min_by(|(_, d1), (_, d2)| d1.total_cmp(d2))
        .unwrap_or((0, 0.0));

    let mut key = Vec::<u8>::with_capacity(key_size);
    for byte in 0..key_size {
        let transposed_input: Vec<u8> =
            input.iter().skip(byte).step_by(key_size).cloned().collect();
        let (_, key_byte, _) = one_byte_xor(&transposed_input);
        key.push(key_byte);
    }

    println!(
        "set 1 problem 6: key: {0}",
        String::from_utf8(key).unwrap_or(String::from("bad encoding"))
    );
}
