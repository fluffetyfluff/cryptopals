use clap::Parser;
use cryptopals::attacks::*;
use cryptopals::oracles::ecb_or_cbc_encrypt_oracle;
use cryptopals::oracles::ecb_prefix_oracle;
use cryptopals::primitives::*;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    /// Set to run (0-8)
    #[arg(short, long)]
    set: u8,
}

fn main() {
    let args = Args::parse();

    match args.set {
        1 => set_1(),
        2 => set_2(),
        3 => unimplemented(),
        4 => unimplemented(),
        5 => unimplemented(),
        6 => unimplemented(),
        7 => unimplemented(),
        8 => unimplemented(),
        _ => println!(),
    }
}

fn unimplemented() {
    println!("Not yet implemented");
}

fn set_1() {
    set_1_problem_1();
    set_1_problem_2();
    set_1_problem_3();
    set_1_problem_4();
    set_1_problem_5();
    set_1_problem_6();
    set_1_problem_7();
    set_1_problem_8();
}

fn set_2() {
    set_2_problem_9();
    set_2_problem_10();
    set_2_problem_11();
    set_2_problem_12();
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

fn set_1_problem_7() {
    let input = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/7.txt")
        .unwrap()
        .text()
        .unwrap()
        .replace("\n", "");
    let input = b64_decode(&input);
    let output = aes_128_ecb_decrypt(&input, b"YELLOW SUBMARINE");
    let output = &String::from_utf8(output).unwrap_or(String::from("bad decryption"));

    println!(
        "set 1 problem 7: {0}",
        output.lines().next().unwrap_or("bad decryption")
    );
}

fn set_1_problem_8() {
    let input = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/8.txt")
        .unwrap()
        .text()
        .unwrap();
    for line in input.lines() {
        let ciphertext = hex_decode(&line);
        let blocks = split_blocks(&ciphertext);
        let mut set = HashSet::new();
        for block in blocks.iter() {
            set.insert(block);
        }
        if set.len() != blocks.len() {
            println!("set 1 problem 8: {0}", &line[..40]);
            return;
        }
    }
    println!("set 1 problem 8: found nothing");
}

fn set_2_problem_9() {
    assert!(pkcs_pad_length(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04");
    println!("set 2 problem 9: ok");
}

fn set_2_problem_10() {
    let orange = b"ORANGE SUBMARINE";
    let yellow = b"YELLOW SUBMARINE";
    assert!(
        aes_128_cbc_decrypt(&aes_128_cbc_encrypt(orange, orange, yellow), orange, yellow) == orange
    );
    println!("set 2 problem 10: ok");
}

fn set_2_problem_11() {
    let input = b"blahblahblahblahblahblahblahblahblahblahblahblah";
    let (oracle_output, is_cbc) = ecb_or_cbc_encrypt_oracle(input);
    let blocks = split_blocks(&oracle_output);
    let first_potential = blocks[1];
    let second_potential = blocks[2];
    assert!((first_potential != second_potential) == is_cbc);
    println!("set 2 problem 11: ok");
}

fn set_2_problem_12() {
    let mut current_known_start = vec![0x20u8; 15];
    let mut offset_encryptions: HashMap<usize, Vec<Block>> = HashMap::new();
    for offset in 0..=15 {
        let prefix = vec![0x20u8; offset];
        let oracle_output = ecb_prefix_oracle(&prefix);
        let oracle_output = split_blocks(&oracle_output);
        offset_encryptions.insert(offset, oracle_output);
    }
    let empty_len = ecb_prefix_oracle(b"").len();
    for byte_offset in 0..empty_len {
        let mut dictionary: HashMap<Block, u8> = HashMap::new();
        for byte in 0u8..=0xffu8 {
            current_known_start.push(byte);
            let current_len = current_known_start.len();
            let oracle_input = &current_known_start[current_len - 16..current_len];
            let output_block = split_blocks(&ecb_prefix_oracle(oracle_input))[0];
            dictionary.insert(output_block, byte);
            current_known_start.pop();
        }
        let actual_block = &offset_encryptions[&(15 - (byte_offset % 16))][byte_offset / 16];
        if let Some(correct_byte) = dictionary.get(actual_block) {
            current_known_start.push(*correct_byte);
        }
    }
    println!(
        "set 2 problem 12: {0}",
        str::from_utf8(&current_known_start[15..])
            .unwrap()
            .lines()
            .next()
            .unwrap()
    );
}
