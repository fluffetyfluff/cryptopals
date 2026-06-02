use clap::Parser;
use cryptopals::attacks::*;
use cryptopals::oracles::*;
use cryptopals::primitives::*;
use rand::random_range;
use std::cmp;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
        3 => set_3(),
        4 => unimplemented(),
        5 => unimplemented(),
        6 => unimplemented(),
        7 => unimplemented(),
        8 => unimplemented(),
        _ => (),
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
    set_2_problem_13();
    set_2_problem_14();
    set_2_problem_15();
    set_2_problem_16();
}

fn set_3() {
    set_3_problem_17();
    set_3_problem_18();
    set_3_problem_19();
    set_3_problem_20();
    set_3_problem_21();
    set_3_problem_22();
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
    let (bytes, iv) = aes_128_cbc_encrypt(orange, orange, yellow);
    assert!(aes_128_cbc_decrypt(&bytes, orange, &iv) == orange);
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

fn set_2_problem_13() {
    let admin_block = profile_oracle("xxxxxxxxxxadmin");
    let role_block = profile_oracle("xxxxxxxxadmin");
    let end_block = profile_oracle("xxxxxxxxxadmin");
    let mut profile: Vec<u8> = Vec::new();
    profile.extend(&admin_block[0..16]);
    profile.extend(&role_block[16..32]);
    profile.extend(&admin_block[16..32]);
    profile.extend(&end_block[32..48]);
    let profile = profile_decrypt_oracle(&profile).unwrap();
    println!("set 2 problem 13: role: {0}", profile["role"]);
}

fn set_2_problem_14() {
    // find random.len()
    let mut length_prefix: Vec<u8> = vec![0x20u8; 32];
    let mut n = 0; // number of padding bits needed to align blocks
    let block_offset; // first duplicate block
    loop {
        let oracle_out = ecb_prefix_postfix_oracle(&length_prefix);
        let blocks = split_blocks(&oracle_out);
        let mut seen = HashSet::new();

        let duplicate_index = blocks.iter().position(|x| !seen.insert(x));
        if let Some(index) = duplicate_index {
            block_offset = index - 1;
            break;
        }

        n += 1;
        length_prefix.push(0x20);
    }

    // crack the ecb
    let mut current_known_start = vec![0x20u8; n + 15];
    let mut offset_encryptions: HashMap<usize, Vec<Block>> = HashMap::new();
    for offset in 0..=15 {
        let prefix = vec![0x20u8; n + offset];
        let oracle_output = ecb_prefix_postfix_oracle(&prefix);
        let oracle_output = split_blocks(&oracle_output);
        offset_encryptions.insert(offset, oracle_output);
    }
    let no_prefix_len = ecb_prefix_postfix_oracle(b"").len() - (block_offset * 16 - n);
    for byte_offset in 0..no_prefix_len {
        let mut dictionary: HashMap<Block, u8> = HashMap::new();
        for byte in 0u8..=0xffu8 {
            current_known_start.push(byte);
            let current_len = current_known_start.len();
            let oracle_input = &current_known_start[current_len - (16 + n)..current_len];
            let output_block = split_blocks(&ecb_prefix_postfix_oracle(oracle_input))[block_offset];
            dictionary.insert(output_block, byte);
            current_known_start.pop();
        }
        let actual_block =
            &offset_encryptions[&(15 - (byte_offset % 16))][(byte_offset / 16) + block_offset];
        if let Some(correct_byte) = dictionary.get(actual_block) {
            current_known_start.push(*correct_byte);
        }
    }
    println!(
        "set 2 problem 14: random_bytes: {0} output: {1}",
        block_offset * 16 + n,
        str::from_utf8(&current_known_start[15 + n..])
            .unwrap()
            .lines()
            .next()
            .unwrap()
    );
}

fn set_2_problem_15() {
    assert!(pkcs_unpad(b"ICE ICE BABY\x04\x04\x04\x04").unwrap() == b"ICE ICE BABY");
    assert!(pkcs_unpad(b"ICE ICE BABY\x01\x02\x03\x04").is_err());
    println!("set 2 problem 15: ok");
}

fn set_2_problem_16() {
    let target = b";admin=true;";
    let (bytes, iv) = cbc_encrypt_oracle(target);
    assert!(!cbc_decrypt_oracle(&bytes, &iv));
    let (bytes, iv) = cbc_encrypt_oracle(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    let mut mask = [0x0; 256];
    for i in 0..12 {
        mask[i + 16] = target[i];
    }
    let mod_bytes = xor(&bytes, &mask);
    assert!(cbc_decrypt_oracle(&mod_bytes, &iv));
    println!("set 2 problem 16: ok");
}

fn set_3_problem_17() {
    let (bytes, iv) = padding_cbc_encrypt_oracle();
    assert!(padding_cbc_decrypt_oracle(&bytes, &iv).is_ok());

    let mut plaintext: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut blocks = vec![iv];
    blocks.extend(split_blocks(&bytes));

    for i in 1..blocks.len() {
        let prev_block = blocks[i - 1];
        let curr_block = blocks[i];

        let mut intermediate = [0u8; 16];
        let mut plaintext_block = [0u8; 16];

        for byte_idx in (0..16).rev() {
            let padding_val = (16 - byte_idx) as u8;

            for guess in 0..=255u8 {
                let mut tampered_iv = [0u8; 16];
                for k in (byte_idx + 1)..16 {
                    tampered_iv[k] = intermediate[k] ^ padding_val;
                }
                tampered_iv[byte_idx] = guess;

                if padding_cbc_decrypt_oracle(&curr_block, &tampered_iv).is_ok() {
                    if byte_idx == 15 {
                        let mut verify_iv = tampered_iv;
                        verify_iv[14] ^= 0xFF;
                        if padding_cbc_decrypt_oracle(&curr_block, &verify_iv).is_err() {
                            continue;
                        }
                    }
                    intermediate[byte_idx] = guess ^ padding_val;
                    plaintext_block[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx];
                    break;
                }
            }
        }
        plaintext.extend_from_slice(&plaintext_block);
    }
    let plaintext = pkcs_unpad(&plaintext).unwrap();

    println!("set 3 problem 17: {0}", String::from_utf8_lossy(&plaintext));
}

fn set_3_problem_18() {
    assert!(
        aes_128_ctr_keystream(
            0x42,
            b"YELLOW SUBMARINE",
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        .len()
            == 0x42
    );
    let ciphertext =
        b64_decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let plaintext = xor(
        &aes_128_ctr_keystream(
            ciphertext.len(),
            b"YELLOW SUBMARINE",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        &ciphertext,
    );
    println!("set 3 problem 18: {0}", String::from_utf8_lossy(&plaintext));
}

fn set_3_problem_19() {
    println!("set 3 problem 19: skipped");
}

fn set_3_problem_20() {
    let input = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/20.txt")
        .unwrap()
        .text()
        .unwrap();
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut shortest_length: usize = 1000;
    for line in input.lines() {
        let ciphertext = b64_decode(line);
        shortest_length = cmp::min(shortest_length, ciphertext.len());
        lines.push(ciphertext);
    }
    lines
        .iter_mut()
        .map(|line| {
            line.truncate(shortest_length);
            line
        })
        .reduce(|line1, line2| {
            line1.append(line2);
            line1
        });

    let input = &lines[0];
    let key_size = shortest_length;
    let mut key = Vec::<u8>::with_capacity(key_size);
    for byte in 0..key_size {
        let transposed_input: Vec<u8> =
            input.iter().skip(byte).step_by(key_size).cloned().collect();
        let (_, key_byte, _) = one_byte_xor(&transposed_input);
        key.push(key_byte);
    }

    println!(
        "set 3 problem 20: {0}",
        String::from_utf8_lossy(&xor(input, &key))
    );
}

fn set_3_problem_21() {
    let mut mt = Mt19937::new(5489);
    assert!(mt.rand() == 3499211612);
    assert!(mt.rand() == 581869302);
    assert!(mt.rand() == 3890346734);
    assert!(mt.rand() == 3586334585);
    assert!(mt.rand() == 545404204);
    println!("set 3 problem 21: correct");
}

fn set_3_problem_22() {
    let output = unix_seeded_mt_oracle();
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut seed = 0;
    for delay in 0..1100 {
        if Mt19937::new(current_timestamp - delay).rand() == output {
            seed = current_timestamp - delay;
        }
    }
    println!("set 3 problem 22: {0}", seed);
}
