use clap::Parser;
use crypto_bigint::DivVartime;
use crypto_bigint::{NonZero, OddUint};
use cryptopals::attacks::*;
use cryptopals::oracles::*;
use cryptopals::primitives::*;
use cryptopals::protocols::*;
use itertools::iproduct;
use openssl::sha::sha256;
use rand::random_range;
use std::cmp;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;
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
        4 => set_4(),
        5 => set_5(),
        6 => set_6(),
        7 => set_7(),
        8 => set_8(),
        _ => (),
    }
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
    set_3_problem_23();
    set_3_problem_24();
}

fn set_4() {
    set_4_problem_25();
    set_4_problem_26();
    set_4_problem_27();
    set_4_problem_28();
    set_4_problem_29();
    set_4_problem_30();
    set_4_problem_31();
    set_4_problem_32();
}

fn set_5() {
    set_5_problem_33();
    set_5_problem_34();
    set_5_problem_35();
    set_5_problem_36();
    set_5_problem_37();
    set_5_problem_38();
    set_5_problem_39();
    set_5_problem_40();
}

fn set_6() {
    set_6_problem_41();
    set_6_problem_42();
    set_6_problem_43();
    set_6_problem_44();
    set_6_problem_45();
    set_6_problem_46();
    set_6_problem_47();
    set_6_problem_48();
}

fn set_7() {
    set_7_problem_49();
    set_7_problem_50();
    set_7_problem_51();
    set_7_problem_52();
    set_7_problem_53();
    set_7_problem_54();
    set_7_problem_55();
    set_7_problem_56();
}

fn set_8() {
    set_8_problem_57();
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

fn set_3_problem_23() {
    let x: u32 = 0b00011111011100001010010110000101;
    let y = x ^ (x >> 11);
    let y = y ^ ((y << 7) & 0x9D2C5680);
    let y = y ^ ((y << 15) & 0xEFC60000);
    let y = y ^ (y >> 18);
    assert!(x == untemper_mt19937(y));

    let mut mt = Mt19937::new(7974);
    let mut state = [0u32; 624];
    for i in 0..624 {
        state[i] = untemper_mt19937(mt.rand());
    }
    let mut cloned_mt = Mt19937::from_state(state);
    assert!(mt.rand() == cloned_mt.rand());
    assert!(mt.rand() == cloned_mt.rand());
    assert!(mt.rand() == cloned_mt.rand());
    println!(
        "set 3 problem 23: orig: {0} cloned: {1}",
        mt.rand(),
        cloned_mt.rand()
    );
}

fn set_3_problem_24() {
    let (ciphertext, secret_seed) = mt_stream_cipher_oracle();
    let mut found_seed: u16 = 0;
    for seed in 0..=u16::MAX {
        let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
        let mut mt = Mt19937::new(seed as u32);
        for byte in ciphertext.iter() {
            let key_byte = mt.rand() as u8;
            plaintext.push(byte ^ key_byte);
        }
        if &plaintext[plaintext.len() - 14..] == b"AAAAAAAAAAAAAA" {
            found_seed = seed;
            break;
        }
    }
    assert!(secret_seed == found_seed);
    println!("set 3 problem 24: secret seed: {secret_seed} found seed: {found_seed}");
}

fn set_4_problem_25() {
    let input = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/25.txt")
        .unwrap()
        .text()
        .unwrap();
    let mut plaintext: Vec<u8> = Vec::new();
    for line in input.lines() {
        plaintext.extend_from_slice(&b64_decode(line));
    }
    let ciphertext = xor(&plaintext, &ctr_keystream_oracle(plaintext.len()));

    let keystream = ctr_edit(&ciphertext, 0, &vec![0x0u8; ciphertext.len()]);
    assert!(&plaintext == &xor(&ciphertext, &keystream));
    println!("set 4 problem 25: ok");
}

fn set_4_problem_26() {
    let target = b";admin=true;";
    let (bytes, nonce) = ctr_encrypt_oracle(target);
    assert!(!ctr_decrypt_oracle(&bytes, nonce));

    let (bytes, nonce) = ctr_encrypt_oracle(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    let mut mask = [0x0u8; 256];
    for i in 0..12 {
        mask[i + 32] = target[i];
    }
    let bytes = xor(&bytes, &mask);
    assert!(ctr_decrypt_oracle(&bytes, nonce));

    println!("set 4 problem 26: ok");
}

fn set_4_problem_27() {
    let ciphertext = cbc_encrypt_iv_oracle(b"");
    let block = split_blocks(&ciphertext)[0];
    let mut new_ciphertext = [0x0u8; 3 * 16];
    new_ciphertext[..16].copy_from_slice(&block);
    new_ciphertext[32..].copy_from_slice(&block);
    let plaintext = cbc_decrypt_iv_oracle(&new_ciphertext).unwrap_err();
    let blocks = split_blocks(&plaintext);
    let key = xor(&blocks[0], &blocks[2]);
    assert!(key == oracle_key());
    println!("set 4 problem 27: recovered key: {0}", hex_encode(&key));
}

fn set_4_problem_28() {
    let hash = hex_encode(&sha_1(b""));
    assert!(hash == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    println!("set 4 problem 28: sha-1 hash of \"\": {0}", hash);
}

fn set_4_problem_29() {
    let original_message =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = secret_prefix_sha1_mac(original_message);
    assert!(secret_prefix_sha1_mac_verifier(original_message, mac));

    let admin_message = b";admin=true";
    let mut k = 999;
    for key_length in 0..512 {
        let ml = (key_length + original_message.len()) * 8;
        let target_length = ml + 1 + (448 - (ml + 1) as i32).rem_euclid(512) as usize;
        let mut tamper_message: Vec<u8> = Vec::with_capacity(target_length / 8 + 64);
        tamper_message.extend_from_slice(original_message);
        tamper_message.push(0x80);
        tamper_message.resize(target_length / 8 - key_length, 0x0);
        tamper_message.extend_from_slice(&(ml as u64).to_be_bytes());

        let h0 = u32::from_be_bytes(mac[0..4].try_into().unwrap());
        let h1 = u32::from_be_bytes(mac[4..8].try_into().unwrap());
        let h2 = u32::from_be_bytes(mac[8..12].try_into().unwrap());
        let h3 = u32::from_be_bytes(mac[12..16].try_into().unwrap());
        let h4 = u32::from_be_bytes(mac[16..20].try_into().unwrap());
        let tamper_mac = sha_1_extend(
            admin_message,
            tamper_message.len() + key_length,
            h0,
            h1,
            h2,
            h3,
            h4,
        );

        tamper_message.extend_from_slice(admin_message);

        if secret_prefix_sha1_mac_verifier(&tamper_message, tamper_mac) {
            k = key_length;
            break;
        }
    }

    println!("set 4 problem 29: forged sha-1 mac with key length: {0}", k);
}

fn set_4_problem_30() {
    let hash = hex_encode(&md4(b""));
    assert!(hash == "31d6cfe0d16ae931b73c59d7e0c089c0");

    let original_message =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = secret_prefix_md4_mac(original_message);
    assert!(secret_prefix_md4_mac_verifier(original_message, mac));

    let admin_message = b";admin=true";
    let mut k = 999;
    for key_length in 0..512 {
        let ml = (key_length + original_message.len()) * 8;
        let target_length = ml + 1 + (448 - (ml + 1) as i32).rem_euclid(512) as usize;
        let mut tamper_message: Vec<u8> = Vec::with_capacity(target_length / 8 + 64);
        tamper_message.extend_from_slice(original_message);
        tamper_message.push(0x80);
        tamper_message.resize(target_length / 8 - key_length, 0x0);
        tamper_message.extend_from_slice(&(ml as u64).to_le_bytes());

        let h0 = u32::from_le_bytes(mac[0..4].try_into().unwrap());
        let h1 = u32::from_le_bytes(mac[4..8].try_into().unwrap());
        let h2 = u32::from_le_bytes(mac[8..12].try_into().unwrap());
        let h3 = u32::from_le_bytes(mac[12..16].try_into().unwrap());
        let tamper_mac = md4_extend(
            admin_message,
            tamper_message.len() + key_length,
            h0,
            h1,
            h2,
            h3,
        );

        tamper_message.extend_from_slice(admin_message);

        if secret_prefix_md4_mac_verifier(&tamper_message, tamper_mac) {
            k = key_length;
            break;
        }
    }

    println!("set 4 problem 30: forged md4 mac with key length: {0}", k);
}

fn set_4_problem_31() {
    let client = reqwest::blocking::Client::new();
    let request = client
        .get("http://127.0.0.1:8080/test?file=foo&signature=a")
        .send();
    match request {
        Ok(_) => (),
        Err(error) => {
            if error.is_connect() {
                println!("set 4 problem 31: did not reach server, skipping");
                return;
            }
        }
    }

    fn time(client: &reqwest::blocking::Client, signature: &[u8]) -> Result<Duration, Duration> {
        let now = Instant::now();
        let url = format!(
            "http://127.0.0.1:8080/test?file=foo&signature={0}",
            str::from_utf8(signature).unwrap()
        );
        let result = client.get(url).send();
        let duration = now.elapsed();
        let result = result.unwrap();
        if result.status().is_success() {
            Ok(duration)
        } else {
            Err(duration)
        }
    }

    let mut signature = vec![b'0'; 40];
    'outer: for i in 0..40 {
        let mut longest = Duration::from_secs(0);
        let mut longest_char = b'0';
        for byte in b"0123456789abcdef" {
            signature[i] = *byte;
            match time(&client, &signature) {
                Ok(_) => break 'outer,
                Err(t) => {
                    if t > longest {
                        longest = t;
                        longest_char = *byte;
                    }
                }
            }
        }
        signature[i] = longest_char;
    }

    let url = format!(
        "http://127.0.0.1:8080/test?file=foo&signature={0}",
        str::from_utf8(&signature).unwrap()
    );
    let response = client.get(url).send().unwrap();
    assert!(response.status().is_success());

    println!(
        "set 4 problem 31: recovered signature {0}",
        str::from_utf8(&signature).unwrap()
    );
}

fn set_4_problem_32() {
    let client = reqwest::blocking::Client::new();
    let request = client
        .get("http://127.0.0.1:8080/test?file=foo&signature=z")
        .send();
    match request {
        Ok(_) => (),
        Err(error) => {
            if error.is_connect() {
                println!("set 4 problem 32: did not reach server, skipping");
                return;
            }
        }
    }

    fn time(client: &reqwest::blocking::Client, signature: &[u8]) -> Result<Duration, Duration> {
        let now = Instant::now();
        let url = format!(
            "http://127.0.0.1:8080/faster?file=foo&signature={0}",
            str::from_utf8(signature).unwrap()
        );
        let result = client.get(&url).send();
        for _ in 0..10 {
            let _ = client.get(&url).send();
        }
        let duration = now.elapsed();
        let result = result.unwrap();
        if result.status().is_success() {
            Ok(duration)
        } else {
            Err(duration)
        }
    }

    let mut signature = vec![b'0'; 40];
    'outer: for i in 0..40 {
        let mut longest = Duration::from_secs(0);
        let mut longest_char = b'0';
        for byte in b"0123456789abcdef" {
            signature[i] = *byte;
            match time(&client, &signature) {
                Ok(_) => break 'outer,
                Err(t) => {
                    if t > longest {
                        longest = t;
                        longest_char = *byte;
                    }
                }
            }
        }
        signature[i] = longest_char;
    }

    let url = format!(
        "http://127.0.0.1:8080/faster?file=foo&signature={0}",
        str::from_utf8(&signature).unwrap()
    );
    let response = client.get(url).send().unwrap();
    assert!(response.status().is_success());

    println!(
        "set 4 problem 32: recovered signature {0}",
        str::from_utf8(&signature).unwrap(),
    );
}

fn set_5_problem_33() {
    let p = odd_bigint(37);
    let g = bigint(5);
    let a = random_biguint(p.as_nz_ref());
    let b = random_biguint(p.as_nz_ref());
    let ga = modexp(&g, &a, &p);
    let gb = modexp(&g, &b, &p);
    assert!(modexp(&ga, &b, &p) == modexp(&gb, &a, &p));

    let p = nist_prime();
    let g = bigint(2);
    let a = random_biguint(p.as_nz_ref());
    let b = random_biguint(p.as_nz_ref());
    let ga = modexp(&g, &a, &p);
    let gb = modexp(&g, &b, &p);
    assert!(modexp(&ga, &b, &p) == modexp(&gb, &a, &p));

    println!("set 5 problem 33: ok");
}

fn set_5_problem_34() {
    let msg = b"YELLOW SUBMARINE";
    let p = nist_prime();
    let g = bigint(2);
    let a = random_biguint(p.as_nz_ref());
    let ga = modexp(&g, &a, &p);

    let (server, gb) = DhEchoServer::new(&p, &g, &ga);
    let s = modexp(&gb, &a, &p);

    let key: [u8; 16] = sha_1(&s.to_be_bytes())[..16].try_into().unwrap();
    let (ciphertext, iv) = aes_128_cbc_encrypt(msg, &key, &random_block());
    let (new_ct, new_iv) = server.echo(&ciphertext, iv);
    let dec = aes_128_cbc_decrypt(&new_ct, &key, &new_iv);
    assert!(dec == msg);

    // mitm parameter injection
    let a = random_biguint(p.as_nz_ref());
    let (server, _) = DhEchoServer::new(&p, &g, &p);
    let gb = p;
    let s = modexp(&gb, &a, &p);

    let key: [u8; 16] = sha_1(&s.to_be_bytes())[..16].try_into().unwrap();
    let m_key: [u8; 16] = sha_1(&bigint(0).to_be_bytes())[..16].try_into().unwrap();

    let (ciphertext, iv) = aes_128_cbc_encrypt(msg, &key, &random_block());
    let (new_ct, new_iv) = server.echo(&ciphertext, iv);
    let dec = aes_128_cbc_decrypt(&new_ct, &key, &new_iv);
    let m_dec = aes_128_cbc_decrypt(&new_ct, &m_key, &new_iv);
    assert!(dec == msg);
    assert!(dec == m_dec);

    println!("set 5 problem 34: ok");
}

fn set_5_problem_35() {
    let msg = b"YELLOW SUBMARINE";
    let p = nist_prime();

    // g = 1
    // mitm attacker replaces g and g^a with 1, then runs rest of protocol as normal
    let a = random_biguint(p.as_nz_ref());

    let (server, gb) = DhEchoServer::new(&p, &bigint(1), &bigint(1));
    let a_s = modexp(&gb, &a, &p);
    let a_key = sha_1(&a_s.to_be_bytes())[..16].try_into().unwrap();
    let (ciphertext, iv) = aes_128_cbc_encrypt(msg, &a_key, &random_block());
    let (new_ct, new_iv) = server.echo(&ciphertext, iv);
    let a_dec = aes_128_cbc_decrypt(&new_ct, &a_key, &new_iv);

    let m_key = sha_1(&bigint(1).to_be_bytes())[..16].try_into().unwrap();
    let m_dec = aes_128_cbc_decrypt(&new_ct, &m_key, &new_iv);
    assert!(a_dec == msg);
    assert!(a_dec == m_dec);

    // g = p
    // mitm attacker replaces g and g^a with p === 0, then runs rest of protocol
    let a = random_biguint(p.as_nz_ref());

    let (server, gb) = DhEchoServer::new(&p, &p, &p);
    let a_s = modexp(&gb, &a, &p);
    let a_key = sha_1(&a_s.to_be_bytes())[..16].try_into().unwrap();
    let (ciphertext, iv) = aes_128_cbc_encrypt(msg, &a_key, &random_block());
    let (new_ct, new_iv) = server.echo(&ciphertext, iv);
    let a_dec = aes_128_cbc_decrypt(&new_ct, &a_key, &new_iv);

    let m_key = sha_1(&bigint(0).to_be_bytes())[..16].try_into().unwrap();
    let m_dec = aes_128_cbc_decrypt(&new_ct, &m_key, &new_iv);
    assert!(a_dec == msg);
    assert!(a_dec == m_dec);

    // g = p - 1 === -1 mod p -> try both -1 and 1
    let a = random_biguint(p.as_nz_ref());
    let p1 = p.sub_mod(&bigint(1), p.as_nz_ref());

    let (server, gb) = DhEchoServer::new(&p, &p1, &bigint(1));
    let (server2, gb2) = DhEchoServer::new(&p, &p1, &p1);

    let a_s = modexp(&gb, &a, &p);
    let a_key = sha_1(&a_s.to_be_bytes())[..16].try_into().unwrap();
    let (ciphertext, iv) = aes_128_cbc_encrypt(msg, &a_key, &random_block());
    let (new_ct, new_iv) = server.echo(&ciphertext, iv);
    let a_dec = aes_128_cbc_decrypt(&new_ct, &a_key, &new_iv);

    let a_s = modexp(&gb2, &a, &p);
    let a_key = sha_1(&a_s.to_be_bytes())[..16].try_into().unwrap();
    let (ciphertext, iv) = aes_128_cbc_encrypt(msg, &a_key, &random_block());
    let (new_ct, new_iv) = server2.echo(&ciphertext, iv);
    let a_dec2 = aes_128_cbc_decrypt(&new_ct, &a_key, &new_iv);

    let m_key = sha_1(&bigint(1).to_be_bytes())[..16].try_into().unwrap();
    let m_dec = aes_128_cbc_decrypt(&new_ct, &m_key, &new_iv);
    let m_key2 = sha_1(&p1.to_be_bytes())[..16].try_into().unwrap();
    let m_dec2 = aes_128_cbc_decrypt(&new_ct, &m_key2, &new_iv);
    assert!((a_dec == msg) || (a_dec2 == msg));
    assert!((m_dec == msg) || (m_dec2 == msg));

    println!("set 5 problem 35: ok");
}

fn set_5_problem_36() {
    let n = nist_prime();
    let nz = n.as_nz_ref();
    let g = bigint(2);
    let k = bigint(3);
    let mut server = SrpServer::new(n, g, k);

    let i = b"alice@cryptopals.com";
    let p = b"password";
    server.register_user(i, p);

    let a = random_biguint(n.as_nz_ref());
    let ga = modexp(&g, &a, &n);
    let (salt, gb, key_b) = server.handshake(i, &ga);

    let uh = sha256(&[ga.to_be_bytes().as_slice(), gb.to_be_bytes().as_slice()].concat());
    let u = bigint_hex(&hex_encode(&uh));
    let xh = sha256(&[&salt, p as &[u8]].concat());
    let x = bigint_hex(&hex_encode(&xh));

    let kgx = k.mul_mod(&modexp(&g, &x, &n), nz);
    let gbkgx = gb.sub_mod(&kgx, nz);
    let aux = a.add_mod(&u.mul_mod(&x, nz), nz);
    let s = modexp(&gbkgx, &aux, &n);
    let key_a = sha256(s.to_be_bytes().as_slice());

    assert!(key_a == key_b);
    println!("set 5 problem 36: ok");
}

fn set_5_problem_37() {
    let n = nist_prime();
    let g = bigint(2);
    let k = bigint(3);
    let mut server = SrpServer::new(n, g, k);

    let i = b"alice@cryptopals.com";
    let p = random_bytes(16);
    server.register_user(i, &p);

    let ga = bigint(0);
    let (_, _, key_b) = server.handshake(i, &ga);
    let key_a = sha256(ga.to_be_bytes().as_slice());

    assert!(key_a == key_b);
    println!("set 5 problem 37: ok");
}

fn set_5_problem_38() {
    let n = nist_prime();
    let nz = n.as_nz_ref();
    let g = bigint(2);
    let p = b"YELLOW SUBMARINE";

    let server = SimpleSrpServer::new(n, g, p);
    let a = random_biguint(nz);
    let ga = modexp(&g, &a, &n);
    let (salt, gb, u, s_key) = server.handshake(&ga);
    let xh = sha256(&[&salt, p as &[u8]].concat());
    let x = bigint_hex(&hex_encode(&xh));
    let ux = u.mul_mod(&x, nz);
    let aux = a.add_mod(&ux, nz);
    let s = modexp(&gb, &aux, &n);
    let a_key = sha256(s.to_be_bytes().as_slice());
    assert!(a_key == s_key);

    let adjectives: [&[u8]; 4] = [b"YELLOW ", b"ORANGE ", b"PURPLE ", b"BRONZE "];
    let objects: [&[u8]; 4] = [b"SUBMARINE", b"VEGETABLE", b"SATELLITE", b"COOKWARE"];
    let p = [
        adjectives[random_range(0..adjectives.len())],
        objects[random_range(0..objects.len())],
    ]
    .concat();

    let a = random_biguint(nz);
    // simulate mitm values - no need to call server
    let salt = b"";
    let gb = g;
    let u = bigint(1);
    let xh = sha256(&[salt as &[u8], &p].concat());
    let x = bigint_hex(&hex_encode(&xh));
    let ux = u.mul_mod(&x, nz);
    let aux = a.add_mod(&ux, nz);
    let s = modexp(&gb, &aux, &n);
    let a_key = sha256(s.to_be_bytes().as_slice());

    // mitm attacker has ga
    let ga = modexp(&g, &a, &n);
    let product =
        iproduct!(adjectives.iter(), objects.iter()).map(|(&adj, &obj)| [adj, obj].concat());
    for p_guess in product {
        let xh = sha256(&p_guess);
        let x = bigint_hex(&hex_encode(&xh));
        let gx = modexp(&g, &x, &n);
        let s = ga.mul_mod(&gx, nz);
        let key_guess = sha256(s.to_be_bytes().as_slice());
        if key_guess == a_key {
            println!(
                "set 5 problem 38: recovered password {0}",
                String::from_utf8_lossy(&p_guess)
            );
            return;
        }
    }

    panic!("set 5 problem 38: not ok");
}

fn set_5_problem_39() {
    assert!(modinv(&bigint(17), &NonZero::new(bigint(3120)).unwrap()).unwrap() == bigint(2753));
    let (e, d, n) = rsa_keygen(512);
    let m = random_biguint(n.as_nz_ref());
    assert!(rsa_decrypt(&d, &n, &rsa_encrypt(&e, &n, &m)).to_be_bytes() == m.to_be_bytes());

    println!("set 5 problem 39: ok");
}

fn set_5_problem_40() {
    // use 256 bit primes -> 512 bit n -> four of them multiplied still fits in U2048
    let (e1, _, n1) = rsa_keygen(256);
    let (e2, _, n2) = rsa_keygen(256);
    let (e3, _, n3) = rsa_keygen(256);
    let message = bigint_hex(&hex_encode(b"YELLOW SUBMARINE"));

    let ct1 = rsa_encrypt(&e1, &n1, &message);
    let ct2 = rsa_encrypt(&e2, &n2, &message);
    let ct3 = rsa_encrypt(&e3, &n3, &message);

    let n123 = n1 * n2 * n3;
    let n123 = n123.as_nz_ref();

    let n23 = n2.mul_mod(&n3, n123);
    let p1 = ct1.mul_mod(
        &n23.mul_mod(&modinv(&n23, n1.as_nz_ref()).unwrap(), n123),
        n123,
    );
    let n13 = n1.mul_mod(&n3, n123);
    let p2 = ct2.mul_mod(
        &n13.mul_mod(&modinv(&n13, n2.as_nz_ref()).unwrap(), n123),
        n123,
    );
    let n12 = n1.mul_mod(&n2, n123);
    let p3 = ct3.mul_mod(
        &n12.mul_mod(&modinv(&n12, n3.as_nz_ref()).unwrap(), n123),
        n123,
    );

    let sum = p1.add_mod(&p2.add_mod(&p3, n123), n123);
    let decryption = cube_root(&sum);
    assert!(decryption.to_be_bytes() == message.to_be_bytes());
    println!("set 5 problem 40: ok");
}

fn set_6_problem_41() {
    let message = bigint_hex(&hex_encode(b"YELLOW SUBMARINE"));
    let (mut server, n, e) = RsaOnceServer::new();
    let ct = rsa_encrypt(&e, &n, &message);
    let decryption = server.decrypt(&ct).unwrap();
    assert!(server.decrypt(&ct).is_err());

    let two = bigint(2);
    let ct2 = ct.mul_mod(&modexp(&two, &e, &n), n.as_nz_ref());
    let inv2 = modinv(&two, n.as_nz_ref()).unwrap();
    let decryption2 = server.decrypt(&ct2).unwrap().mul_mod(&inv2, n.as_nz_ref());
    assert!(decryption.to_be_bytes() == decryption2.to_be_bytes());

    println!("set 6 problem 41: ok");
}

fn set_6_problem_42() {
    // funnily enough, this attack gets easier when the rsa key size is larger
    // since we need ~2/3 of the bits to massage message to look like a cube root
    // sha-256 and its asn don't actually fit in the top third of 1024 bits
    // using md4 instead puts us closer to the margin
    let (_, d, n) = rsa_keygen(512);
    let crafted_string = bigint_hex(
        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003020\
         300c06082a864886f70d0204050004103caec78ddfc0b781a428aaeb9ead641d",
    );
    let valid_signature = modexp(&crafted_string, &d, &n);
    assert!(rsa_pkcs_verifier(b"hi mom", &valid_signature, &n, 1024));

    let forgery_target = bigint_hex(
        "0001ff003020300c06082a864886f70d0204050004103caec78ddfc0b781a428\
         aaeb9ead641d0000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
    );
    let one = bigint(1);
    let three = bigint(3);
    let mut cube_root = cube_root(&forgery_target);
    while modexp(&cube_root, &three, &n) < forgery_target {
        cube_root += one;
    }
    rsa_pkcs_verifier(b"hi mom", &(cube_root.wrapping_sub(&one)), &n, 1024);
    assert!(rsa_pkcs_verifier(b"hi mom", &cube_root, &n, 1024));

    println!("set 6 problem 42: ok");
}

fn set_6_problem_43() {
    let p = bigint_hex(
        "800000000000000089e1855218a0e7dac38136ffafa72eda7\
     859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
     2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
     ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
     b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
     1a584471bb1",
    );
    let p = OddUint::new(p).unwrap();
    let g = bigint_hex(
        "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
     458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
     322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
     0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
     878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
     9fc95302291",
    );
    let q = bigint_hex("f4f47f05794b256174bba6e9b396a7707e563c5b");
    let q = OddUint::new(q).unwrap();

    let test_message = b"blahblahblah";
    let test_x = random_biguint(q.as_nz_ref());
    let test_y = modexp(&g, &test_x, &p);
    let (test_r, test_s) = dsa_sign(&test_x, test_message);
    assert!(dsa_verify(&test_y, &test_r, &test_s, test_message));

    let message = b"For those that envy a MC it can be hazardous to your health\n\
    So be friendly, a matter of life and death, just like a etch-a-sketch\n";
    let hash = hex_encode(&sha_1(message));
    assert!(hash == "d2d0714f014a9784047eaeccf956520045c45265");

    let hash = bigint_hex(&hash);
    let r = bigint_hex("60019CACDC56EEDF8E080984BFA898C8C5C419A8");
    let s = bigint_hex("961F2062EFC3C68DB965A90C924CF76580EC1BBC");

    let mut real_k = 1u64 << 63;
    for k in 0..1u64 << 16 {
        let k_big = bigint(k);

        let r1 = modexp(&g, &k_big, &p).rem(&q.as_nz_ref());
        if r1.to_be_bytes() == r.to_be_bytes() {
            real_k = k;
            break;
        }
    }

    let x = dsa_key_recovery(&r, &s, &bigint(real_k), &hash);
    let key = hex_encode(&x.to_be_bytes().as_slice());
    let key = key.trim_start_matches('0');
    let key_hash = sha_1(key.as_bytes());
    assert!(&key_hash as &[u8] == &hex_decode("0954edd5e0afe5542a4adf012611a91912a3ec16"));

    println!("set 6 problem 43: found key {0}", key);
}

fn set_6_problem_44() {
    let q = bigint_hex("f4f47f05794b256174bba6e9b396a7707e563c5b");
    let q = OddUint::new(q).unwrap();
    let q_nz = q.as_nz_ref();

    // r is only dependent on k for randomness -> same k -> same r
    let r = bigint_hex("C1A545DE46348F25BFE81B7B5AD87292F8DB9B7B");
    let s1 = bigint_hex("DE0005B256A1C401DEE8E88C954789A8637D5B9C");
    let hash1 = bigint_hex("a4db3de27e2db3e5ef085ced2bced91b82e0df19");
    let s2 = bigint_hex("B2F415CE7A39268BD650C4975A0ACBE5EFD372D7");
    let hash2 = bigint_hex("d22804c4899b522b23eda34d2137cd8cc22b9ce8");

    let denom = modinv(&s1.sub_mod(&s2, q_nz), q_nz).unwrap();
    let k = hash1.sub_mod(&hash2, q_nz).mul_mod(&denom, q_nz);
    let x = dsa_key_recovery(&r, &s1, &k, &hash1);
    let key = hex_encode(&x.to_be_bytes().as_slice());
    let key = key.trim_start_matches('0');

    let key_hash = sha_1(key.as_bytes());
    assert!(&key_hash as &[u8] == &hex_decode("ca8f6f7c66fa362d40760d135b763eb8527d3d52"));
    println!("set 6 problem 44: found key {0}", key);
}

fn set_6_problem_45() {
    // The g = 0 = p case is uninteresting, since it effectively just fixes r = 0.
    // The Wikipedia implementation of DSA sign also doesn't even allow this,
    // since it explicitly checks for the r = 0 case.
    // This only implements the g = 1 = p + 1 case.
    let p = bigint_hex(
        "800000000000000089e1855218a0e7dac38136ffafa72eda7\
         859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
         2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
         ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
         b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
         1a584471bb1",
    );
    let p = OddUint::new(p).unwrap();
    let q = bigint_hex("f4f47f05794b256174bba6e9b396a7707e563c5b");
    let q = OddUint::new(q).unwrap();
    let g = p.get().wrapping_add(&bigint(1));

    let y = random_biguint(q.as_nz_ref());
    let z = bigint(2);
    let r = modexp(&y, &z, &p).rem(q.as_nz_ref());
    let s = modinv(&z, q.as_nz_ref())
        .unwrap()
        .mul_mod(&r, q.as_nz_ref());
    assert!(dsa_verify_parameters(
        &p,
        &q,
        &g,
        &y,
        &r,
        &s,
        b"Hello, World"
    ));
    assert!(dsa_verify_parameters(
        &p,
        &q,
        &g,
        &y,
        &r,
        &s,
        b"Goodbye, World"
    ));
    println!("set 6 problem 45: ok");
}

fn set_6_problem_46() {
    let message = b64_decode(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==",
    );
    let (server, e, n) = RsaParityOracleServer::new();
    let plaintext = bigint_hex(&hex_encode(&message));
    let ciphertext = rsa_encrypt(&e, &n, &plaintext);

    let two_e = modexp(&bigint(2), &e, &n);
    let mut doubled_ct = ciphertext;
    let mut min = bigint(0);
    let mut max = n.get();
    let mut divisor = bigint(1);

    for _ in 0..n.bits() {
        doubled_ct = doubled_ct.mul_mod(&two_e, n.as_nz_ref());
        let diff = max.wrapping_sub(&min);
        min = min.shl(1);
        max = max.shl(1);
        divisor = divisor.shl(1);

        if server.is_even(&doubled_ct) {
            max = max.wrapping_sub(&diff);
        } else {
            min = min.wrapping_add(&diff);
        }
    }

    let divisor = NonZero::new(divisor).unwrap();
    let ans = max.wrapping_div(&divisor);

    println!(
        "set 6 problem 46: {0}",
        String::from_utf8_lossy(ans.to_be_bytes().as_slice())
    );
}

fn set_6_problem_47() {
    let (server, e, n) = RsaPaddingOracleServer::new(128);
    let plaintext = pkcs15_pad(b"kick it, CC", 256);
    let ciphertext = rsa_encrypt(&e, &n, &plaintext);
    assert!(server.oracle(&ciphertext));

    let recovered_message = bleichenbacher(&ciphertext, &e, &n, |ct| server.oracle(ct), 256);
    let recovered_message = pkcs15_unpad(&recovered_message, 256);
    let recovered_message = String::from_utf8_lossy(&recovered_message);

    println!("set 6 problem 47: {0}", recovered_message);
}

fn set_6_problem_48() {
    let (server, e, n) = RsaPaddingOracleServer::new(384);
    let plaintext = pkcs15_pad(
        b"Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1",
        768,
    );
    let ciphertext = rsa_encrypt(&e, &n, &plaintext);
    assert!(server.oracle(&ciphertext));

    let recovered_message = bleichenbacher(&ciphertext, &e, &n, |ct| server.oracle(ct), 768);
    let recovered_message = pkcs15_unpad(&recovered_message, 768);
    let recovered_message = String::from_utf8_lossy(&recovered_message);

    println!("set 6 problem 48: {0}", recovered_message);
}

fn set_7_problem_49() {
    let server = CbcMacServer::new();
    let message = pkcs7_pad(b"from=pwn&to=bob&amount=1 million spacebucks");
    let iv = random_block();
    let mac = server.mac_iv(&message, &iv);
    assert!(server.verify_iv(&message, &iv, &mac));

    let pwn_message = pkcs7_pad(b"from=bob&to=pwn&amount=1 million spacebucks");
    let pwn_diff = xor(b"from=bob&to=pwn&", b"from=pwn&to=bob&");
    let pwn_iv = xor(&iv, &pwn_diff).try_into().unwrap();
    assert!(server.verify_iv(&pwn_message, &pwn_iv, &mac));

    let message = b"from=alice&tx_list=bob:100000000";
    let mac = server.mac(message);
    assert!(server.verify(message, &mac));

    let pwn_message = b"from=alice&tx_list=bob:100000000;pwn:10000000000";
    let target = xor(b";pwn:10000000000", &mac);
    let block_mac = server.mac(&target);
    assert!(server.verify(pwn_message, &block_mac));

    println!("set 7 problem 49: ok");
}

fn set_7_problem_50() {
    fn cbc_mac(message: &[u8], key: &Block) -> Block {
        let iv = [0x00u8; 16];
        let ct = aes_128_cbc_encrypt(&message, key, &iv).0;
        let mac: Block = ct[ct.len() - 16..].try_into().unwrap();
        mac
    }

    let key = b"YELLOW SUBMARINE";
    let message = pkcs7_pad(b"alert('MZA who was that?');\n");
    let mac = cbc_mac(&message, key);
    assert!(hex_encode(&mac) == "296b8d7cb78a243dda4d0a61d33bbdd1");

    let pwn_message = b"alert('Ayo, the Wu is back!');//";
    let mut pwn_mac = cbc_mac(pwn_message, key).to_vec();
    pwn_mac.resize(message.len(), 0x00);
    let modified_message = xor(&message, &pwn_mac);
    let mut combined_message = pwn_message.to_vec();
    combined_message.extend(&modified_message);
    assert!(hex_encode(&cbc_mac(&combined_message, key)) == "296b8d7cb78a243dda4d0a61d33bbdd1");

    println!("set 7 problem 50: ok");
}

fn set_7_problem_51() {
    let mut candidates = vec![String::from("sessionid=")];
    let alphabet = "1234567890+/qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM=";
    for _ in 0..44 {
        let mut lengths_map: HashMap<usize, Vec<String>> = HashMap::new();
        let mut min = 10000;
        for character in alphabet.chars() {
            for candidate in candidates.iter() {
                let mut new_candidate = candidate.clone();
                new_candidate.push(character);
                let size = ctr_compression_oracle(&new_candidate);
                min = if size < min { size } else { min };
                if size == min {
                    lengths_map
                        .entry(size)
                        .or_insert(Vec::new())
                        .push(new_candidate);
                }
            }
        }
        candidates = lengths_map.get(&min).unwrap().clone();
    }
    assert!(candidates.len() == 1);
    let token = &candidates[0][10..];
    let token = b64_decode(token);
    let token = String::from_utf8_lossy(&token);
    assert!(token == "Never reveal the Wu-Tang Secret!");

    let mut candidate = String::from("sessionid=");
    for _ in 0..22 {
        'inner: for shift in 0..3 {
            let c = &candidate[shift..];
            for padding_len in 0..20 {
                let padding = &alphabet[..padding_len];
                let mut min = 100000;
                let mut lengths_map: HashMap<usize, Vec<(char, char)>> = HashMap::new();
                for char1 in alphabet.chars() {
                    for char2 in alphabet.chars() {
                        let size = ctr_compression_oracle(&format!("{padding}{c}{char1}{char2}"));
                        min = if size < min { size } else { min };
                        if size == min {
                            lengths_map
                                .entry(size)
                                .or_insert(Vec::new())
                                .push((char1, char2));
                        }
                    }
                }
                let min_vec = lengths_map.get(&min).unwrap();
                if min_vec.len() == 1 {
                    candidate.push(min_vec[0].0);
                    candidate.push(min_vec[0].1);
                    break 'inner;
                }
            }
        }
    }

    let token = &candidate[10..];
    let token = b64_decode(token);
    let token = String::from_utf8_lossy(&token);
    assert!(token == "Never reveal the Wu-Tang Secret!");
    println!("set 7 problem 51: {}", token);
}

fn set_7_problem_52() {
    let collisions = find_collisions::<2>(3);
    let u1: Vec<u64> = collisions.iter().map(|(a, _)| *a).collect();
    let u2: Vec<u64> = collisions.iter().map(|(_, b)| *b).collect();
    let u1_pad: Vec<u8> = repad_collision(&u1);
    let u2_pad: Vec<u8> = repad_collision(&u2);
    let hash1 = aes_md::<2>(&u1_pad);
    let hash2 = aes_md::<2>(&u2_pad);
    println!("set 7 problem 52: {u1:?} => {hash1:?} | {u2:?} => {hash2:?}",);
}

fn set_7_problem_53() {
    let collisions = find_expandable_collisions::<2>(8);
    let long_message: Vec<u8> = (0u128..256).map(|u| u.to_be_bytes()).flatten().collect();
    let long_message_blocks = split_blocks(&long_message);

    let mut state_map: HashMap<[u8; 2], usize> = HashMap::new();
    let mut state = [0x00u8; 2];
    for (i, block) in long_message_blocks.iter().enumerate() {
        state = aes_md_extend_block(block, &state);
        if i > 8 {
            // need to skip first 9, since the shortest expandable + bridge is k + 1 = 9
            state_map.insert(state, i);
        }
    }

    let mut state = [0x00u8; 2];
    for (block_u, _) in collisions.iter() {
        state = aes_md_extend_block(&block_u.to_be_bytes(), &state);
    }

    let mut bridge_u: u128 = 0;
    let index;
    loop {
        let bridge_state = aes_md_extend_block(&bridge_u.to_be_bytes(), &state);
        if let Some(i) = state_map.get(&bridge_state) {
            index = *i;
            break;
        }
        bridge_u += 1;
    }

    let mut expandable = expandable_message(&collisions, index);
    expandable.extend_from_slice(&bridge_u.to_be_bytes());
    for i in index + 1..long_message_blocks.len() {
        expandable.extend_from_slice(&long_message_blocks[i]);
    }

    assert!(expandable.len() == long_message.len());
    let expandable_hash = aes_md::<2>(&expandable);
    let original_hash = aes_md::<2>(&long_message);
    println!("set 7 problem 53: original: {original_hash:?} collision: {expandable_hash:?}");
}

fn set_7_problem_54() {
    let funnel_length = 8;
    let funnel = NostradamusFunnel::<2>::new(funnel_length);

    let total_length = 16; // 16 blocks total for message + chain + padding
    let padding_block = b"pad";
    let target_message = b"YELLOW SUBMARINE, BLUE SUBMARINE";
    let target_hash = aes_md_extend(padding_block, total_length * 16, funnel.final_state());

    let mut message: Vec<u8> = Vec::new();
    message.extend_from_slice(target_message);
    message.resize((total_length - funnel_length - 1) * 16, 0b00);
    let mut state = [0x00u8; 2];
    for block in split_blocks(&message) {
        state = aes_md_extend_block(&block, &state);
    }

    let mut attempt: u128 = 0;
    let mut new_state;
    loop {
        new_state = aes_md_extend_block(&attempt.to_be_bytes(), &state);
        if funnel.in_collision_surface(&new_state) {
            break;
        }
        attempt += 1;
    }

    message.extend_from_slice(&attempt.to_be_bytes());
    message.extend_from_slice(&funnel.construct_collision_chain(&new_state));
    message.extend_from_slice(padding_block);
    let message_hash = aes_md::<2>(&message);

    println!("set 7 problem 54: message hash: {message_hash:?} target hash: {target_hash:?}");
}

fn set_7_problem_55() {
    let collision;
    loop {
        let weak_message = weak_message();
        let mut new_message = weak_message.clone();
        new_message[1] = new_message[1].wrapping_add(1 << 31);
        new_message[2] = new_message[2].wrapping_add(1 << 31).wrapping_sub(1 << 28);
        new_message[12] = new_message[12].wrapping_sub(1 << 16);

        let mut weak_bytes: Vec<u8> = Vec::new();
        let mut new_bytes: Vec<u8> = Vec::new();
        for chunk in weak_message {
            weak_bytes.extend_from_slice(&chunk.to_le_bytes());
        }
        for chunk in new_message {
            new_bytes.extend_from_slice(&chunk.to_le_bytes());
        }
        if md4(&weak_bytes) == md4(&new_bytes) {
            collision = weak_bytes;
            break;
        }
    }

    println!(
        "set 7 problem 55: collision: {}",
        hex_encode(&md4(&collision))
    );
}

fn set_7_problem_56() {
    let mut known = vec![0x00u8; 32];

    for offset in 0..16 {
        let mut occurrences_16: HashMap<u8, u32> = HashMap::new();
        let mut occurrences_32: HashMap<u8, u32> = HashMap::new();
        for _ in 0..3000000 {
            let p = rc4_random_key_oracle(&vec![0x00u8; offset]);
            if let Some(&v) = occurrences_16.get(&p[15]) {
                occurrences_16.insert(p[15], v + 1);
            } else {
                occurrences_16.insert(p[15], 1);
            }
            if offset > 2 {
                if let Some(&v) = occurrences_32.get(&p[31]) {
                    occurrences_32.insert(p[31], v + 1);
                } else {
                    occurrences_32.insert(p[31], 1);
                }
            }
        }

        let i = 15 - offset;
        let peak_16 = occurrences_16
            .iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .map(|(k, _v)| k)
            .unwrap();
        known[i] = peak_16 ^ 0xF0;
        if offset > 2 {
            let peak_32 = occurrences_32
                .iter()
                .max_by(|a, b| a.1.cmp(&b.1))
                .map(|(k, _v)| k)
                .unwrap();
            known[i + 16] = peak_32 ^ 0xE0;
        }
    }

    println!("set 7 problem 56: {}", String::from_utf8_lossy(&known));
}

fn set_8_problem_57() {
    let p = bigint_hex(
        "8977C3217DA1F838B8D24B4A790DE8FC8E35AD5483E463028EF9BBF9AF23A9BD\
         1231EBA9AC7E44363D8311D610B09AA224A023268EE8A60AC484FD9381962563",
    );
    let p = OddUint::new(p).unwrap();
    let g = bigint_hex(
        "572AFF4A93EC6214C1036C62E1818FE5E4E1D6DB635C1B12D9572203C47D241A\
         0E543A89B0B12BA61062411FCF3D29C6AB8C3CE6DAC7D2C9F7F0EBD3B7878AAF",
    );
    let q = bigint_hex("B1B914DE773DFCC8BE82251A2AB4F339");
    let server = DhSubgroupServer::new(&p, &NonZero::new(q).unwrap());

    let j = bigint_hex(
        "C603C3A480AEABFEBBEACE077FCD6F114C33CFD660FA70EE6B2D4859205EE6EA\
        36CA0A2774C44BCD5B41A3FE99428672",
    );
    let mut j = j.div_vartime(&NonZero::new(bigint(18)).unwrap());

    let two = bigint(2);
    let one = bigint(1);
    let zero = bigint(0);
    let mut small_factors = vec![NonZero::new(two).unwrap()];
    let mut test_factor = bigint(5);
    let upper_limit = bigint(65536);
    loop {
        let (div, rem) = j.div_rem(&NonZero::new(test_factor).unwrap());
        if rem == zero {
            j = div;
            small_factors.push(NonZero::new(test_factor).unwrap());
        }
        test_factor = test_factor.wrapping_add(&two);
        if test_factor > upper_limit {
            break;
        }
    }

    let mut residues = Vec::new();
    for factor in small_factors.iter() {
        let mut h;
        loop {
            h = modexp(
                &random_biguint(p.as_nz_ref()),
                &p.wrapping_sub(&one).wrapping_div_vartime(factor),
                &p,
            );
            if h != one {
                break;
            }
        }
        let signature = server.sign(b"crazy flamboyant for the rap enjoyment", &h);

        let mut guess = one;
        loop {
            let bob_secret = modexp(&h, &guess, &p);
            if DhSubgroupServer::mac(b"crazy flamboyant for the rap enjoyment", &bob_secret)
                == signature
            {
                break;
            }
            guess = guess.wrapping_add(&one);
        }
        residues.push(guess);
    }

    let secret = crt(&residues, &small_factors);

    assert!(
        server.sign(b"my clan increase like black unemployment", &two)
            == DhSubgroupServer::mac(
                b"my clan increase like black unemployment",
                &modexp(&two, &secret, &p)
            )
    );

    println!("set 8 problem 57: ok");
}
