#![allow(dead_code,unused_imports)]

use crate::parse_seed;
use crate::cipher::Cipher;
use bip39::Mnemonic;

fn init() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::max())
        .try_init();
}

#[cfg(test)]
fn test_mnemonic(mnemonic: &str, password: &str) -> Mnemonic {
    let mnemonic = mnemonic.trim();
    let parsed = parse_seed(mnemonic).unwrap();
    let time_limit = std::time::Duration::from_secs(15);
    
    let cipher = Cipher::new(&parsed, password.to_string(), Some(4)).unwrap();
    let encrypted_seed = cipher.encrypt(time_limit, true).unwrap();

    let cipher = Cipher::new(&encrypted_seed, password.to_string(), Some(4)).unwrap();
    cipher.decrypt_validate(time_limit * 2, &parsed).unwrap();
    encrypted_seed
}

#[test]
fn test24() {
    let mnemonic = "
        machine music coil word wire creek radar staff survey upper jelly unveil
        pill tribe manage book grab eternal fortune disease amateur vessel comic inhale
    ";
    let expected_output = "
        shrug pluck cement exclude half honey output coil brand spatial force soon display
        twenty inform connect skill lonely stuff release behave split speak valve
    ";
    let expected_output = parse_seed(expected_output).unwrap();
    let password = "password24words";
    let output = test_mnemonic(mnemonic, password);
    println!("Expect: {}", &expected_output);
    println!("Output: {}", &output);
    assert_eq!(output, expected_output);
}
