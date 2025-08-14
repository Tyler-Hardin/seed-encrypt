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
    let time_limit = std::time::Duration::from_secs(10);
    
    let cipher = Cipher::new(&parsed, password.to_string(), Some(4)).unwrap();
    let encrypted_seed = cipher.encrypt(time_limit, true).unwrap();

    let cipher = Cipher::new(&encrypted_seed, password.to_string(), Some(4)).unwrap();
    cipher.decrypt_validate(time_limit * 2, &parsed).unwrap();
    encrypted_seed
}

#[cfg(test)]  
fn test_mnemonic_dynamic_salt(mnemonic: &str, password: &str, salt_hex: &str) -> String {
    use crate::cipher::Salt;
    
    let mnemonic = mnemonic.trim();
    let parsed = parse_seed(mnemonic).unwrap();
    let time_limit = std::time::Duration::from_secs(10);
    
    // Create a deterministic salt from hex for testing
    let salt_bytes = hex::decode(salt_hex).unwrap();
    let mut salt_array = [0u8; 32];
    salt_array.copy_from_slice(&salt_bytes); // Use all 32 bytes
    let salt = Salt::new(salt_array);
    
    let salt_base58 = salt.to_base58();
    let cipher = Cipher::new_with_dynamic_salt(&parsed, password.to_string(), salt, Some(4)).unwrap();
    let encrypted_base58 = cipher.encrypt_to_base58(time_limit, true).unwrap();
    
    // Validate by decrypting
    let decrypted_seeds = Cipher::decrypt_base58(&encrypted_base58, password.to_string(), &salt_base58, time_limit * 2, false, Some(4)).unwrap();
    assert!(decrypted_seeds.iter().any(|s| s == &parsed));
    
    encrypted_base58
}

#[test]
fn test24() {
    let mnemonic = "
        machine music coil word wire creek radar staff survey upper jelly unveil
        pill tribe manage book grab eternal fortune disease amateur vessel comic inhale
    ";
    let expected_output = "
        orient trim when dawn cloud video raw sense prison expand wife slim
        outdoor expand diet kind liar east wasp tennis blade social today rain
    ";
    let expected_output = parse_seed(expected_output).unwrap();
    let password = "password24words";
    let output = test_mnemonic(mnemonic, password);
    println!("Expect: {}", &expected_output);
    println!("Output: {}", &output);
    assert_eq!(output, expected_output);
}

#[test]
fn test24_dynamic_salt() {
    init();
    // Test dynamic salt encryption with the same test vectors as test24
    // This ensures that dynamic salt mode produces consistent, deterministic output
    // when using a fixed salt value (for testing purposes only)
    let mnemonic = "
        machine music coil word wire creek radar staff survey upper jelly unveil
        pill tribe manage book grab eternal fortune disease amateur vessel comic inhale
    ";
    let password = "password24words";
    // Use a deterministic salt for testing (32 bytes of incrementing values)
    // This allows us to have reproducible test results while still testing the dynamic salt code path
    let salt_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let expected_output = "AeJ3:kobG:D1Kb:XR1h:UKz8:aa7K:9UPT:j1x2:yzqS:NRFB:6Ygq";
    
    let output = test_mnemonic_dynamic_salt(mnemonic, password, salt_hex);
    println!("Expected: {}", expected_output);
    println!("Output: {}", &output);
    
    assert_eq!(output, expected_output);
}

#[test]
fn test_base58_formatting() {
    use crate::cipher::Salt;
    
    // Test that we can create salt and format it with colons
    let salt_bytes = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let mut salt_array = [0u8; 32];
    salt_array.copy_from_slice(&salt_bytes);
    let salt = Salt::new(salt_array);
    
    let formatted = salt.to_base58();
    println!("Formatted salt: {}", formatted);
    
    // Test that we can parse back the formatted version
    let parsed_salt = Salt::from_base58(&formatted).unwrap();
    assert_eq!(salt.0, parsed_salt.0);
    
    // Test with spaces in input
    let with_spaces = formatted.replace(":", " : ");
    let parsed_with_spaces = Salt::from_base58(&with_spaces).unwrap();
    assert_eq!(salt.0, parsed_with_spaces.0);
    
    // Test with mixed spaces and colons
    let mixed = "1111:2222 3333:4444   5555";
    let cleaned = Salt::clean_base58_input(&mixed);
    assert_eq!(cleaned, "11112222333344445555");
}
