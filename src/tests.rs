#![allow(dead_code, unused_imports)]

use crate::cipher::Cipher;
use crate::parse_seed;

fn init() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::max())
        .try_init();
}

#[cfg(test)]
fn test_mnemonic(mnemonic: &str, password: &str) {
    let mnemonic = mnemonic.trim();
    let parsed = parse_seed(mnemonic).unwrap();
    let time_limit = std::time::Duration::from_secs(15);

    let cipher = Cipher::new(&parsed, password.to_string(), Some(4)).unwrap();
    let encrypted_seed = cipher.encrypt(time_limit, true).unwrap();

    let cipher = Cipher::new(&encrypted_seed, password.to_string(), Some(4)).unwrap();
    cipher.decrypt_validate(time_limit * 2, &parsed).unwrap();
}

#[test]
fn test24() {
    let mnemonic = "
        machine music coil word wire creek radar staff survey upper jelly unveil
        pill tribe manage book grab eternal fortune disease amateur vessel comic inhale
    ";
    let password = "password24words";
    test_mnemonic(mnemonic, password);
}

/// Deterministic test using fixed cycle count instead of time-based execution.
/// This ensures reproducible results across different machines and runs.
#[test]
fn test_deterministic_cycles() {
    init();

    let mnemonic = "machine music coil word wire creek radar staff survey upper jelly unveil pill tribe manage book grab eternal fortune disease amateur vessel comic inhale";
    let password = "test_password_deterministic";
    let cycles = 5;

    let parsed = parse_seed(mnemonic).unwrap();

    // Encrypt with fixed cycles
    let cipher = Cipher::new(&parsed, password.to_string(), Some(4)).unwrap();
    let encrypted_seed = cipher.encrypt_cycles(cycles, false).unwrap();

    // Verify the encrypted seed is deterministic
    let expected = "jazz sort practice invite busy clump deal situate curve calm position boring rural because health night usual crack team year horror athlete planet loan";
    assert_eq!(
        encrypted_seed.to_string(),
        expected,
        "Encrypted seed should be deterministic for fixed cycles"
    );

    // Decrypt and validate with same number of cycles
    let cipher = Cipher::new(&encrypted_seed, password.to_string(), Some(4)).unwrap();
    cipher.decrypt_validate_cycles(cycles, &parsed).unwrap();
}
