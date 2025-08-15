#![allow(clippy::suspicious_doc_comments)]
///!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
///
///   DO NOT CHANGE THIS FILE!
///
///   This file generates the cipher used to encrypt and decrypt the key.
///
///   The parameters for the Argon2 and Balloon hash functions are set to be extremely slow.
///
///   This is to make it difficult for attackers to brute force the password.
///
///   Changing the parameters to something other than the defaults will mean that you will not
///   be able to decrypt the data that was encrypted with the default parameters. You will need
///   to remember your password AND the parameters you used to encrypt the data.
///
///   Do not change this file.
///
///!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

mod params {
    pub const ARGON2_MEM_COST: u32         = 2 * 1024 * 1024;   // 2 GiB (units of 1KiB)
    pub const ARGON2_TIME_COST_INIT: u32   = 10;
    pub const DEFAULT_THREADS: u32         = 16;
}

pub const _1SEC: Duration = Duration::from_secs(1);

use crate::prelude::*;
use bip39::Mnemonic;


use std::time::{Duration,Instant};

#[derive(Clone)]
pub struct Salt(pub &'static [u8]);

impl Salt {
    /// Create a new Salt from a 32-byte array
    pub fn new(salt: [u8; 32]) -> Self {
        Salt(salt.to_vec().leak())
    }

    /// Create a new Salt from a slice (must be exactly 32 bytes)
    pub fn from_slice(salt: &[u8]) -> Result<Self> {
        if salt.len() != 32 {
            anyhow::bail!("salt must be 32 bytes, got {}", salt.len());
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(salt);
        Ok(Salt(array.to_vec().leak()))
    }

    /// Generate a random dynamic salt (32 bytes)
    pub fn generate_dynamic() -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        Salt::new(salt)
    }

    /// Create a static salt from the predefined constants
    pub fn static_salt() -> Self {
        let nums = [
            0x65f71a65d3cb1c16210fa2dfb4502775u128,
            0xe592b4a4c0aa536a3b65de9d4d01c480u128,
            0x4cefd807d4ff378f15805708fd4b43f6u128,
            0xf0172570c5c02c577126196871fb3584u128,
        ];
        let bytes: Vec<u8> = nums.iter().flat_map(|n| n.to_be_bytes()).collect();
        assert_eq!(bytes.len(), 64);
        // Take first 32 bytes for the new 32-byte salt format
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[0..32]);
        Salt::new(salt)
    }

    /// Convert salt to base58 string with colon separators every 4 characters
    pub fn to_base58(&self) -> String {
        let base58 = bs58::encode(&self.0).into_string();
        Self::format_base58_with_colons(&base58)
    }

    /// Create salt from base58 string (accepts colons and spaces as separators)
    pub fn from_base58(s: &str) -> Result<Self> {
        let cleaned = Self::clean_base58_input(s);
        let bytes = bs58::decode(&cleaned).into_vec().context("invalid base58 salt")?;
        Self::from_slice(&bytes)
    }

    /// Format a base58 string with colons every 4 characters
    fn format_base58_with_colons(base58: &str) -> String {
        base58
            .chars()
            .enumerate()
            .fold(String::new(), |mut acc, (i, c)| {
                if i > 0 && i % 4 == 0 {
                    acc.push(':');
                }
                acc.push(c);
                acc
            })
    }

    /// Clean base58 input by removing colons and spaces
    pub fn clean_base58_input(s: &str) -> String {
        s.chars()
            .filter(|&c| c != ':' && c != ' ')
            .collect()
    }
}

struct Entropy([u8; 32]);

impl Entropy {
    pub fn encrypt(&self, cipher: &aes::Aes256) -> Result<Mnemonic> {
        use aes::Aes256;
        use aes::cipher::{Block, BlockEncrypt};

        let mut entropy = self.0.to_vec();
        let block1 = Block::<Aes256>::from_mut_slice(&mut entropy[0..16]);
        cipher.encrypt_block(block1);
        let block2 = Block::<Aes256>::from_mut_slice(&mut entropy[16..32]);
        cipher.encrypt_block(block2);
        bip39::Mnemonic::from_entropy(&entropy)
            .context("failed to create encrypted seed")
    }

    pub fn decrypt(&self, cipher: &aes::Aes256) -> Result<Mnemonic> {
        use aes::Aes256;
        use aes::cipher::{Block, BlockDecrypt};

        let mut entropy = self.0.to_vec();
        let block1 = Block::<Aes256>::from_mut_slice(&mut entropy[0..16]);
        cipher.decrypt_block(block1);
        let block2 = Block::<Aes256>::from_mut_slice(&mut entropy[16..32]);
        cipher.decrypt_block(block2);
        bip39::Mnemonic::from_entropy(&entropy)
            .context("failed to create decrypted seed")
    }

    pub fn encrypt_to_base58(&self, cipher: &aes::Aes256) -> Result<String> {
        use aes::Aes256;
        use aes::cipher::{Block, BlockEncrypt};

        let mut entropy = self.0.to_vec();
        let block1 = Block::<Aes256>::from_mut_slice(&mut entropy[0..16]);
        cipher.encrypt_block(block1);
        let block2 = Block::<Aes256>::from_mut_slice(&mut entropy[16..32]);
        cipher.encrypt_block(block2);
        let base58 = bs58::encode(&entropy).into_string();
        Ok(Salt::format_base58_with_colons(&base58))
    }



    pub fn decrypt_from_base58(encrypted_base58: &str, cipher: &aes::Aes256) -> Result<Mnemonic> {
        use aes::Aes256;
        use aes::cipher::{Block, BlockDecrypt};

        // Clean input by removing colons and spaces before decoding
        let cleaned = Salt::clean_base58_input(encrypted_base58);
        let mut entropy = bs58::decode(&cleaned).into_vec().context("invalid base58 entropy")?;
        if entropy.len() != 32 {
            anyhow::bail!("encrypted entropy must be 32 bytes, got {}", entropy.len());
        }
        let block1 = Block::<Aes256>::from_mut_slice(&mut entropy[0..16]);
        cipher.decrypt_block(block1);
        let block2 = Block::<Aes256>::from_mut_slice(&mut entropy[16..32]);
        cipher.decrypt_block(block2);
        bip39::Mnemonic::from_entropy(&entropy)
            .context("failed to create decrypted seed")
    }
}




/// The cipher generator. We generate keys for encrypting and decrypting the key by recursively
/// hashing the password with Argon2, increasing the time cost of each until the target duration
/// is reached.
///
/// We hash the password+salt with Argon2.
///
/// If the runtime has been long enough, the user can use the most recent result to encrypt the
/// key with AES-256.
///
/// If the run time has not been long enough, we increase the time cost and try again.
pub struct Cipher {
    password: String,
    entropy: Entropy,
    salt: Salt,
    argon2_time_cost: u32,
    threads: u32,
    last_result: [u8; 32],
    round: u32,
}

impl Cipher {
    pub fn new(key: &Mnemonic, password: String, threads: Option<u32>) -> Result<Self> {
        let entropy = {
            let mut entropy = [0; 32];
            let entropy_vec = key.to_entropy();
            assert!(entropy_vec.len() == 32);
            entropy.copy_from_slice(&entropy_vec);
            Entropy(entropy)
        };

        let salt = Salt::static_salt();

        Ok(Self {
            password,
            entropy,
            salt,
            argon2_time_cost: params::ARGON2_TIME_COST_INIT,
            threads: threads.unwrap_or(params::DEFAULT_THREADS),
            last_result: [0u8; 32],
            round: 0,
        })
    }

    pub fn new_with_dynamic_salt(key: &Mnemonic, password: String, dynamic_salt: Salt, threads: Option<u32>) -> Result<Self> {
        let entropy = {
            let mut entropy = [0; 32];
            let entropy_vec = key.to_entropy();
            assert!(entropy_vec.len() == 32);
            entropy.copy_from_slice(&entropy_vec);
            Entropy(entropy)
        };

        Ok(Self {
            password,
            entropy,
            salt: dynamic_salt,
            argon2_time_cost: params::ARGON2_TIME_COST_INIT,
            threads: threads.unwrap_or(params::DEFAULT_THREADS),
            last_result: [0u8; 32],
            round: 0,
        })
    }

    fn get_hash_input(&self) -> Vec<u8> {
        let mut input = self.password.as_bytes().to_vec();
        if self.last_result.iter().all(|b| *b == 0) {
            return input;
        }
        input.extend_from_slice(&self.last_result);
        input
    }

    fn do_argon2_hash(&mut self) -> Result<()> {
        use argon2_kdf::*;

        let start = Instant::now();

        let hash_input = self.get_hash_input();
        let argon2_hash = Hasher::default()
            .algorithm(Algorithm::Argon2id)
            .hash_length(32)
            .salt_length(self.salt.0.len().try_into()?)
            .custom_salt(self.salt.0)
            .iterations(self.argon2_time_cost)
            .memory_cost_kib(params::ARGON2_MEM_COST)
            .threads(self.threads)
            .hash(&hash_input)?;

        assert_eq!(argon2_hash.as_bytes().len(), self.last_result.len());
        self.last_result.copy_from_slice(argon2_hash.as_bytes());

        log::trace!("Argon2 hash took {:?}", round_duration(start.elapsed(), _1SEC));
        Ok(())
    }

    fn next_key(&mut self) -> Result<aes::Aes256> {
        use aes::cipher::KeyInit;

        self.do_argon2_hash()?;

        let cipher = aes::Aes256::new_from_slice(&self.last_result[0..32])
            .context("failed to create cipher")?;

        self.round += 1;
        self.argon2_time_cost = (self.argon2_time_cost * 2).max(self.argon2_time_cost + 1);

        Ok(cipher)
    }

    fn next_encrypted(&mut self) -> Result<Mnemonic> {
        let cipher = self.next_key()?;
        self.entropy.encrypt(&cipher)
    }

    fn next_decrypted(&mut self) -> Result<Mnemonic> {
        let cipher = self.next_key()?;
        self.entropy.decrypt(&cipher)
    }

    pub fn encrypt(mut self, time_limit: Duration, print: bool) -> Result<Mnemonic> {
        let start = Instant::now();

        let log_round = |round| {
            if print {
                let elapsed = start.elapsed();
                let elapsed = round_duration(elapsed, Duration::from_secs(1));
                let elapsed = humantime::format_duration(elapsed);
                log::info!("Finished round {} in {}", round, elapsed);
            }
        };

        let mut key = self.next_encrypted()?;
        log_round(self.round);

        while start.elapsed() < time_limit {
            key = self.next_encrypted()?;
            log_round(self.round);
        }
        Ok(key)
    }

    pub fn encrypt_to_base58(mut self, time_limit: Duration, print: bool) -> Result<String> {
        let start = Instant::now();

        let log_round = |round| {
            if print {
                let elapsed = start.elapsed();
                let elapsed = round_duration(elapsed, Duration::from_secs(1));
                let elapsed = humantime::format_duration(elapsed);
                log::info!("Finished round {} in {}", round, elapsed);
            }
        };

        let cipher = self.next_key()?;
        let mut encrypted_base58 = self.entropy.encrypt_to_base58(&cipher)?;
        log_round(self.round);

        while start.elapsed() < time_limit {
            let cipher = self.next_key()?;
            encrypted_base58 = self.entropy.encrypt_to_base58(&cipher)?;
            log_round(self.round);
        }
        Ok(encrypted_base58)
    }

    pub fn decrypt(mut self, time_limit: Duration, print: bool) -> Result<Vec<Mnemonic>> {
        let start = Instant::now();
        let mut keys = vec![];
        while start.elapsed() < time_limit {
            let key = self.next_decrypted()?;
            if print {
                println!("Potential key: {}", key);
            }
            keys.push(key);
        }
        Ok(keys)
    }

    pub fn decrypt_validate(mut self, time_limit: Duration, validate: &Mnemonic) -> Result<()> {
        let start = std::time::Instant::now();
        let log_round = |round| {
            let elapsed = start.elapsed();
            let elapsed = round_duration(elapsed, Duration::from_secs(1));
            let elapsed = humantime::format_duration(elapsed);
            log::info!("Finished round {} in {}", round, elapsed);
        };

        while start.elapsed() < time_limit {
            let key = self.next_decrypted()?;
            log_round(self.round);

            if key == *validate {
                return Ok(());
            }
        }
        anyhow::bail!("failed to validate encrypted key")
    }

    pub fn decrypt_base58(encrypted_base58: &str, password: String, salt_base58: &str, time_limit: Duration, print: bool, threads: Option<u32>) -> Result<Vec<Mnemonic>> {
        let salt = Salt::from_base58(salt_base58)?;
        let start = Instant::now();
        let mut keys = vec![];

        let mut cipher = Self {
            password,
            entropy: Entropy([0; 32]), // Will be overridden
            salt,
            argon2_time_cost: params::ARGON2_TIME_COST_INIT,
            threads: threads.unwrap_or(params::DEFAULT_THREADS),
            last_result: [0u8; 32],
            round: 0,
        };

        while start.elapsed() < time_limit {
            let aes_cipher = cipher.next_key()?;
            let key = Entropy::decrypt_from_base58(encrypted_base58, &aes_cipher)?;
            if print {
                println!("Potential key: {}", key);
            }
            keys.push(key);
        }
        Ok(keys)
    }
}
