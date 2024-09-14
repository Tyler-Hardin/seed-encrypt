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

use std::sync::LazyLock;
use std::time::{Duration,Instant};

// Using a constant salt is bad, but the goal is to have 256 bits input and 256 bits output with
// only a password as extra input. It is what it is. I figure some salt is better than no salt.
static SALT: LazyLock<&[u8]> = LazyLock::new(|| {
    let nums = [
        0x65f71a65d3cb1c16210fa2dfb4502775u128,
        0xe592b4a4c0aa536a3b65de9d4d01c480u128,
        0x4cefd807d4ff378f15805708fd4b43f6u128,
        0xf0172570c5c02c577126196871fb3584u128,
    ];
    let nums = nums.iter().flat_map(|n| n.to_be_bytes()).collect::<Vec<u8>>();
    assert_eq!(nums.iter().map(|i: &u8| *i as u64).sum::<u64>(), 7848);
    nums.leak()
});


/// The cipher generator. We generate keys for encrypting and decrypting the key by recursively
/// hashing the password with Argon2 and Balloon, increasing the time cost of each until the
/// target duration is reached.
///
/// We hash the password+salt with Argon2.
///
/// Then use the output as a secret for Balloon<Sha256> and concatenate the Argon2 output to the
/// password before hashing with Balloon.
///
/// If the runtime has been long enough, the user can use the most recent result to encrypt the
/// key with AES-256.
///
/// If the run time has not been long enough, we increase the time cost of Argon2 and Balloon and
/// try again.
pub struct Cipher {
    // key: Mnemonic,
    password: String,
    entropy: [u8; 32],
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
            entropy
        };

        Ok(Self {
            // key,
            password,
            entropy,
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

        let argon2_hash = Hasher::default()
            .algorithm(Algorithm::Argon2id)
            .hash_length(32)
            .salt_length(SALT.len().try_into()?)
            .custom_salt(*SALT)
            .iterations(self.argon2_time_cost)
            .memory_cost_kib(params::ARGON2_MEM_COST)
            .threads(self.threads)
            .hash(self.get_hash_input().as_slice())?;

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
        use aes::Aes256;
        use aes::cipher::{Block, BlockEncrypt};

        let mut entropy = self.entropy.to_vec();
        let cipher = self.next_key()?;
        let block1 = Block::<Aes256>::from_mut_slice(&mut entropy[0..16]);
        cipher.encrypt_block(block1);
        let block2 = Block::<Aes256>::from_mut_slice(&mut entropy[16..32]);
        cipher.encrypt_block(block2);
        bip39::Mnemonic::from_entropy(&entropy)
            .context("failed to create encrypted seed")
    }

    fn next_decrypted(&mut self) -> Result<Mnemonic> {
        use aes::Aes256;
        use aes::cipher::{Block, BlockDecrypt};

        let mut entropy = self.entropy.to_vec();
        let cipher = self.next_key()?;
        let block1 = Block::<Aes256>::from_mut_slice(&mut entropy[0..16]);
        cipher.decrypt_block(block1);
        let block2 = Block::<Aes256>::from_mut_slice(&mut entropy[16..32]);
        cipher.decrypt_block(block2);
        bip39::Mnemonic::from_entropy(&entropy)
            .context("failed to create encrypted seed")
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
}
