//! Meta word encoding/decoding for storing thread count, time limit, and git commit hash.
//!
//! Encoding schemes:
//! - **BIP-39 words** (3 words): Human-readable, compatible with seed phrase format
//! - **Base58** (6 characters): Compact, useful when space is tight
//!
//! Both encode the same data:
//! - Word 1 / bits 0-10: First 11 bits of git commit hash (version pinning)
//! - Word 2 / bits 11-21: Thread count (1-2048, stored as count-1)
//! - Word 3 / bits 22-32: Time limit as ceil(log2(hours)), decode as 2^value hours

use crate::prelude::*;

/// Base58 alphabet (Bitcoin style, no confusing characters like 0, O, I, l)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode a number to base58 string.
fn base58_encode(mut num: u64) -> String {
    if num == 0 {
        return "1".to_string();
    }

    let mut result = Vec::new();
    while num > 0 {
        let remainder = (num % 58) as usize;
        result.push(BASE58_ALPHABET[remainder]);
        num /= 58;
    }
    result.reverse();
    String::from_utf8(result).unwrap()
}

/// Decode a base58 string to a number.
#[allow(dead_code)]
fn base58_decode(s: &str) -> Result<u64> {
    let mut num: u64 = 0;
    for c in s.chars() {
        let digit = BASE58_ALPHABET
            .iter()
            .position(|&b| b as char == c)
            .context(format!("Invalid base58 character: {}", c))?;
        num = num
            .checked_mul(58)
            .and_then(|n| n.checked_add(digit as u64))
            .context("Base58 value too large")?;
    }
    Ok(num)
}

/// Check if we're in a git repository and if it's clean (no uncommitted changes).
pub fn check_git_status() -> Result<()> {
    // Check if we're in a git repo
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .context("Failed to run git. Is git installed?")?;

    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "true" {
        anyhow::bail!("Not in a git repository. --meta flag requires running in a git directory.");
    }

    // Check if the repo is clean (no uncommitted changes)
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .context("Failed to check git status")?;

    if !output.stdout.is_empty() {
        anyhow::bail!(
            "Git repository has uncommitted changes. --meta flag requires a clean git directory.\n\
             Please commit or stash your changes before using --meta."
        );
    }

    Ok(())
}

/// Get the first 11 bits of the current git commit hash.
pub fn get_git_commit_bits() -> Result<u16> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("Failed to get git commit hash")?;

    if !output.status.success() {
        anyhow::bail!("Failed to get git commit hash");
    }

    let hash_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // The commit hash is 40 hex chars. Take first 3 hex chars (12 bits) and use the lower 11 bits.
    // First 3 hex chars give us 12 bits, we mask to 11 bits (0x7FF = 2047).
    let first_hex = &hash_str[..3];
    let bits = u16::from_str_radix(first_hex, 16).context("Failed to parse git commit hash")?;

    // Mask to 11 bits
    Ok(bits & 0x7FF)
}

/// Encode thread count to BIP-39 word index.
/// Thread count must be in range 1-2048 (stored as count-1 to use full 11-bit range).
#[allow(dead_code)]
pub fn encode_thread_count(threads: u32) -> Result<u16> {
    ensure!(
        (1..=2048).contains(&threads),
        "Thread count must be in range 1-2048 for meta encoding, got {}",
        threads
    );
    Ok((threads - 1) as u16)
}

/// Decode BIP-39 word index to thread count.
pub fn decode_thread_count(index: u16) -> u32 {
    (index as u32) + 1
}

/// Encode time limit (in hours) to BIP-39 word index using ceil(log2(hours)).
/// Returns the exponent such that decode gives 2^exponent hours.
/// Minimum time is 1 hour (returns 0).
pub fn encode_time_limit(hours: f64) -> u16 {
    if hours <= 1.0 {
        return 0;
    }
    // ceil(log2(hours))
    let log2 = hours.log2().ceil() as u16;
    // Cap at 2047 (2^2047 hours is practically infinite)
    log2.min(2047)
}

/// Decode BIP-39 word index to time limit (in hours).
/// Returns 2^exponent hours.
pub fn decode_time_limit_hours(exponent: u16) -> f64 {
    2_f64.powi(exponent as i32)
}

/// Convert decoded hours to a Duration.
pub fn decode_time_limit(exponent: u16) -> std::time::Duration {
    let hours = decode_time_limit_hours(exponent);
    std::time::Duration::from_secs_f64(hours * 3600.0)
}

/// Convert a BIP-39 word index to a word.
pub fn index_to_word(index: u16) -> Result<&'static str> {
    let language = bip39::Language::English;
    let word_list = language.word_list();
    ensure!(
        (index as usize) < word_list.len(),
        "Index {} out of range for BIP-39 word list",
        index
    );
    Ok(word_list[index as usize])
}

/// Convert a BIP-39 word to its index.
pub fn word_to_index(word: &str) -> Result<u16> {
    let language = bip39::Language::English;
    let word_list = language.word_list();
    let index = word_list
        .iter()
        .position(|&w| w == word)
        .context(format!("Word '{}' not found in BIP-39 word list", word))?;
    Ok(index as u16)
}

/// Meta words containing the encoded parameters.
pub struct MetaWords {
    /// First 11 bits of git commit hash
    pub git_bits: u16,
    /// Thread count (exact)
    pub threads: u32,
    /// Time limit exponent (ceil(log2(hours)))
    pub time_exponent: u16,
}

impl MetaWords {
    /// Create MetaWords from current git state and parameters.
    pub fn new(threads: u32, time_limit: std::time::Duration) -> Result<Self> {
        check_git_status()?;
        let git_bits = get_git_commit_bits()?;

        let hours = time_limit.as_secs_f64() / 3600.0;
        let time_exponent = encode_time_limit(hours);

        Ok(Self {
            git_bits,
            threads,
            time_exponent,
        })
    }

    /// Create MetaWords from raw values (without git check).
    #[allow(dead_code)]
    pub fn from_parts(git_bits: u16, threads: u32, time_exponent: u16) -> Self {
        Self {
            git_bits,
            threads,
            time_exponent,
        }
    }

    /// Parse MetaWords from three BIP-39 words.
    pub fn from_words(git_word: &str, thread_word: &str, time_word: &str) -> Result<Self> {
        let git_bits = word_to_index(git_word)?;
        let thread_index = word_to_index(thread_word)?;
        let time_exponent = word_to_index(time_word)?;

        Ok(Self {
            git_bits,
            threads: decode_thread_count(thread_index),
            time_exponent,
        })
    }

    /// Parse MetaWords from a base58 encoded string.
    ///
    /// The base58 string encodes a 33-bit value:
    /// - bits 0-10: git_bits (11 bits)
    /// - bits 11-21: threads-1 (11 bits, decoded as threads+1)
    /// - bits 22-32: time_exponent (11 bits)
    #[allow(dead_code)]
    pub fn from_base58(s: &str) -> Result<Self> {
        ensure!(!s.is_empty(), "Empty base58 string");

        let num = base58_decode(s)?;

        // Extract fields from the packed 33-bit value
        // Layout: [time_exponent (11 bits) | threads-1 (11 bits) | git_bits (11 bits)]
        // bits 0-10: git_bits
        // bits 11-21: threads-1
        // bits 22-32: time_exponent
        let git_bits = (num & 0x7FF) as u16;
        let threads = ((num >> 11) & 0x7FF) as u32 + 1; // Add 1 to get actual thread count
        let time_exponent = ((num >> 22) & 0x7FF) as u16;

        Ok(Self {
            git_bits,
            threads,
            time_exponent,
        })
    }

    /// Parse MetaWords from the last 3 words of a 27-word seed phrase.
    /// Returns (24-word seed, MetaWords) if successful.
    pub fn parse_from_seed_phrase(phrase: &str) -> Result<(String, Self)> {
        let words: Vec<&str> = phrase.split_whitespace().collect();

        ensure!(
            words.len() == 27,
            "Expected 27 words for meta-encoded seed phrase, got {}",
            words.len()
        );

        let seed_words = words[..24].join(" ");
        let meta_words = Self::from_words(words[24], words[25], words[26])?;

        Ok((seed_words, meta_words))
    }

    /// Convert to three BIP-39 words.
    pub fn to_words(&self) -> Result<[&'static str; 3]> {
        Ok([
            index_to_word(self.git_bits)?,
            index_to_word(encode_thread_count(self.threads)?)?,
            index_to_word(self.time_exponent)?,
        ])
    }

    /// Encode to a base58 string.
    ///
    /// Packs the 33-bit value: [time_exponent (11 bits) | threads-1 (11 bits) | git_bits (11 bits)]
    /// Maximum value is 2^33 - 1 = 8,589,934,591, which encodes to 6 base58 characters.
    pub fn to_base58(&self) -> String {
        // Pack the fields into a single number (threads stored as count-1)
        let num: u64 = ((self.time_exponent as u64) << 22)
            | (((self.threads - 1) as u64) << 11)
            | (self.git_bits as u64);

        base58_encode(num)
    }

    /// Get the decoded time limit as Duration.
    pub fn time_limit(&self) -> std::time::Duration {
        decode_time_limit(self.time_exponent)
    }

    /// Verify that the current git commit matches the stored git bits.
    pub fn verify_git_bits(&self) -> Result<()> {
        check_git_status()?;
        let current_bits = get_git_commit_bits()?;

        ensure!(
            current_bits == self.git_bits,
            "Git commit hash mismatch! Stored bits: {}, current bits: {}. \
             The encrypted seed was created with a different version of the code.",
            self.git_bits,
            current_bits
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_threads() {
        for threads in [1, 4, 16, 64, 256, 1024, 2047, 2048] {
            let index = encode_thread_count(threads).unwrap();
            assert_eq!(decode_thread_count(index), threads);
        }
    }

    #[test]
    fn test_encode_decode_time() {
        // Test exact powers of 2
        assert_eq!(encode_time_limit(1.0), 0);
        assert_eq!(decode_time_limit_hours(0), 1.0);

        assert_eq!(encode_time_limit(2.0), 1);
        assert_eq!(decode_time_limit_hours(1), 2.0);

        assert_eq!(encode_time_limit(4.0), 2);
        assert_eq!(decode_time_limit_hours(2), 4.0);

        assert_eq!(encode_time_limit(8.0), 3);
        assert_eq!(decode_time_limit_hours(3), 8.0);

        // Test rounding up
        assert_eq!(encode_time_limit(1.5), 1); // ceil(log2(1.5)) = ceil(0.58) = 1 -> 2 hours
        assert_eq!(encode_time_limit(3.0), 2); // ceil(log2(3)) = ceil(1.58) = 2 -> 4 hours
        assert_eq!(encode_time_limit(5.0), 3); // ceil(log2(5)) = ceil(2.32) = 3 -> 8 hours

        // Test less than 1 hour
        assert_eq!(encode_time_limit(0.5), 0); // Rounds to 1 hour
        assert_eq!(encode_time_limit(0.25), 0); // Rounds to 1 hour
    }

    #[test]
    fn test_index_to_word_roundtrip() {
        // Test a few known values
        let test_cases = [(0, "abandon"), (1, "ability"), (2, "able"), (2047, "zoo")];

        for (index, expected_word) in test_cases {
            let word = index_to_word(index).unwrap();
            assert_eq!(word, expected_word);
            let decoded = word_to_index(expected_word).unwrap();
            assert_eq!(decoded, index);
        }
    }

    #[test]
    fn test_thread_count_too_large() {
        assert!(encode_thread_count(0).is_err()); // 0 is invalid
        assert!(encode_thread_count(2049).is_err());
        assert!(encode_thread_count(4096).is_err());
    }

    #[test]
    fn test_thread_count_valid_range() {
        assert!(encode_thread_count(1).is_ok()); // minimum valid
        assert!(encode_thread_count(2048).is_ok()); // maximum valid
    }

    #[test]
    fn test_base58_encode_decode() {
        // Test basic roundtrip
        for num in [
            0,
            1,
            57,
            58,
            100,
            1000,
            12345,
            0x7FF,
            0x1FFFFF,
            0x3FFFFFF,
            0x1FFFFFFFF,
        ] {
            let encoded = base58_encode(num);
            let decoded = base58_decode(&encoded).unwrap();
            assert_eq!(decoded, num, "Failed for num={}, encoded={}", num, encoded);
        }
    }

    #[test]
    fn test_base58_known_values() {
        // Known Bitcoin base58 values
        assert_eq!(base58_encode(0), "1");
        assert_eq!(base58_encode(1), "2");
        assert_eq!(base58_encode(57), "z");
        assert_eq!(base58_encode(58), "21");
        assert_eq!(base58_encode(12345), "4fr");
    }

    #[test]
    fn test_meta_words_base58_roundtrip() {
        // Test roundtrip for various values
        for git_bits in [0, 100, 500, 2047] {
            for threads in [1, 16, 64, 256, 1024] {
                for time_exponent in [0, 1, 5, 10] {
                    let meta = MetaWords::from_parts(git_bits, threads, time_exponent);
                    let encoded = meta.to_base58();
                    let decoded = MetaWords::from_base58(&encoded).unwrap();

                    assert_eq!(
                        decoded.git_bits, git_bits,
                        "git_bits mismatch for encoded={}",
                        encoded
                    );
                    assert_eq!(
                        decoded.threads, threads,
                        "threads mismatch for encoded={}",
                        encoded
                    );
                    assert_eq!(
                        decoded.time_exponent, time_exponent,
                        "time_exponent mismatch for encoded={}",
                        encoded
                    );
                }
            }
        }
    }

    #[test]
    fn test_meta_words_base58_length() {
        // Maximum value (all bits set) should encode to 6 characters
        let meta = MetaWords::from_parts(2047, 2048, 2047);
        let encoded = meta.to_base58();
        assert!(
            encoded.len() <= 6,
            "Base58 encoding too long: {} ({} chars)",
            encoded,
            encoded.len()
        );

        // Minimum value should encode to 1 character
        let meta = MetaWords::from_parts(0, 1, 0);
        let encoded = meta.to_base58();
        assert_eq!(encoded.len(), 1, "Base58 encoding too short: {}", encoded);
    }

    #[test]
    fn test_meta_words_bip39_roundtrip() {
        // Test roundtrip through BIP-39 words
        for git_bits in [0, 100, 500, 2047] {
            for threads in [1, 16, 64, 256, 1024, 2048] {
                for time_exponent in [0, 1, 5, 10] {
                    let meta = MetaWords::from_parts(git_bits, threads, time_exponent);
                    let words = meta.to_words().unwrap();
                    let decoded = MetaWords::from_words(words[0], words[1], words[2]).unwrap();

                    assert_eq!(
                        decoded.git_bits, git_bits,
                        "git_bits mismatch for words={:?}",
                        words
                    );
                    assert_eq!(
                        decoded.threads, threads,
                        "threads mismatch for words={:?}",
                        words
                    );
                    assert_eq!(
                        decoded.time_exponent, time_exponent,
                        "time_exponent mismatch for words={:?}",
                        words
                    );
                }
            }
        }
    }

    #[test]
    fn test_meta_words_parse_from_seed_phrase() {
        // Test parsing from a 27-word seed phrase
        // Create a fake 24-word seed + 3 meta words
        let fake_seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let meta = MetaWords::from_parts(500, 16, 2); // git=500, threads=16, time=4h
        let words = meta.to_words().unwrap();

        let seed_phrase = format!("{} {} {} {}", fake_seed, words[0], words[1], words[2]);

        let (parsed_seed, parsed_meta) = MetaWords::parse_from_seed_phrase(&seed_phrase).unwrap();

        assert_eq!(parsed_seed, fake_seed);
        assert_eq!(parsed_meta.git_bits, 500);
        assert_eq!(parsed_meta.threads, 16);
        assert_eq!(parsed_meta.time_exponent, 2);
    }

    #[test]
    fn test_meta_words_bip39_and_base58_equivalence() {
        // Test that BIP-39 words and base58 encode the same data
        for git_bits in [0, 100, 500, 2047] {
            for threads in [1, 16, 64, 256, 1024, 2048] {
                for time_exponent in [0, 1, 5, 10] {
                    let meta = MetaWords::from_parts(git_bits, threads, time_exponent);

                    // Encode to both formats
                    let words = meta.to_words().unwrap();
                    let base58 = meta.to_base58();

                    // Decode from both formats
                    let from_words = MetaWords::from_words(words[0], words[1], words[2]).unwrap();
                    let from_base58 = MetaWords::from_base58(&base58).unwrap();

                    // Both should decode to the same values
                    assert_eq!(from_words.git_bits, from_base58.git_bits);
                    assert_eq!(from_words.threads, from_base58.threads);
                    assert_eq!(from_words.time_exponent, from_base58.time_exponent);

                    // And match the original
                    assert_eq!(from_words.git_bits, git_bits);
                    assert_eq!(from_words.threads, threads);
                    assert_eq!(from_words.time_exponent, time_exponent);
                }
            }
        }
    }

    #[test]
    fn test_meta_words_known_bip39_words() {
        // Test specific known values to verify BIP-39 word encoding
        // git_bits=0 -> "abandon", threads=1 -> "abandon" (index 0 = threads 1), time_exponent=0 -> "abandon"
        let meta = MetaWords::from_parts(0, 1, 0);
        let words = meta.to_words().unwrap();
        assert_eq!(words, ["abandon", "abandon", "abandon"]);

        // git_bits=1 -> "ability", threads=2 -> "ability" (index 1 = threads 2), time_exponent=1 -> "ability"
        let meta = MetaWords::from_parts(1, 2, 1);
        let words = meta.to_words().unwrap();
        assert_eq!(words, ["ability", "ability", "ability"]);

        // git_bits=2047 -> "zoo", threads=2048 -> "zoo" (index 2047 = threads 2048), time_exponent=2047 -> "zoo"
        let meta = MetaWords::from_parts(2047, 2048, 2047);
        let words = meta.to_words().unwrap();
        assert_eq!(words, ["zoo", "zoo", "zoo"]);
    }
}
