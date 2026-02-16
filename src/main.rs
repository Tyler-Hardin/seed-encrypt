use clap::Parser;

// Enforce mutual exclusivity of pledge and check-history features
#[cfg(all(feature = "pledge", feature = "check-history"))]
compile_error!(
    "features `pledge` and `check-history` are mutually exclusive; the `check-history` feature adds network dependencies which undermine the security benefits of seccomp pledging. Use `--no-default-features --features check-history` to disable pledge when using check-history."
);

mod prelude;
use prelude::*;

mod cipher;
use cipher::Cipher;

mod meta;
use meta::MetaWords;

#[cfg(feature = "check-history")]
mod derive_address;

#[cfg(feature = "check-history")]
use derive_address::{check_address_history, derive_addresses};

#[cfg(feature = "pledge")]
mod pledge;

mod tests;

#[derive(clap::ValueEnum, Clone, Debug, Eq, PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
    Generate,
}

#[derive(clap::Parser, Debug)]
struct Args {
    #[clap(long)]
    private: bool,

    #[clap(long, default_value = "encrypt")]
    mode: Mode,

    #[clap(long, default_value = "1h")]
    time_limit: humantime::Duration,

    #[clap(long, default_value = "16")]
    threads: Option<u32>,

    /// Append 3 meta words to the encrypted seed phrase encoding:
    /// - Git commit hash (first 11 bits) for version pinning
    /// - Thread count (exact)
    /// - Time limit as ceil(log2(hours))
    ///
    /// Requires running in a clean git directory.
    /// During decryption, use a 27-word seed phrase to auto-detect parameters.
    #[clap(long)]
    meta: bool,

    /// Print meta info as a 6-character base58 string instead of 3 BIP-39 words.
    /// Useful when space is tight. Encodes the same data as --meta.
    /// Can be used alone or with --meta.
    #[clap(long)]
    meta_base58: bool,

    /// Check derived addresses for transaction history during decryption.
    /// Exits when a seed with used addresses is found.
    /// Only available with "check-history" feature.
    #[cfg(feature = "check-history")]
    #[clap(long)]
    check_history: bool,
}

fn read_seedword_list(private: bool) -> Result<bip39::Mnemonic> {
    use dialoguer::FuzzySelect;

    let language = bip39::Language::English;
    let word_list = {
        let mut wl = ["Done", "Back"].to_vec();
        wl.extend(language.word_list());
        wl
    };

    let mut chosen_words = vec![];
    if private {
        let seed_phrase = dialoguer::Password::new()
            .with_prompt("Enter seed words")
            .allow_empty_password(false)
            .interact()?;
        parse_seed(&seed_phrase)
    } else {
        loop {
            let selection = FuzzySelect::new()
                .with_prompt("What do you choose?")
                .items(&word_list)
                .interact()
                .unwrap();
            match selection {
                0 => break,
                1 => {
                    if !chosen_words.is_empty() {
                        chosen_words.pop();
                    }
                }
                i => {
                    chosen_words.push(word_list[i]);
                    println!("Last chosen word: {}", word_list[selection]);
                    println!("Number of words: {}", chosen_words.len());
                    println!("Chosen words so far: {:?}", chosen_words);
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                }
            }
        }

        println!("Chosen words: {:?}", chosen_words);
        let mnemonic = chosen_words.join(" ");
        parse_seed(&mnemonic)
    }
}

fn parse_seed(seed: &str) -> Result<bip39::Mnemonic> {
    bip39::Mnemonic::parse(seed).context("failed to parse mnemonic")
}

/// Format duration for display, handling very long durations
fn format_duration(d: Duration) -> String {
    let years = d.as_secs_f64() / 60.0 / 60.0 / 24.0 / 365.25;
    if years > 1000. {
        format!("{}ky", (years / 100.).round() / 10.)
    } else {
        let d = round_duration(d, Duration::from_secs(60 * 60 * 24));
        humantime::format_duration(d).to_string()
    }
}

/// Parsed seed input result: (mnemonic, meta_words, threads, time_limit)
type SeedInput = (
    bip39::Mnemonic,
    Option<MetaWords>,
    Option<u32>,
    Option<Duration>,
);

/// Parse seed phrase input, handling meta word encoding if present
fn parse_seed_input(args: &Args) -> Result<SeedInput> {
    match args.mode {
        Mode::Decrypt => {
            let raw_input = if args.private {
                dialoguer::Password::new()
                    .with_prompt("Enter seed words")
                    .allow_empty_password(false)
                    .interact()?
            } else {
                let mn = read_seedword_list(args.private)?;
                let words = mn.to_string();
                println!("Entered seed: {}", words);
                words
            };

            let words: Vec<&str> = raw_input.split_whitespace().collect();

            if words.len() == 27 {
                let (seed_phrase, meta) = MetaWords::parse_from_seed_phrase(&raw_input)?;
                log::info!("Detected 27-word seed phrase with meta encoding");
                log::info!(
                    "Meta words: threads={}, time_limit={}h (decoded from exponent {})",
                    meta.threads,
                    meta.time_limit().as_secs_f64() / 3600.0,
                    meta.time_exponent
                );

                if let Err(e) = meta.verify_git_bits() {
                    log::warn!("Git commit hash verification failed: {}", e);
                    log::warn!(
                        "Proceeding anyway - the encrypted seed may have been created with a different code version"
                    );
                }

                let mnemonic = parse_seed(&seed_phrase)?;
                Ok((mnemonic, Some(meta), None, None))
            } else if words.len() == 24 {
                let mnemonic = parse_seed(&raw_input)?;
                Ok((mnemonic, None, args.threads, Some(*args.time_limit)))
            } else {
                anyhow::bail!("Expected 24 or 27 words, got {}", words.len());
            }
        }
        Mode::Encrypt | Mode::Generate => {
            let mnemonic = match args.mode {
                Mode::Encrypt => read_seedword_list(args.private)?,
                Mode::Generate => {
                    use rand::RngExt;
                    let mut entropy = [0u8; 32];
                    rand::rng().fill(&mut entropy);
                    bip39::Mnemonic::from_entropy(&entropy)?
                }
                _ => unreachable!(),
            };
            Ok((mnemonic, None, args.threads, Some(*args.time_limit)))
        }
    }
}

/// Validate password strength and return password
fn get_and_validate_password(time_limit: Duration) -> Result<String> {
    let password = dialoguer::Password::new()
        .with_prompt("Enter password")
        .allow_empty_password(false)
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .unwrap();

    use zxcvbn::Score;
    let zxcvbn = zxcvbn::zxcvbn(&password, &[]);
    log::warn!("Password strength: {}", zxcvbn.score());
    log::warn!("Password guesses to crack: {}", zxcvbn.guesses());
    log::warn!(
        "Password crack time with 10k cores: {}",
        format_duration(time_limit * (zxcvbn.guesses() / 10_000 / 10) as u32)
    );
    log::warn!("Password suggestions: {:?}", zxcvbn.feedback());
    ensure!(zxcvbn.score() >= Score::Three, "Password is too weak");

    Ok(password)
}

/// Handle encrypt/generate mode output
fn handle_encrypt_output(
    args: &Args,
    mnemonic: &bip39::Mnemonic,
    encrypted_seed: bip39::Mnemonic,
    threads: u32,
    time_limit: Duration,
) -> Result<()> {
    let output = if args.meta || args.meta_base58 {
        let meta = MetaWords::new(threads, time_limit)?;

        if args.meta {
            let meta_words_arr = meta.to_words()?;
            log::info!(
                "Meta words: {} {} {}",
                meta_words_arr[0],
                meta_words_arr[1],
                meta_words_arr[2]
            );
            log::info!("  Git bits: {}", meta.git_bits);
            log::info!("  Threads: {}", meta.threads);
            log::info!(
                "  Time exponent: {} ({}h)",
                meta.time_exponent,
                meta.time_limit().as_secs_f64() / 3600.0
            );

            format!(
                "{} {} {} {}",
                encrypted_seed, meta_words_arr[0], meta_words_arr[1], meta_words_arr[2]
            )
        } else {
            let base58 = meta.to_base58();
            log::info!("Meta base58: {}", base58);
            log::info!("  Git bits: {}", meta.git_bits);
            log::info!("  Threads: {}", meta.threads);
            log::info!(
                "  Time exponent: {} ({}h)",
                meta.time_exponent,
                meta.time_limit().as_secs_f64() / 3600.0
            );
            encrypted_seed.to_string()
        }
    } else {
        encrypted_seed.to_string()
    };

    if args.meta && args.meta_base58 {
        let meta = MetaWords::new(threads, time_limit)?;
        println!("Meta base58: {}", meta.to_base58());
    }

    if args.private && args.mode != Mode::Generate {
        println!("Encrypted seed: {}", output);
    } else {
        println!("Seed: {}", mnemonic);
        println!("Encrypted seed: {}", output);
    }

    Ok(())
}

/// Handle decrypt mode with optional history checking
#[cfg(feature = "check-history")]
fn handle_decrypt(cipher: Cipher, decrypt_time_limit: Duration, check_history: bool) -> Result<()> {
    let handle = tokio::runtime::Handle::current();

    cipher.decrypt(decrypt_time_limit, |seed| {
        let addresses = derive_addresses(seed)?;
        println!("  Legacy:          {}", addresses.legacy);
        println!("  Native SegWit:   {}", addresses.native_segwit);
        println!("  Taproot:         {}", addresses.taproot);

        if check_history {
            match handle.block_on(check_address_history(&addresses))? {
                Some((addr_type, addr)) => {
                    println!("\n=== FOUND USED ADDRESS ===");
                    println!("Address type: {}", addr_type);
                    println!("Address: {}", addr);
                    println!("===========================\n");
                    Ok(true)
                }
                None => {
                    println!("  No transaction history found, continuing...\n");
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    })?;
    Ok(())
}

/// Handle decrypt mode without history checking
#[cfg(not(feature = "check-history"))]
fn handle_decrypt(
    cipher: Cipher,
    decrypt_time_limit: Duration,
    _check_history: bool,
) -> Result<()> {
    cipher.decrypt(decrypt_time_limit, |seed| {
        println!("Potential seed: {}", seed);
        Ok(false)
    })?;
    Ok(())
}

/// Initialize logging and privilege reduction
fn init_runtime() -> Result<()> {
    #[cfg(feature = "pledge")]
    pledge::pledge()?;

    env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .try_init()?;

    Ok(())
}

/// Core application logic shared between async and sync main
fn run(args: Args) -> Result<()> {
    // Warn if time limit is less than 1 hour (should only be used for testing)
    if *args.time_limit < Duration::from_secs(3600) {
        log::warn!(
            "WARNING: Time limit is less than 1 hour. This should only be used for testing!"
        );
    }

    // Parse seed input
    let (mnemonic, meta_words, actual_threads, actual_time_limit) = parse_seed_input(&args)?;

    // Validate seed word count
    let num_words = mnemonic.to_string().split_whitespace().count();
    ensure!(
        num_words == 24,
        "Seed must be 24 words. Found {} words.",
        num_words
    );

    // Get and validate password
    let password = get_and_validate_password(*args.time_limit)?;

    // Resolve parameters (use meta-encoded if available, otherwise CLI args)
    let threads = actual_threads.unwrap_or_else(|| args.threads.unwrap_or(16));
    let time_limit = actual_time_limit.unwrap_or(*args.time_limit);

    // Double the time limit for decryption to account for rounding
    let decrypt_time_limit = if meta_words.is_some() {
        time_limit * 2
    } else {
        *args.time_limit * 2
    };

    // Create cipher
    let cipher = Cipher::new(&mnemonic, password.clone(), Some(threads))?;

    match args.mode {
        Mode::Encrypt | Mode::Generate => {
            log::info!("Encrypting seed");
            let encrypted_seed = cipher.encrypt(time_limit, true)?;

            // Validate encrypted seed
            log::info!("Validating encrypted seed");
            let validate_cipher = Cipher::new(&encrypted_seed, password.clone(), Some(threads))?;
            validate_cipher.decrypt_validate(time_limit * 2, &mnemonic)?;

            handle_encrypt_output(&args, &mnemonic, encrypted_seed, threads, time_limit)?;
        }
        Mode::Decrypt => {
            #[cfg(feature = "check-history")]
            let check_history = args.check_history;
            #[cfg(not(feature = "check-history"))]
            let check_history = false;

            handle_decrypt(cipher, decrypt_time_limit, check_history)?;
        }
    }

    Ok(())
}

/// Main entry point - async version for check-history feature
#[cfg(feature = "check-history")]
#[tokio::main]
async fn main() -> Result<()> {
    init_runtime()?;
    run(Args::parse())
}

/// Main entry point - sync version when check-history is not enabled
#[cfg(not(feature = "check-history"))]
fn main() -> Result<()> {
    init_runtime()?;
    run(Args::parse())
}
