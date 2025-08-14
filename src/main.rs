use clap::Parser;

mod prelude;
use prelude::*;

mod cipher;
use cipher::{Cipher, Salt};

#[cfg(feature="pledge")]
mod pledge;

mod tests;

#[derive(clap::ValueEnum,Clone,Debug,Eq,PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
    Generate,
}

#[derive(clap::Parser,Debug)]
struct Args {
    #[clap(long)]
    private: bool,

    #[clap(long, default_value="encrypt")]
    mode: Mode,

    #[clap(long, default_value="1m")]
    time_limit: humantime::Duration,

    #[clap(long, default_value="16")]
    threads: Option<u32>,

    #[clap(long)]
    dynamic_salt: bool,
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
        assert_eq!(chosen_words.len(), 24);
        let mnemonic = chosen_words.join(" ");
        parse_seed(&mnemonic)
    }
}

fn parse_seed(seed: &str) -> Result<bip39::Mnemonic> {
    bip39::Mnemonic::parse(seed).context("failed to parse mnemonic")
}

/// Represents the execution context after parsing CLI arguments and initial setup
struct ExecutionContext {
    args: Args,
    password: String,
}

impl ExecutionContext {
    fn new(args: Args) -> Result<Self> {
        let is_encrypt_or_generate = matches!(args.mode, Mode::Encrypt | Mode::Generate);

        let password = dialoguer::Password::new()
            .with_prompt("Enter password")
            .allow_empty_password(false)
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?;

        // Validate password strength only for encryption/generation
        if is_encrypt_or_generate {
            let fmt_dur = |d: std::time::Duration| {
                let years = d.as_secs_f64() / 60.0 / 60.0 / 24.0 / 365.25;
                if years > 1000. {
                    format!("{}ky", (years / 100.).round() / 10.)
                } else {
                    let d = round_duration(d, std::time::Duration::from_secs(60 * 60 * 24));
                    humantime::format_duration(d).to_string()
                }
            };

            let zxcvbn = zxcvbn::zxcvbn(&password, &[]).unwrap();
            log::warn!("Password strength: {}", zxcvbn.score());
            log::warn!("Password guesses to crack: {}", zxcvbn.guesses());
            let time_limit_std: std::time::Duration = args.time_limit.into();
            log::warn!("Password crack time with 10k cores: {}",
                fmt_dur(time_limit_std * (zxcvbn.guesses() / 10_000 / 10) as u32));
            log::warn!("Password suggestions: {:?}", zxcvbn.feedback());
            ensure!(zxcvbn.score() >= 3, "Password is too weak");
        }

        Ok(Self {
            args,
            password,
        })
    }

    fn execute(self) -> Result<()> {
        match (&self.args.mode, self.args.dynamic_salt) {
            (Mode::Encrypt, false) => self.execute_encrypt_static(),
            (Mode::Encrypt, true) => self.execute_encrypt_dynamic(),
            (Mode::Generate, false) => self.execute_generate_static(),
            (Mode::Generate, true) => self.execute_generate_dynamic(),
            (Mode::Decrypt, false) => self.execute_decrypt_static(),
            (Mode::Decrypt, true) => self.execute_decrypt_dynamic(),
        }
    }

    fn execute_encrypt_static(self) -> Result<()> {
        let mnemonic = read_seedword_list(self.args.private)?;
        ensure_24_words(&mnemonic)?;

        let cipher = Cipher::new(&mnemonic, self.password.clone(), self.args.threads)?;
        log::info!("Encrypting seed");
        let encrypted_seed = cipher.encrypt(self.args.time_limit.into(), true)?;
        
        // Validate encryption
        log::info!("Validating encrypted seed");
        let cipher = Cipher::new(&encrypted_seed, self.password.clone(), self.args.threads)?;
        let time_limit: std::time::Duration = self.args.time_limit.into();
        cipher.decrypt_validate(time_limit * 2, &mnemonic)?;

        self.print_static_results(&mnemonic, &encrypted_seed);
        Ok(())
    }

    fn execute_encrypt_dynamic(self) -> Result<()> {
        let mnemonic = read_seedword_list(self.args.private)?;
        ensure_24_words(&mnemonic)?;

        let dynamic_salt = Salt::generate_dynamic();
        let salt_base58 = dynamic_salt.to_base58();
        let cipher = Cipher::new_with_dynamic_salt(&mnemonic, self.password.clone(), dynamic_salt, self.args.threads)?;
        
        log::info!("Encrypting seed with dynamic salt");
        let encrypted_base58 = cipher.encrypt_to_base58(self.args.time_limit.into(), true)?;
        
        // Validate encryption
        log::info!("Validating encrypted seed");
        let time_limit: std::time::Duration = self.args.time_limit.into();
        let decrypted_seeds = Cipher::decrypt_base58(&encrypted_base58, self.password.clone(), &salt_base58, time_limit * 2, false, self.args.threads)?;
        if !decrypted_seeds.iter().any(|s| s == &mnemonic) {
            anyhow::bail!("Failed to validate encrypted seed");
        }

        self.print_dynamic_results(Some(&mnemonic), &encrypted_base58, &salt_base58);
        Ok(())
    }

    fn execute_generate_static(self) -> Result<()> {
        let mnemonic = generate_mnemonic()?;
        
        let cipher = Cipher::new(&mnemonic, self.password.clone(), self.args.threads)?;
        log::info!("Encrypting seed");
        let encrypted_seed = cipher.encrypt(self.args.time_limit.into(), true)?;
        
        // Validate encryption
        log::info!("Validating encrypted seed");
        let cipher = Cipher::new(&encrypted_seed, self.password.clone(), self.args.threads)?;
        let time_limit: std::time::Duration = self.args.time_limit.into();
        cipher.decrypt_validate(time_limit * 2, &mnemonic)?;

        self.print_static_results(&mnemonic, &encrypted_seed);
        Ok(())
    }

    fn execute_generate_dynamic(self) -> Result<()> {
        let mnemonic = generate_mnemonic()?;

        let dynamic_salt = Salt::generate_dynamic();
        let salt_base58 = dynamic_salt.to_base58();
        let cipher = Cipher::new_with_dynamic_salt(&mnemonic, self.password.clone(), dynamic_salt, self.args.threads)?;
        
        log::info!("Encrypting seed with dynamic salt");
        let encrypted_base58 = cipher.encrypt_to_base58(self.args.time_limit.into(), true)?;
        
        // Validate encryption
        log::info!("Validating encrypted seed");
        let time_limit: std::time::Duration = self.args.time_limit.into();
        let decrypted_seeds = Cipher::decrypt_base58(&encrypted_base58, self.password.clone(), &salt_base58, time_limit * 2, false, self.args.threads)?;
        if !decrypted_seeds.iter().any(|s| s == &mnemonic) {
            anyhow::bail!("Failed to validate encrypted seed");
        }

        self.print_dynamic_results(Some(&mnemonic), &encrypted_base58, &salt_base58);
        Ok(())
    }

    fn execute_decrypt_static(self) -> Result<()> {
        let mnemonic = read_seedword_list(self.args.private)?;
        ensure_24_words(&mnemonic)?;

        let cipher = Cipher::new(&mnemonic, self.password, self.args.threads)?;
        let time_limit: std::time::Duration = self.args.time_limit.into();
        cipher.decrypt(time_limit * 2, true)?;
        Ok(())
    }

    fn execute_decrypt_dynamic(self) -> Result<()> {
        let encrypted_base58 = dialoguer::Password::new()
            .with_prompt("Enter encrypted seed (base58)")
            .allow_empty_password(false)
            .interact()?;
            
        let salt_base58 = dialoguer::Password::new()
            .with_prompt("Enter salt (base58)")
            .allow_empty_password(false)
            .interact()?;
        
        let time_limit: std::time::Duration = self.args.time_limit.into();
        Cipher::decrypt_base58(&encrypted_base58, self.password, &salt_base58, time_limit * 2, true, self.args.threads)?;
        Ok(())
    }

    fn print_static_results(&self, mnemonic: &bip39::Mnemonic, encrypted_seed: &bip39::Mnemonic) {
        if self.args.private && self.args.mode != Mode::Generate {
            println!("Encrypted seed: {}", encrypted_seed);
        } else {
            println!("Seed: {}", mnemonic);
            println!("Encrypted seed: {}", encrypted_seed);
        }
    }

    fn print_dynamic_results(&self, mnemonic: Option<&bip39::Mnemonic>, encrypted_base58: &str, salt_base58: &str) {
        if self.args.private && self.args.mode != Mode::Generate {
            println!("Encrypted seed (base58): {}", encrypted_base58);
            println!("Salt (base58): {}", salt_base58);
        } else {
            if let Some(mnemonic) = mnemonic {
                println!("Seed: {}", mnemonic);
            }
            println!("Encrypted seed (base58): {}", encrypted_base58);
            println!("Salt (base58): {}", salt_base58);
        }
    }
}

fn generate_mnemonic() -> Result<bip39::Mnemonic> {
    use rand::Rng;
    let mut entropy = [0u8; 32];
    rand::thread_rng().try_fill(&mut entropy).context("failed to generate entropy")?;
    Ok(bip39::Mnemonic::from_entropy(&entropy)?)
}

fn ensure_24_words(mnemonic: &bip39::Mnemonic) -> Result<()> {
    let num_words = mnemonic.to_string().split_whitespace().count();
    ensure!(num_words == 24, "Seed must be 24 words. Found {} words.", num_words);
    Ok(())
}

fn main() -> Result<()> {
    // Remove privileges to prevent supply chain attacks. This should be the first thing to run.
    #[cfg(feature="pledge")]
    pledge::pledge()?;

    env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .try_init()?;

    let args = Args::parse();
    let context = ExecutionContext::new(args)?;
    context.execute()
}
