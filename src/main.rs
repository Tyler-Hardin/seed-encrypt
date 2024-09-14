use clap::Parser;
use zxcvbn;

mod prelude;
use prelude::*;

mod cipher;
use cipher::Cipher;

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

fn main() -> Result<()> {
    // Remove privileges to prevent supply chain attacks. This should be the first thing to run.
    #[cfg(feature="pledge")]
    pledge::pledge()?;

    env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .try_init()?;

    let args = Args::parse();

    let mnemonic = match args.mode {
        Mode::Encrypt | Mode::Decrypt => read_seedword_list(args.private)?,
        Mode::Generate => {
            use rand::Rng;
            let mut entropy = [0u8; 32];
            rand::thread_rng().try_fill(&mut entropy).context("failed to generate entropy")?;
            bip39::Mnemonic::from_entropy(&entropy)?
        }
    };

    let num_words = mnemonic.to_string().split_whitespace().count();
    ensure!(num_words == 24, "Seed must be 24 words. Found {} words.", num_words);

    let password = dialoguer::Password::new()
        .with_prompt("Enter password")
        .allow_empty_password(false)
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .unwrap();

    let fmt_dur = |d: std::time::Duration| {
        let years = d.as_secs_f64() / 60.0 / 60.0 / 24.0 / 365.25;
        if years > 1000. {
            return format!("{}ky", (years / 100.).round() / 10.);
        } else {
            let d = round_duration(d, std::time::Duration::from_secs(60 * 60 * 24));
            humantime::format_duration(d).to_string()
        }
    };

    let zxcvbn = zxcvbn::zxcvbn(&password, &[]).unwrap();
    log::warn!("Password strength: {}", zxcvbn.score());
    log::warn!("Password guesses to crack: {}", zxcvbn.guesses());
    log::warn!("Password crack time with 10k cores: {}",
        fmt_dur(*args.time_limit * (zxcvbn.guesses() / 10_000 / 10) as u32));
    log::warn!("Password suggestions: {:?}", zxcvbn.feedback());
    ensure!(zxcvbn.score() >= 3, "Password is too weak");

    let cipher = Cipher::new(&mnemonic, password.clone(), args.threads)?;

    match args.mode {
        Mode::Encrypt | Mode::Generate => {
            log::info!("Encrypting seed");
            let encrypted_seed = cipher.encrypt(*args.time_limit, true)?;
            {
                log::info!("Validating encrypted seed");
                let cipher = Cipher::new(&encrypted_seed, password.clone(), args.threads)?;
                cipher.decrypt_validate(*args.time_limit * 2, &mnemonic)?
            };

            if args.private && args.mode != Mode::Generate {
                println!("Encrypted seed: {}", encrypted_seed);
            } else {
                println!("Seed: {}", mnemonic);
                println!("Encrypted seed: {}", encrypted_seed);
            }
        },
        Mode::Decrypt => {
            cipher.decrypt(*args.time_limit * 2, true)?;
        }
    }

    Ok(())
}
