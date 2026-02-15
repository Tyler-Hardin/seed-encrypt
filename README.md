## Introduction
This is a tool for encrypting and decrypting BIP-39 seed phrases. To my knowledge, there is
no other tool that takes a seed phrase and a password and simply returns a new seed phrase.
There are reasons for that, good cryptographic reasons, but I wanted to do it anyway. I wanted
to be able to store my key using one of the existing products (steel capsule, steel plate, etc),
but I really hated the idea of making such a permanent impression of such sensitive data. So
here we are.

## Installation

### Using Nix (recommended)
```bash
# Build the project
nix build

# Run the binary
./result/bin/seed-encrypt
```

### Development
```bash
# Enter development shell
nix develop

# Run tests
cargo test

# Format and lint
cargo fmt
cargo clippy
```

## Usage
```
seed-encrypt [OPTIONS]

Options:
  --mode <MODE>           encrypt, decrypt, or generate (default: encrypt)
  --time-limit <DURATION> how long to hash (e.g., "1h", "30m") (default: 1m)
  --threads <N>           number of threads (default: 16)
  --private               hide seed phrase input (for encryption)
```

### Example
```bash
# Encrypt a seed phrase (runs for 1 hour)
seed-encrypt --mode encrypt --time-limit 1h

# Decrypt (needs same time limit and thread count used for encryption)
seed-encrypt --mode decrypt --time-limit 2h
```

## Implementation
We convert the input seed phrase back into pure entropy. The entropy is hashed with the password
plus a hard coded salt. The hash is repeated until the time limit is reached. The end result
hash is used as a key to encrypt the entropy using a symmetric cipher.

## ⚠️ Caveats and warnings ⚠️
It's technically pretty bad to hash with a constant salt. The salt is supposed to be generated
randomly and stored with the hash. But I didn't want to store the salt (I wanted 256 bits of
output), so it is what it is.

This is why it's important to use a strong password and as high of a time limit as you can
tolerate. I wouldn't use less than an hour. A day is probably better. A week is probably overkill.

It's also really important that you remember your thread count if you use threads. Different
thread counts will produce different results. If you forget your thread count, you will not be
able to decrypt your seed phrase. If you want to be really safe, don't set the option and let
the default option be used. I won't change the default option except maybe once a decade.
