[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Tyler-Hardin/seed-encrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Tyler-Hardin/seed-encrypt/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Nix Flake](https://img.shields.io/badge/Nix-Flake-7EB6D7.svg)](https://nixos.org/)

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
# Build the project (default: pledge feature enabled, check-history disabled)
nix build

# Run the binary
./result/bin/seed-encrypt
```

### Building with Cargo
```bash
# Default build (pledge feature enabled, minimal dependencies)
cargo build --release

# With address history checking (adds tokio, reqwest, bitcoin dependencies)
# Note: Must disable default features since pledge and check-history are mutually exclusive
cargo build --release --no-default-features --features check-history

# Without seccomp pledging (for non-Linux systems)
cargo build --release --no-default-features
```

### Development
```bash
# Enter development shell
nix develop

# Run tests (default features - pledge enabled)
cargo test

# Run tests with check-history feature (must disable default features)
cargo test --no-default-features --features check-history

# Run tests with no features
cargo test --no-default-features

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
  --check-history         during decryption, check derived addresses for transaction
                          history and exit when a used address is found
                          (only available with "check-history" feature)
```

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `pledge` | ✓ | Seccomp privilege reduction (Linux only) |
| `check-history` | ✗ | Address transaction history checking (adds tokio, reqwest, bitcoin deps) |

**Note:** `pledge` and `check-history` are mutually exclusive. The `check-history` feature adds network dependencies which undermine the security benefits of seccomp pledging.

**Supply chain attack surface:**
- Default build (`pledge`): minimal dependencies, no network code, seccomp sandboxing
- With `check-history`: includes async runtime (tokio) and HTTP client (reqwest) - cannot use pledge
- No features: minimal build without seccomp (for non-Linux systems)

### Example
```bash
# Encrypt a seed phrase (runs for 1 hour)
seed-encrypt --mode encrypt --time-limit 1h

# Decrypt (needs same time limit and thread count used for encryption)
seed-encrypt --mode decrypt --time-limit 2h

# Decrypt with address history checking (requires check-history feature)
# For each potential seed, derives Bitcoin addresses and checks if they've been used
seed-encrypt --mode decrypt --time-limit 2h --check-history
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
