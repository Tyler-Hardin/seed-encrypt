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
  --time-limit <DURATION> how long to hash (e.g., "1h", "30m") (default: 1h)
  --threads <N>           number of threads (default: 16)
  --meta                  append 3 meta words encoding git hash, threads, and time limit
  --meta-base58           print meta info as 6-char base58 string (compact alternative to --meta)
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

# Encrypt with meta words (requires clean git directory)
seed-encrypt --mode encrypt --time-limit 2h --threads 8 --meta

# Decrypt (needs same time limit and thread count used for encryption)
seed-encrypt --mode decrypt --time-limit 2h

# Decrypt with 27-word meta-encoded seed (auto-detects parameters)
seed-encrypt --mode decrypt
# Then enter your 27-word seed phrase - threads and time limit are decoded from the last 3 words

# Decrypt with address history checking (requires check-history feature)
# For each potential seed, derives Bitcoin addresses and checks if they've been used
seed-encrypt --mode decrypt --time-limit 2h --check-history
```

### Meta Words Encoding

The `--meta` flag appends 3 extra BIP-39 words to the encrypted seed phrase, encoding:

| Word | Encodes | Range |
|------|---------|-------|
| 1 | First 11 bits of git commit hash | 0-2047 |
| 2 | Thread count (exact) | 0-2047 |
| 3 | Time limit exponent `ceil(log2(hours))` | 0-2047 |

**Benefits:**
- Never forget your thread count or time limit again
- Version pinning via git commit hash (warns if code version differs)
- Self-documenting encrypted seeds

**Requirements for `--meta`:**
- Must run inside a git repository
- Git directory must be clean (no uncommitted changes)

**Decoding:**
When decrypting with a 27-word seed phrase, the tool automatically:
1. Extracts the last 3 words as meta encoding
2. Decodes thread count and time limit
3. Warns if git commit hash doesn't match current code version
4. Uses the decoded parameters for decryption

**Time Limit Encoding:**
The time limit is encoded as `ceil(log2(hours))` and decoded as `2^exponent` hours:

| Actual Time | Encoded As | Decoded Time |
|-------------|------------|--------------|
| 1h | 0 | 1h |
| 1.5h | 1 | 2h |
| 2h | 1 | 2h |
| 3h | 2 | 4h |
| 4h | 2 | 4h |
| 8h | 3 | 8h |
| 24h (1 day) | 5 | 32h |
| 168h (1 week) | 8 | 256h (~10.7 days) |

The rounding is always upward, ensuring decryption runs at least as long as encryption.

### Base58 Meta Encoding (`--meta-base58`)

For situations where space is tight (e.g., engraving on metal), use `--meta-base58` to output
the meta information as a compact 6-character base58 string instead of 3 BIP-39 words:

```bash
# Output meta as base58 only (6 characters)
seed-encrypt --mode encrypt --time-limit 2h --meta-base58

# Output both 27-word seed phrase AND base58 on separate line
seed-encrypt --mode encrypt --time-limit 2h --meta --meta-base58
```

The base58 encoding packs the same 33 bits:
- Bits 0-10: git commit hash (11 bits)
- Bits 11-21: thread count (11 bits)
- Bits 22-32: time exponent (11 bits)

**Example:** With git bits=500, threads=16, time_exponent=1 (2h), the base58 output is `2kTj`.

To decode a base58 meta string manually, you can use the tool's internal functions or any
base58 decoder with the Bitcoin alphabet (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).

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
able to decrypt your seed phrase. **Use the `--meta` flag to encode thread count and time limit
directly into the encrypted seed phrase, so you never have to remember these parameters.**
