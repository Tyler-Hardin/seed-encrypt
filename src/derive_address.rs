//! Bitcoin address derivation from BIP-39 mnemonic seeds.
//!
//! Derives the three major Bitcoin address types:
//! - Legacy (P2PKH) via BIP-44
//! - Native SegWit (P2WPKH) via BIP-84
//! - Taproot (P2TR) via BIP-86
//!
//! This module is only available when the `check-history` feature is enabled.

use crate::prelude::*;
use bip39::Mnemonic;

/// Derived Bitcoin addresses from a seed phrase.
#[derive(Debug, Clone)]
pub struct DerivedAddresses {
    /// Legacy P2PKH address (starts with "1")
    /// Derivation path: m/44'/0'/0'/0/0 (BIP-44)
    pub legacy: String,
    /// Native SegWit P2WPKH address (starts with "bc1q")
    /// Derivation path: m/84'/0'/0'/0/0 (BIP-84)
    pub native_segwit: String,
    /// Taproot P2TR address (starts with "bc1p")
    /// Derivation path: m/86'/0'/0'/0/0 (BIP-86)
    pub taproot: String,
}

impl std::fmt::Display for DerivedAddresses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Legacy (P2PKH):        {}", self.legacy)?;
        writeln!(f, "Native SegWit (P2WPKH): {}", self.native_segwit)?;
        write!(f, "Taproot (P2TR):        {}", self.taproot)
    }
}

/// Derives Bitcoin addresses from a 24-word BIP-39 mnemonic seed.
///
/// # Arguments
/// * `mnemonic` - The BIP-39 mnemonic (must be 24 words for 256-bit entropy)
///
/// # Returns
/// * `Result<DerivedAddresses>` - The three major Bitcoin address types
///
/// # Errors
/// Returns an error if the mnemonic is invalid or derivation fails.
pub fn derive_addresses(mnemonic: &Mnemonic) -> Result<DerivedAddresses> {
    use bip32::{DerivationPath, XPrv};
    use bitcoin::{Address, CompressedPublicKey, Network, XOnlyPublicKey};

    // Get the seed from the mnemonic
    let seed = mnemonic.to_seed("");

    // Derive Legacy address (BIP-44): m/44'/0'/0'/0/0
    let legacy_path: DerivationPath = "m/44'/0'/0'/0/0"
        .parse()
        .context("failed to parse legacy derivation path")?;
    let legacy_xprv =
        XPrv::derive_from_path(seed, &legacy_path).context("failed to derive legacy path")?;
    let legacy_pubkey = CompressedPublicKey::from_slice(&legacy_xprv.public_key().to_bytes())
        .context("failed to create legacy public key")?;
    let legacy_address = Address::p2pkh(legacy_pubkey, Network::Bitcoin);

    // Derive Native SegWit address (BIP-84): m/84'/0'/0'/0/0
    let segwit_path: DerivationPath = "m/84'/0'/0'/0/0"
        .parse()
        .context("failed to parse segwit derivation path")?;
    let segwit_xprv =
        XPrv::derive_from_path(seed, &segwit_path).context("failed to derive segwit path")?;
    let segwit_pubkey = CompressedPublicKey::from_slice(&segwit_xprv.public_key().to_bytes())
        .context("failed to create segwit public key")?;
    let segwit_address = Address::p2wpkh(&segwit_pubkey, Network::Bitcoin);

    // Derive Taproot address (BIP-86): m/86'/0'/0'/0/0
    let taproot_path: DerivationPath = "m/86'/0'/0'/0/0"
        .parse()
        .context("failed to parse taproot derivation path")?;
    let taproot_xprv =
        XPrv::derive_from_path(seed, &taproot_path).context("failed to derive taproot path")?;

    // For Taproot, we need the x-only public key
    let taproot_pubkey_bytes = taproot_xprv.public_key().to_bytes();
    // Compressed public key is 33 bytes, x-only is the last 32 bytes (skip the prefix byte)
    let xonly_pubkey = XOnlyPublicKey::from_slice(&taproot_pubkey_bytes[1..33])
        .context("failed to create x-only public key for taproot")?;

    // For Taproot address we need a Secp256k1 context
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let taproot_address = Address::p2tr(&secp, xonly_pubkey, None, Network::Bitcoin);

    Ok(DerivedAddresses {
        legacy: legacy_address.to_string(),
        native_segwit: segwit_address.to_string(),
        taproot: taproot_address.to_string(),
    })
}

/// Checks if a Bitcoin address has any transaction history.
///
/// Uses the Blockstream API to query transaction history.
///
/// # Arguments
/// * `address` - The Bitcoin address to check
///
/// # Returns
/// * `Result<bool>` - true if the address has transactions, false otherwise
pub async fn address_has_history(address: &str) -> Result<bool> {
    let url = format!("https://blockstream.info/api/address/{}/txs", address);

    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .context("failed to send request to blockstream API")?;

    if !response.status().is_success() {
        anyhow::bail!("blockstream API returned status {}", response.status());
    }

    let body = response
        .text()
        .await
        .context("failed to read response body")?;

    // Parse the JSON and verify it's an array
    let txs: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse blockstream API response as JSON")?;

    // Check that it's an array and not empty
    match txs.as_array() {
        Some(arr) => Ok(!arr.is_empty()),
        None => anyhow::bail!("blockstream API returned non-array JSON"),
    }
}

/// Checks all three derived addresses for transaction history.
/// Returns the first address type that has history, along with the address.
///
/// # Arguments
/// * `addresses` - The derived addresses to check
///
/// # Returns
/// * `Result<Option<(&'static str, String)>>` - (address_type, address) if found, None otherwise
pub async fn check_address_history(
    addresses: &DerivedAddresses,
) -> Result<Option<(&'static str, String)>> {
    // Check native segwit first (most commonly used nowadays)
    if address_has_history(&addresses.native_segwit).await? {
        return Ok(Some(("Native SegWit", addresses.native_segwit.clone())));
    }

    // Check legacy
    if address_has_history(&addresses.legacy).await? {
        return Ok(Some(("Legacy", addresses.legacy.clone())));
    }

    // Check taproot
    if address_has_history(&addresses.taproot).await? {
        return Ok(Some(("Taproot", addresses.taproot.clone())));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_bacon_mnemonic() -> Mnemonic {
        Mnemonic::parse("bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon").unwrap()
    }

    #[test]
    fn test_bacon_legacy() {
        let mnemonic = get_bacon_mnemonic();
        let addresses = derive_addresses(&mnemonic).unwrap();

        assert!(
            addresses.legacy.starts_with('1'),
            "Legacy address should start with '1'"
        );
        assert_eq!(addresses.legacy, "159ysWF6HKJHvzCFEkVvDnHNgBjkbqj6K4");
    }

    #[test]
    fn test_bacon_segwit() {
        let mnemonic = get_bacon_mnemonic();
        let addresses = derive_addresses(&mnemonic).unwrap();

        assert!(
            addresses.native_segwit.starts_with("bc1q"),
            "Native SegWit should start with 'bc1q'"
        );
        assert_eq!(
            addresses.native_segwit,
            "bc1qyngkwkslw5ng4v7m42s8t9j6zldmhyvrnnn9k5"
        );
    }

    #[test]
    fn test_bacon_taproot() {
        let mnemonic = get_bacon_mnemonic();
        let addresses = derive_addresses(&mnemonic).unwrap();

        assert!(
            addresses.taproot.starts_with("bc1p"),
            "Taproot should start with 'bc1p'"
        );
        assert_eq!(
            addresses.taproot,
            "bc1pn6enrmgfgfgwx2szefrsjwc4tsgv0wneme604lwae7ek280n8xmskvt37a"
        );
    }

    #[tokio::test]
    async fn test_bacon_address_has_history() {
        // The bacon addresses are known to have transaction history
        let mnemonic = get_bacon_mnemonic();
        let addresses = derive_addresses(&mnemonic).unwrap();

        // Check that at least one of the bacon addresses has history
        let has_history = check_address_history(&addresses).await.unwrap();
        assert!(
            has_history.is_some(),
            "At least one bacon address should have history"
        );

        let (addr_type, addr) = has_history.unwrap();
        println!("\nFound history for {} address: {}", addr_type, addr);
    }
}
