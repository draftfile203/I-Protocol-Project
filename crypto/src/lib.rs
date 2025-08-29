//! Cryptographic foundations for I Protocol V5
//!
//! This module provides the exact cryptographic primitives specified across
//! all five engines: LAMEq-X, VDF, MARS, PADA, and Tokenomics.
//!
//! All implementations are byte-precise and follow the normative specifications.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
use core::fmt;
use sha3::{Digest, Sha3_256};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

/// Hash256 type used throughout I Protocol V5
pub type Hash256 = [u8; 32];

/// Public key type (32 bytes for Ed25519)
pub type PK = [u8; 32];

/// Signature type (64 bytes for Ed25519)
pub type Sig = [u8; 64];

/// Cryptographic errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid signature
    InvalidSignature,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid input length
    InvalidLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::InvalidLength => write!(f, "Invalid input length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

// ——— Integer encoding utilities (normative across all engines) ————————————

/// Convert integer to little-endian bytes with specified width
/// This is the canonical encoding used across all five engines
#[inline]
#[must_use]
pub fn le_bytes<const W: usize>(mut x: u128) -> [u8; W] {
    let mut out = [0u8; W];
    for byte in out.iter_mut().take(W) {
        *byte = (x & 0xFF) as u8;
        x >>= 8;
    }
    out
}

/// Convert little-endian bytes to u64
#[inline]
#[must_use]
pub fn u64_from_le(b: &[u8]) -> u64 {
    let mut x = 0u64;
    for (i, &bi) in b.iter().take(8).enumerate() {
        x |= u64::from(bi) << (8 * i);
    }
    x
}

/// Convert little-endian bytes to u128
#[inline]
#[must_use]
pub fn u128_from_le(b: &[u8]) -> u128 {
    let mut x = 0u128;
    for (i, &bi) in b.iter().take(16).enumerate() {
        x |= u128::from(bi) << (8 * i);
    }
    x
}

// ——— Domain-tagged hashing (normative specification) ——————————————————————

/// SHA3-256 hash function
/// This is the canonical hash function used across all engines
#[inline]
#[must_use]
pub fn sha3_256(input: &[u8]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Domain-tagged SHA3-256 hash with length framing
/// This is the normative hashing discipline used across all five engines
/// 
/// Format: H(tag || len(part1) || part1 || len(part2) || part2 || ...)
/// where `len()` is encoded as LE(8) bytes
#[inline]
#[must_use]
pub fn h_tag(tag: &str, parts: &[&[u8]]) -> Hash256 {
    let mut buf = Vec::new();
    buf.extend_from_slice(tag.as_bytes());
    for p in parts {
        let len = le_bytes::<8>(p.len() as u128);
        buf.extend_from_slice(&len);
        buf.extend_from_slice(p);
    }
    sha3_256(&buf)
}

// ——— Ed25519 signature operations (canonical, non-malleable) ——————————————

/// Generate a new Ed25519 keypair
#[must_use]
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (PK, [u8; 32]) {
    let signing_key = SigningKey::generate(rng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key.to_bytes(), signing_key.to_bytes())
}

/// Sign a message with Ed25519
/// Uses canonical encoding to prevent signature malleability
/// 
/// # Errors
/// 
/// Returns `CryptoError::InvalidPrivateKey` if the private key is invalid
pub fn sign_message(private_key: &[u8; 32], message: &[u8]) -> Result<Sig, CryptoError> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature
/// Enforces canonical encoding to prevent signature malleability
#[must_use]
pub fn verify_sig(pk: &PK, msg: &[u8], sig: &Sig) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    
    let Ok(signature) = Signature::try_from(sig.as_slice()) else {
        return false;
    };
    
    verifying_key.verify(msg, &signature).is_ok()
}

/// Convert public key bytes to `VerifyingKey`
/// 
/// # Errors
/// 
/// Returns `CryptoError::InvalidPublicKey` if the public key is invalid
pub fn pk_to_verifying_key(pk: &PK) -> Result<VerifyingKey, CryptoError> {
    VerifyingKey::from_bytes(pk).map_err(|_| CryptoError::InvalidPublicKey)
}

/// Convert private key bytes to `SigningKey`
/// 
/// # Errors
/// 
/// Returns `CryptoError::InvalidPrivateKey` if the private key is invalid
pub fn sk_to_signing_key(sk: &[u8; 32]) -> Result<SigningKey, CryptoError> {
    Ok(SigningKey::from_bytes(sk))
}

// ——— Merkle tree operations (binary, duplicate-last) ——————————————————————

/// Compute Merkle leaf hash
#[inline]
#[must_use]
pub fn merkle_leaf(payload: &[u8]) -> Hash256 {
    h_tag("merkle.leaf", &[payload])
}

/// Compute Merkle internal node hash
#[inline]
#[must_use]
pub fn merkle_node(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut cat = [0u8; 64];
    cat[..32].copy_from_slice(left);
    cat[32..].copy_from_slice(right);
    h_tag("merkle.node", &[&cat])
}

/// Compute Merkle root from leaf payloads
/// 
/// Uses binary tree with duplicate-last strategy for odd numbers
/// 
/// # Panics
/// 
/// Panics if the input is empty
#[must_use]
pub fn merkle_root(leaves_payload: &[Vec<u8>]) -> Hash256 {
    if leaves_payload.is_empty() {
        return h_tag("merkle.empty", &[]);
    }
    
    let mut level: Vec<Hash256> = leaves_payload
        .iter()
        .map(|p| merkle_leaf(p))
        .collect();
    
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            next.push(merkle_node(&level[i], &level[i + 1]));
        }
        level = next;
    }
    
    level[0]
}

/// Merkle path for proof verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root
    pub siblings: Vec<Hash256>,
    /// Index of the leaf (0-based)
    pub index: u64,
}

impl MerklePath {
    /// Verify a Merkle path against a root
    #[must_use]
    pub fn verify(&self, leaf_hash: &Hash256, root: &Hash256) -> bool {
        let mut current = *leaf_hash;
        let mut index = self.index;
        
        for sibling in &self.siblings {
            if index % 2 == 0 {
                current = merkle_node(&current, sibling);
            } else {
                current = merkle_node(sibling, &current);
            }
            index /= 2;
        }
        
        current == *root
    }
}

/// Build all levels of a Merkle tree from leaf hashes
/// 
/// Uses duplicate-last strategy for odd-sized levels
/// 
/// # Panics
/// 
/// Panics if the input is empty
#[must_use]
pub fn build_tree_levels(leaves: &[Hash256]) -> Vec<Vec<Hash256>> {
    if leaves.is_empty() {
        return vec![];
    }
    
    let mut levels = vec![leaves.to_vec()];
    let mut current_level = leaves.to_vec();
    
    while current_level.len() > 1 {
        if current_level.len() % 2 == 1 {
            current_level.push(*current_level.last().unwrap());
        }
        
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for i in (0..current_level.len()).step_by(2) {
            next_level.push(merkle_node(&current_level[i], &current_level[i + 1]));
        }
        
        levels.push(next_level.clone());
        current_level = next_level;
    }
    
    levels
}

/// Generate Merkle path for a specific leaf index
/// 
/// Returns a Merkle path that can be used to verify inclusion of the leaf
/// at the specified index in the tree represented by the given levels
/// 
/// # Panics
/// 
/// Panics if the level is empty when accessing the last element
#[must_use]
pub fn merkle_path_for_index(levels: &[Vec<Hash256>], leaf_index: u64) -> MerklePath {
    let mut siblings = Vec::new();
    let mut index = leaf_index;
    
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        
        // Safe conversion with bounds checking
        if let Ok(sibling_idx) = usize::try_from(sibling_index) {
            if sibling_idx < level.len() {
                siblings.push(level[sibling_idx]);
            } else {
                // Use the last element (which was duplicated in build_tree_levels)
                siblings.push(*level.last().unwrap());
            }
        } else {
            // Index too large for usize, use the last element
            siblings.push(*level.last().unwrap());
        }
        
        index /= 2;
    }
    
    MerklePath {
        siblings,
        index: leaf_index,
    }
}

/// Verify a Merkle path for a leaf payload against a root
/// 
/// This function takes the actual payload (not pre-hashed) and applies
/// `merkle_leaf()` to it before verification, matching the specification
#[must_use]
pub fn merkle_verify_leaf(root: &Hash256, leaf_payload: &[u8], path: &MerklePath) -> bool {
    let mut current = merkle_leaf(leaf_payload);
    let mut index = path.index;
    
    for sibling in &path.siblings {
        if index % 2 == 0 {
            current = merkle_node(&current, sibling);
        } else {
            current = merkle_node(sibling, &current);
        }
        index /= 2;
    }
    
    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    /// # Panics
    /// 
    /// Panics if byte encoding assertions fail.
    fn test_le_bytes_encoding() {
        assert_eq!(le_bytes::<4>(0x1234_5678), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(le_bytes::<8>(0x1234_5678_9ABC_DEF0), 
                   [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
    }
    
    #[test]
    /// # Panics
    /// 
    /// Panics if hash comparison assertions fail.
    fn test_domain_tagged_hashing() {
        let hash1 = h_tag("test.tag", &[b"hello", b"world"]);
        let hash2 = h_tag("test.tag", &[b"hello", b"world"]);
        let hash3 = h_tag("test.tag", &[b"helloworld"]);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3); // Length framing prevents collision
    }
    
    #[test]
    /// # Panics
    /// 
    /// Panics if signature operations fail or verification assertions fail.
    fn test_ed25519_operations() {
        let mut rng = thread_rng();
        let (pk, sk) = generate_keypair(&mut rng);
        
        let message = b"test message";
        let signature = sign_message(&sk, message).unwrap();
        
        assert!(verify_sig(&pk, message, &signature));
        assert!(!verify_sig(&pk, b"different message", &signature));
    }
    
    #[test]
    /// # Panics
    /// 
    /// Panics if Merkle path verification assertions fail.
    fn test_merkle_operations() {
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];
        
        let root = merkle_root(&leaves);
        let leaf_hashes: Vec<Hash256> = leaves.iter().map(|l| merkle_leaf(l)).collect();
        let levels = build_tree_levels(&leaf_hashes);
        
        for (i, leaf_hash) in leaf_hashes.iter().enumerate() {
            let path = merkle_path_for_index(&levels, i as u64);
            assert!(path.verify(leaf_hash, &root));
        }
    }
    
    #[test]
    /// # Panics
    /// 
    /// Panics if the empty root assertion fails.
    fn test_empty_merkle_root() {
        let empty_leaves: Vec<Vec<u8>> = vec![];
        let root = merkle_root(&empty_leaves);
        let expected = h_tag("merkle.empty", &[]);
        assert_eq!(root, expected);
    }
}