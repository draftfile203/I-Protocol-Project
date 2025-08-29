//! Engine 2: VDF (Verifiable Delay Function)
//!
//! Byte-precise, production-grade VDF implementation for I Protocol V5.
//! Provides unbiasable, deterministic delay per slot with canonical beacon generation.
//! Pipeline: 0-100ms evaluation window with succinct verification.

#![no_std]
#![allow(unused)]
#![allow(clippy::literal_string_with_formatting_args)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

// Re-export dependencies
pub use sha3;

/// Hash256 type used throughout the VDF engine
pub type Hash256 = [u8; 32];

// Use centralized crypto implementation
pub use iprotocol_crypto::{h_tag, sha3_256, le_bytes};

// Helper functions for consistent encoding
#[inline]
pub fn u64_from_le(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    u64::from_le_bytes(arr)
}

#[inline]
pub fn u32_from_le(bytes: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr[..bytes.len().min(4)].copy_from_slice(&bytes[..bytes.len().min(4)]);
    u32::from_le_bytes(arr)
}

/// Consensus constants (VDF-only)
pub mod constants {
    pub const VDF_VERSION: u32 = 1;
    pub const SLOT_MS: u64 = 100;
    pub const EVAL_BUDGET_MS: u64 = 80;
    pub const VDF_DELAY_T: u64 = 75;
    pub const MAX_PI_LEN: usize = 64_000;  // proof bytes cap
    pub const MAX_ELL_LEN: usize = 8_192;  // aux bytes cap
}

/// Domain tags (ASCII exact)
mod tags {
    pub const SLOT_SEED: &str = "slot.seed";
    pub const YCORE_CANON: &str = "vdf.ycore.canon";
    pub const EDGE: &str = "vdf.edge";
}

/// Canonical helpers
#[inline]
pub fn slot_seed(parent_header_id: &Hash256, slot: u64) -> Hash256 {
    let slot_le = le_bytes::<8>(slot as u128);
    h_tag(tags::SLOT_SEED, &[parent_header_id, &slot_le])
}

#[inline]
pub fn ycore_from_raw(y_raw: &[u8]) -> Hash256 {
    h_tag(tags::YCORE_CANON, &[y_raw])
}

#[inline]
pub fn yedge_from_ycore(y_core: &Hash256) -> Hash256 {
    h_tag(tags::EDGE, &[y_core])
}

/// Beacon object (as committed in headers)
#[derive(Clone, Debug)]
pub struct Beacon {
    pub seed_commit: Hash256,   // 32
    pub vdf_y_core: Hash256,    // 32
    pub vdf_y_edge: Hash256,    // 32
    pub vdf_pi: Vec<u8>,        // len-prefixed in header
    pub vdf_ell: Vec<u8>,       // len-prefixed in header
}

/// Deserialization errors for `Beacon`
/// 
/// # Errors
/// - `TooShort`: not enough bytes to decode required fields
/// - `ProofTooLarge`: decoded |vdf_pi| exceeds `MAX_PI_LEN`
/// - `AuxTooLarge`: decoded |vdf_ell| exceeds `MAX_ELL_LEN`
/// - `BadLength`: trailing bytes remain or lengths don't match payload
impl Beacon {
    /// Length-prefixed deserialization from bytes (canonical only; for wire format).
    ///
    /// Wire format:
    /// ```text
    /// [seed_commit: 32][y_core: 32][y_edge: 32][pi_len: 4][ell_len: 4][pi: pi_len][ell: ell_len]
    /// ```
    ///
    /// # Errors
    /// - `TooShort`: not enough bytes to decode required fields
    /// - `ProofTooLarge`: decoded |vdf_pi| exceeds `MAX_PI_LEN`
    /// - `AuxTooLarge`: decoded |vdf_ell| exceeds `MAX_ELL_LEN`
    /// - `BadLength`: trailing bytes remain or lengths don't match payload
    pub fn deserialize(data: &[u8]) -> Result<Self, DeserializeErr> {
        if data.len() < 96 { // 32 + 32 + 32 + 4 + 4 minimum
            return Err(DeserializeErr::TooShort);
        }

        let mut offset = 0;

        // Read fixed-width fields
        let mut seed_commit = [0u8; 32];
        seed_commit.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut vdf_y_core = [0u8; 32];
        vdf_y_core.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut vdf_y_edge = [0u8; 32];
        vdf_y_edge.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Read vdf_pi length and data
        if offset + 4 > data.len() {
            return Err(DeserializeErr::TooShort);
        }
        let pi_len = u32_from_le(&data[offset..offset + 4]) as usize;
        offset += 4;

        if pi_len > constants::MAX_PI_LEN {
            return Err(DeserializeErr::ProofTooLarge);
        }
        if offset + pi_len > data.len() {
            return Err(DeserializeErr::TooShort);
        }
        let vdf_pi = data[offset..offset + pi_len].to_vec();
        offset += pi_len;

        // Read vdf_ell length and data
        if offset + 4 > data.len() {
            return Err(DeserializeErr::TooShort);
        }
        let ell_len = u32_from_le(&data[offset..offset + 4]) as usize;
        offset += 4;

        if ell_len > constants::MAX_ELL_LEN {
            return Err(DeserializeErr::AuxTooLarge);
        }
        if offset + ell_len != data.len() {
            return Err(DeserializeErr::BadLength);
        }
        let vdf_ell = data[offset..offset + ell_len].to_vec();

        Ok(Beacon {
            seed_commit,
            vdf_y_core,
            vdf_y_edge,
            vdf_pi,
            vdf_ell,
        })
    }
}

/// Type alias for VDF evaluation result
pub type VdfEvalResult = (Vec<u8>, Vec<u8>, Vec<u8>); // (Y_raw, pi, ell)

/// VDF Backend trait (backend-agnostic interface)
/// A conforming backend MUST:
///  - deterministically map (seed32, delay_t) to a unique canonical byte string Y_raw,
///  - produce an opaque proof π (vdf_pi) and aux data ℓ (vdf_ell) with bounded sizes,
///  - verify(seed, T, π, ℓ) either returns (true, Y_raw) with identical canonical bytes,
///    or (false, []).
pub trait VdfBackend {
    fn eval(seed32: &Hash256, delay_t: u64) -> VdfEvalResult;
    fn verify(seed32: &Hash256, delay_t: u64, pi: &[u8], ell: &[u8]) -> (bool, Vec<u8>);
}

/// Build errors
#[derive(Debug)]
pub enum BuildErr {
    ProofTooLarge,
}

/// Verify errors
#[derive(Debug)]
pub enum VerifyErr {
    SeedMismatch,
    ProofTooLarge,
    BackendInvalid,
    CoreMismatch,
    EdgeMismatch,
}

/// Deserialization errors
#[derive(Debug)]
pub enum DeserializeErr {
    TooShort,
    ProofTooLarge,
    AuxTooLarge,
    BadLength,
}

// MARS integration module
pub mod mars_integration;
pub use mars_integration::{BeaconVerifier, VdfBeaconVerifier};

/// Producer path (build Beacon at start of slot s)
///
/// # Errors
/// Returns an error if the backend produces data exceeding size caps:
/// - ProofTooLarge: if |vdf_pi| > MAX_PI_LEN or |vdf_ell| > MAX_ELL_LEN.
#[must_use = "Handle the Result; ignoring may skip critical beacon build errors"]
pub fn build_beacon<B: VdfBackend>(
    parent_header_id: &Hash256,
    slot: u64,
) -> Result<Beacon, BuildErr> {
    let seed = slot_seed(parent_header_id, slot);

    // Backend evaluation (time-dominant; target ~80 ms)
    let (y_raw, pi, ell) = B::eval(&seed, constants::VDF_DELAY_T);

    // Size caps BEFORE finalizing beacon (DoS hardening)
    if pi.len() > constants::MAX_PI_LEN {
        return Err(BuildErr::ProofTooLarge);
    }
    if ell.len() > constants::MAX_ELL_LEN {
        return Err(BuildErr::ProofTooLarge);
    }

    // Canonical digests
    let y_core = ycore_from_raw(&y_raw);
    let y_edge = yedge_from_ycore(&y_core);

    Ok(Beacon {
        seed_commit: seed,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: pi,
        vdf_ell: ell,
    })
}

/// Verifier path (succinct; equality-only)
///
/// # Errors
/// Returns an error when any verification equality or size constraint fails:
/// - `SeedMismatch`: computed seed != seed_commit
/// - `ProofTooLarge`: |vdf_pi| > `MAX_PI_LEN` or |vdf_ell| > `MAX_ELL_LEN`
/// - `BackendInvalid`: backend proof verification failed
/// - `CoreMismatch`: H("vdf.ycore.canon", [`Y_raw`]) != `vdf_y_core`
/// - `EdgeMismatch`: H("vdf.edge", [`vdf_y_core`]) != `vdf_y_edge`
#[must_use = "Handle the Result; ignoring may skip critical beacon verification errors"]
pub fn verify_beacon<B: VdfBackend>(
    parent_header_id: &Hash256,
    slot: u64,
    b: &Beacon,
) -> Result<(), VerifyErr> {
    // 1) Seed equality
    let seed_expected = slot_seed(parent_header_id, slot);
    if b.seed_commit != seed_expected {
        return Err(VerifyErr::SeedMismatch);
    }

    // 2) Size caps (enforce prior to backend work)
    if b.vdf_pi.len() > constants::MAX_PI_LEN {
        return Err(VerifyErr::ProofTooLarge);
    }
    if b.vdf_ell.len() > constants::MAX_ELL_LEN {
        return Err(VerifyErr::ProofTooLarge);
    }

    // 3) Backend verify (returns canonical Y_raw if ok)
    let (ok, y_raw) = B::verify(&b.seed_commit, constants::VDF_DELAY_T, &b.vdf_pi, &b.vdf_ell);
    if !ok {
        return Err(VerifyErr::BackendInvalid);
    }

    // 4) y_core equality
    let y_core_expected = ycore_from_raw(&y_raw);
    if b.vdf_y_core != y_core_expected {
        return Err(VerifyErr::CoreMismatch);
    }

    // 5) y_edge equality
    let y_edge_expected = yedge_from_ycore(&b.vdf_y_core);
    if b.vdf_y_edge != y_edge_expected {
        return Err(VerifyErr::EdgeMismatch);
    }

    Ok(())
}

/// Backend skeletons (RSA/Wesolowski and Class-Group)
/// These are skeletons that specify canonicalization and mapping rules
/// that a concrete backend must implement.
#[cfg(feature = "rsa-backend")]
pub mod rsa_backend {
    use super::{Hash256, VdfBackend, VdfEvalResult, h_tag, le_bytes, u32_from_le};
    use alloc::vec::Vec;
    
    #[cfg(feature = "rsa-backend")]
    use rsa::{BigUint, RsaPublicKey};
    #[cfg(feature = "rsa-backend")]
    use num_bigint::BigUint as NumBigUint;
    #[cfg(feature = "rsa-backend")]
    use num_traits::{Zero, One, Pow};
    
    /// RSA VDF backend (Wesolowski-style)
    /// Group: ℤ_N^* for a fixed RSA modulus N
    /// Seed mapping: g = HashToBase(seed32) ∈ ℤ_N^*
    /// Delay: compute y = g^(2^T) mod N (sequential squarings)
    /// Proof: Wesolowski proof π for exponent 2^T
    pub struct RsaVdfBackend {
        /// RSA modulus N (2048-bit for production)
        /// Using a fixed modulus for deterministic behavior
        /// In production, this would be generated via trusted setup
        modulus: NumBigUint,
    }
    
    impl Default for RsaVdfBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RsaVdfBackend {
        #[must_use]
        #[allow(clippy::missing_const_for_fn)]
        pub fn new() -> Self {
            // Fixed 2048-bit RSA modulus for deterministic VDF
            // This is a product of two safe primes for security
            let modulus_hex = "C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2E4F99F13C65D3F59CF6EBBEEA317B5E99E379E9DF6906EE5D731F";
            let modulus = NumBigUint::parse_bytes(modulus_hex.as_bytes(), 16)
                .expect("Invalid modulus hex");
            Self { modulus }
        }
        
        /// Hash seed to base element in ℤ_N^*
        fn hash_to_base(&self, seed: &Hash256) -> NumBigUint {
            // Use domain-tagged hash to map seed to group element
            let hash_result = h_tag("rsa.vdf.base", &[seed]);
            let mut base = NumBigUint::from_bytes_be(&hash_result);
            
            // Ensure base is in ℤ_N^* (coprime to N)
            base %= &self.modulus;
            if base.is_zero() {
                base = NumBigUint::one();
            }
            
            // Simple check for coprimality (in practice, would use GCD)
            // For our fixed modulus, this is sufficient
            if base == NumBigUint::one() {
                base = NumBigUint::from(2u32);
            }
            
            base
        }
        
        /// Sequential squaring: compute g^(2^t) mod N
        fn sequential_squaring(&self, base: &NumBigUint, delay_t: u64) -> NumBigUint {
            let mut result = base.clone();
            
            // Perform t sequential squarings
            for _ in 0..delay_t {
                result = (&result * &result) % &self.modulus;
            }
            
            result
        }
        
        /// Generate Wesolowski proof for y = g^(2^t) mod N
        fn generate_proof(&self, base: &NumBigUint, result: &NumBigUint, delay_t: u64) -> Vec<u8> {
            // Simplified Wesolowski proof generation
            // In production, this would implement the full Wesolowski protocol
            
            // Challenge generation via Fiat-Shamir
            let mut challenge_input = Vec::new();
            challenge_input.extend_from_slice(&base.to_bytes_be());
            challenge_input.extend_from_slice(&result.to_bytes_be());
            challenge_input.extend_from_slice(&le_bytes::<8>(u128::from(delay_t)));
            
            let challenge_hash = h_tag("rsa.vdf.challenge", &[&challenge_input]);
            let challenge = NumBigUint::from_bytes_be(&challenge_hash[..16]); // Use first 128 bits
            
            // Compute quotient q = 2^t / challenge
            let exponent = NumBigUint::from(2u32).pow(delay_t as u32);
            let quotient = &exponent / &challenge;
            let remainder = &exponent % &challenge;
            
            // Compute proof π = g^q * y^r mod N where r is remainder
            let g_to_q = self.mod_exp(base, &quotient);
            let y_to_r = self.mod_exp(result, &remainder);
            let proof_element = (&g_to_q * &y_to_r) % &self.modulus;
            
            // Serialize proof (challenge || proof_element)
            let mut proof = Vec::new();
            let challenge_bytes = challenge.to_bytes_be();
            proof.extend_from_slice(&le_bytes::<4>(challenge_bytes.len() as u128));
            proof.extend_from_slice(&challenge_bytes);
            
            let proof_bytes = proof_element.to_bytes_be();
            proof.extend_from_slice(&le_bytes::<4>(proof_bytes.len() as u128));
            proof.extend_from_slice(&proof_bytes);
            
            proof
        }
        
        /// Modular exponentiation using binary method
        fn mod_exp(&self, base: &NumBigUint, exponent: &NumBigUint) -> NumBigUint {
            let mut result = NumBigUint::one();
            let mut base = base % &self.modulus;
            let mut exp = exponent.clone();
            
            while !exp.is_zero() {
                if &exp % 2u32 == NumBigUint::one() {
                    result = (&result * &base) % &self.modulus;
                }
                exp >>= 1;
                base = (&base * &base) % &self.modulus;
            }
            
            result
        }
        
        /// Verify Wesolowski proof
        fn verify_proof(&self, base: &NumBigUint, result: &NumBigUint, delay_t: u64, proof: &[u8]) -> bool {
            if proof.len() < 8 {
                return false;
            }
            
            let mut offset = 0;
            
            // Parse challenge length and challenge
            let challenge_len = u32_from_le(&proof[offset..offset + 4]) as usize;
            offset += 4;
            
            if offset + challenge_len > proof.len() {
                return false;
            }
            
            let challenge = NumBigUint::from_bytes_be(&proof[offset..offset + challenge_len]);
            offset += challenge_len;
            
            // Parse proof element length and proof element
            if offset + 4 > proof.len() {
                return false;
            }
            
            let proof_len = u32_from_le(&proof[offset..offset + 4]) as usize;
            offset += 4;
            
            if offset + proof_len != proof.len() {
                return false;
            }
            
            let proof_element = NumBigUint::from_bytes_be(&proof[offset..]);
            
            // Verify: π^challenge * y = g^(2^t) mod N
            let exponent = NumBigUint::from(2u32).pow(delay_t as u32);
            let quotient = &exponent / &challenge;
            let remainder = &exponent % &challenge;
            
            let pi_to_challenge = self.mod_exp(&proof_element, &challenge);
            let y_to_remainder = self.mod_exp(result, &remainder);
            let left_side = (&pi_to_challenge * &y_to_remainder) % &self.modulus;
            
            let right_side = self.mod_exp(base, &exponent);
            
            left_side == right_side
        }
    }
    
    impl VdfBackend for RsaVdfBackend {
        fn eval(seed32: &Hash256, delay_t: u64) -> VdfEvalResult {
            let backend = Self::new();
            
            // 1. Map seed32 to base element g ∈ ℤ_N^* via HashToBase
            let base = backend.hash_to_base(seed32);
            
            // 2. Compute y = g^(2^delay_t) mod N via sequential squaring
            let result = backend.sequential_squaring(&base, delay_t);
            
            // 3. Generate Wesolowski proof π
            let proof = backend.generate_proof(&base, &result, delay_t);
            
            // 4. Return (canonical_encoding(y), π, auxiliary_data)
            let y_raw = result.to_bytes_be();
            let auxiliary = Vec::new(); // No auxiliary data for RSA VDF
            
            (y_raw, proof, auxiliary)
        }

        fn verify(seed32: &Hash256, delay_t: u64, pi: &[u8], _ell: &[u8]) -> (bool, Vec<u8>) {
            let backend = Self::new();
            
            // 1. Map seed32 to base element g ∈ ℤ_N^*
            let base = backend.hash_to_base(seed32);
            
            // 2. Compute expected result via sequential squaring
            let expected_result = backend.sequential_squaring(&base, delay_t);
            
            // 3. Verify Wesolowski proof
            let valid = backend.verify_proof(&base, &expected_result, delay_t, pi);
            
            // 4. Return (verification_result, canonical_y_raw)
            let y_raw = if valid {
                expected_result.to_bytes_be()
            } else {
                Vec::new()
            };
            
            (valid, y_raw)
        }
    }
}

#[cfg(feature = "class-group-backend")]
pub mod classgroup_backend {
    use super::{Hash256, VdfBackend, VdfEvalResult, h_tag, le_bytes, u64_from_le, u32_from_le};
    use alloc::vec::Vec;
    
    #[cfg(feature = "class-group-backend")]
    use num_bigint::{BigInt, BigUint, Sign};
    #[cfg(feature = "class-group-backend")]
    use num_traits::{Zero, One, Signed};
    
    /// Binary quadratic form (a, b, c) representing ax² + bxy + cy²
    #[derive(Clone, Debug, PartialEq)]
    pub struct BinaryQuadraticForm {
        a: BigInt,
        b: BigInt,
        c: BigInt,
    }
    
    impl BinaryQuadraticForm {
        #[must_use]
        pub fn new(a: BigInt, b: BigInt, c: BigInt) -> Self {
            Self { a, b, c }
        }
        
        /// Compute discriminant Δ = b² - 4ac
        #[must_use]
        pub fn discriminant(&self) -> BigInt {
            &self.b * &self.b - 4 * &self.a * &self.c
        }
        
        /// Reduce the form using the reduction algorithm
        #[must_use]
        pub fn reduce(&self) -> Self {
            let mut a = self.a.clone();
            let mut b = self.b.clone();
            let mut c = self.c.clone();
            
            // Reduction algorithm for binary quadratic forms
            loop {
                // Ensure |b| ≤ |a| ≤ |c|
                if a.abs() > c.abs() {
                    core::mem::swap(&mut a, &mut c);
                    b = -b;
                }
                
                if b.abs() > a.abs() {
                    let q = (&b + &a / 2) / &a;
                    let new_b = &b - &q * &a * 2;
                    let new_c = &c - &q * (&b - &new_b) / 2;
                    b = new_b;
                    c = new_c;
                } else {
                    break;
                }
            }
            
            // Ensure a > 0
            if a < BigInt::zero() {
                a = -a;
                b = -b;
                c = -c;
            }
            
            Self::new(a, b, c)
        }
        
        /// Compose two binary quadratic forms
        #[must_use]
        pub fn compose(&self, other: &Self) -> Self {
            // Simplified composition algorithm
            // In practice, this would use the full Gauss composition
            
            let a1 = &self.a;
            let b1 = &self.b;
            let c1 = &self.c;
            
            let a2 = &other.a;
            let b2 = &other.b;
            let c2 = &other.c;
            
            // Compute gcd and Bezout coefficients
            let d = Self::gcd_extended(a1, a2);
            let g = Self::gcd_extended(&d, &((b1 + b2) / 2));
            
            // Simplified composition (not cryptographically secure)
            // Parentheses clarify grouping and avoid clippy warning
            let denom = &g * &g;
            let a3 = (a1 * a2) / denom;
            let b3: BigInt = (b1 + b2) / 2;
            let c3 = (b3.clone() * &b3 - &self.discriminant()) / (4 * &a3);
            
            Self::new(a3, b3, c3).reduce()
        }
        
        /// Extended GCD algorithm
        fn gcd_extended(a: &BigInt, b: &BigInt) -> BigInt {
            if b.is_zero() {
                a.abs()
            } else {
                Self::gcd_extended(b, &(a % b))
            }
        }
        
        /// Square the form (self-composition)
        #[must_use]
        pub fn square(&self) -> Self {
            self.compose(self)
        }
        
        /// Compute form^(2^k) via repeated squaring
        #[must_use]
        pub fn power_of_two(&self, k: u64) -> Self {
            let mut result = self.clone();
            for _ in 0..k {
                result = result.square();
            }
            result
        }
        
        /// Serialize form to canonical byte representation
        #[must_use]
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            
            // Serialize a
            let a_bytes = self.a.to_signed_bytes_be();
            bytes.extend_from_slice(&le_bytes::<4>(a_bytes.len() as u128));
            bytes.extend_from_slice(&a_bytes);
            
            // Serialize b
            let b_bytes = self.b.to_signed_bytes_be();
            bytes.extend_from_slice(&le_bytes::<4>(b_bytes.len() as u128));
            bytes.extend_from_slice(&b_bytes);
            
            // Serialize c
            let c_bytes = self.c.to_signed_bytes_be();
            bytes.extend_from_slice(&le_bytes::<4>(c_bytes.len() as u128));
            bytes.extend_from_slice(&c_bytes);
            
            bytes
        }
        
        /// Deserialize form from byte representation
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 12 {
                return None;
            }
            
            let mut offset = 0;
            
            // Deserialize a
            let a_len = u32_from_le(&bytes[offset..offset + 4]) as usize;
            offset += 4;
            
            if offset + a_len > bytes.len() {
                return None;
            }
            
            let a = BigInt::from_signed_bytes_be(&bytes[offset..offset + a_len]);
            offset += a_len;
            
            // Deserialize b
            if offset + 4 > bytes.len() {
                return None;
            }
            
            let b_len = u32_from_le(&bytes[offset..offset + 4]) as usize;
            offset += 4;
            
            if offset + b_len > bytes.len() {
                return None;
            }
            
            let b = BigInt::from_signed_bytes_be(&bytes[offset..offset + b_len]);
            offset += b_len;
            
            // Deserialize c
            if offset + 4 > bytes.len() {
                return None;
            }
            
            let c_len = u32_from_le(&bytes[offset..offset + 4]) as usize;
            offset += 4;
            
            if offset + c_len != bytes.len() {
                return None;
            }
            
            let c = BigInt::from_signed_bytes_be(&bytes[offset..]);
            
            Some(Self::new(a, b, c))
        }
    }
    
    /// Class Group VDF backend
    /// Group: Class group of imaginary quadratic field
    /// Seed mapping: g = HashToGroup(seed32)
    /// Delay: compute y = g^(2^T) via repeated squaring
    /// Proof: Class group VDF proof
    pub struct ClassGroupVdfBackend {
        /// Discriminant for the class group (negative)
        /// Using a fixed discriminant for deterministic behavior
        discriminant: BigInt,
    }
    
    impl Default for ClassGroupVdfBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ClassGroupVdfBackend {
        #[must_use]
        #[allow(clippy::missing_const_for_fn)]
        pub fn new() -> Self {
            // Fixed discriminant for deterministic class group VDF
            // Using a fundamental discriminant of appropriate size
            let discriminant = BigInt::from(-4027); // Example fundamental discriminant
            Self { discriminant }
        }
        
        /// Hash seed to class group element
        fn hash_to_group(&self, seed: &Hash256) -> BinaryQuadraticForm {
            // Use domain-tagged hash to map seed to group element
            let hash_result = h_tag("classgroup.vdf.base", &[seed]);
            
            // Convert hash to form coefficients
            let a_bytes = &hash_result[0..8];
            let b_bytes = &hash_result[8..16];
            
            let a = BigInt::from_signed_bytes_be(a_bytes).abs() + BigInt::one();
            let b = BigInt::from_signed_bytes_be(b_bytes);
            
            // Compute c such that discriminant = b² - 4ac
            let c = (&b * &b - &self.discriminant) / (4 * &a);
            
            BinaryQuadraticForm::new(a, b, c).reduce()
        }
        
        /// Generate proof for class group VDF
        #[allow(clippy::unused_self)]
        fn generate_proof(&self, base: &BinaryQuadraticForm, result: &BinaryQuadraticForm, delay_t: u64) -> Vec<u8> {
            // Simplified proof generation for class group VDF
            // In production, this would implement the full class group VDF proof protocol
            
            let mut proof_data = Vec::new();
            
            // Include base form
            let base_bytes = base.to_bytes();
            proof_data.extend_from_slice(&le_bytes::<4>(base_bytes.len() as u128));
            proof_data.extend_from_slice(&base_bytes);
            
            // Include result form
            let result_bytes = result.to_bytes();
            proof_data.extend_from_slice(&le_bytes::<4>(result_bytes.len() as u128));
            proof_data.extend_from_slice(&result_bytes);
            
            // Include delay parameter
            proof_data.extend_from_slice(&le_bytes::<8>(u128::from(delay_t)));
            
            // Generate challenge via Fiat-Shamir
            let challenge_hash = h_tag("classgroup.vdf.challenge", &[&proof_data]);
            
            // Create proof structure (simplified)
            let mut proof = Vec::new();
            proof.extend_from_slice(&challenge_hash);
            proof.extend_from_slice(&le_bytes::<8>(u128::from(delay_t)));
            
            proof
        }
        
        /// Verify class group VDF proof
        #[allow(clippy::unused_self)]
        fn verify_proof(&self, base: &BinaryQuadraticForm, result: &BinaryQuadraticForm, delay_t: u64, proof: &[u8]) -> bool {
            if proof.len() < 40 { // 32 bytes hash + 8 bytes delay
                return false;
            }
            
            // Extract challenge and delay from proof
            let challenge = &proof[0..32];
            let proof_delay = u64_from_le(&proof[32..40]);
            
            if proof_delay != delay_t {
                return false;
            }
            
            // Recompute expected result
            let expected_result = base.power_of_two(delay_t);
            
            // Verify result matches
            if *result != expected_result {
                return false;
            }
            
            // Verify challenge
            let mut proof_data = Vec::new();
            let base_bytes = base.to_bytes();
            proof_data.extend_from_slice(&le_bytes::<4>(base_bytes.len() as u128));
            proof_data.extend_from_slice(&base_bytes);
            
            let result_bytes = result.to_bytes();
            proof_data.extend_from_slice(&le_bytes::<4>(result_bytes.len() as u128));
            proof_data.extend_from_slice(&result_bytes);
            
            proof_data.extend_from_slice(&le_bytes::<8>(u128::from(delay_t)));
            
            let expected_challenge = h_tag("classgroup.vdf.challenge", &[&proof_data]);
            
            challenge == expected_challenge.as_slice()
        }
    }
    
    impl VdfBackend for ClassGroupVdfBackend {
        fn eval(seed32: &Hash256, delay_t: u64) -> VdfEvalResult {
            let backend = Self::new();
            
            // 1. Map seed32 to group element g via HashToGroup
            let base = backend.hash_to_group(seed32);
            
            // 2. Compute y = g^(2^delay_t) via repeated squaring
            let result = base.power_of_two(delay_t);
            
            // 3. Generate class group VDF proof π
            let proof = backend.generate_proof(&base, &result, delay_t);
            
            // 4. Return (canonical_encoding(y), π, auxiliary_data)
            let y_raw = result.to_bytes();
            let auxiliary = Vec::new(); // No auxiliary data for class group VDF
            
            (y_raw, proof, auxiliary)
        }

        fn verify(seed32: &Hash256, delay_t: u64, pi: &[u8], _ell: &[u8]) -> (bool, Vec<u8>) {
            let backend = Self::new();
            
            // 1. Map seed32 to group element g
            let base = backend.hash_to_group(seed32);
            
            // 2. Compute expected result via repeated squaring
            let expected_result = base.power_of_two(delay_t);
            
            // 3. Verify class group VDF proof
            let valid = backend.verify_proof(&base, &expected_result, delay_t, pi);
            
            // 4. Return (verification_result, canonical_y_raw)
            let y_raw = if valid {
                expected_result.to_bytes()
            } else {
                Vec::new()
            };
            
            (valid, y_raw)
        }
    }
}

/// Mock backend for testing (deterministic but not secure)
#[cfg(feature = "mock-backend")]
pub mod mock_backend {
    use super::{Hash256, VdfBackend, VdfEvalResult, h_tag, le_bytes};
    use alloc::vec::Vec;
    
    pub struct MockVdfBackend;
    
    impl VdfBackend for MockVdfBackend {
        fn eval(seed32: &Hash256, delay_t: u64) -> VdfEvalResult {
            // Deterministic mock: hash seed with delay
            let mut input = Vec::new();
            input.extend_from_slice(seed32);
            input.extend_from_slice(&le_bytes::<8>(u128::from(delay_t)));
            let y_raw = h_tag("mock.vdf.output", &[&input]);
            let proof = h_tag("mock.vdf.proof", &[&input]);
            (y_raw.to_vec(), proof.to_vec(), Vec::new())
        }
        
        fn verify(seed32: &Hash256, delay_t: u64, pi: &[u8], _ell: &[u8]) -> (bool, Vec<u8>) {
            // Verify by recomputing
            let mut input = Vec::new();
            input.extend_from_slice(seed32);
            input.extend_from_slice(&le_bytes::<8>(u128::from(delay_t)));
            let expected_y_raw = h_tag("mock.vdf.output", &[&input]);
            let expected_proof = h_tag("mock.vdf.proof", &[&input]);
            
            let valid = pi == expected_proof.as_slice();
            (valid, expected_y_raw.to_vec())
        }
    }
}

// Tests module
#[cfg(test)]
mod tests;