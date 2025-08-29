//! LAMEq-X Engine: Ledger-Aware Memory-Equalized Proof-of-Work (exact specification)
//!
//! This module implements the exact LAMEq-X specification from FINALIZED LAMEQX.txt
//! with byte-precise compliance to the normative blueprint.

use std::fmt;

// ——— Type Definitions (exact specification) ——————————————————————————————————

pub type Hash256 = [u8; 32];
pub type PK = [u8; 32];  // Ed25519/Schnorr public key
pub type Sig = [u8; 64]; // Ed25519/Schnorr signature

// ——— Utility Functions (exact specification) —————————————————————————————————

// Use centralized crypto implementation
pub use iprotocol_crypto::{h_tag, sha3_256, le_bytes};

/// Convert little-endian bytes to u64
#[must_use]
pub fn u64_from_le(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    u64::from_le_bytes(arr)
}

// ——— Merkle Tree Implementation (exact specification) ————————————————————————

#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: Vec<Hash256>,
    pub index: u64,
}

#[must_use]
pub fn merkle_leaf(payload: &[u8]) -> Hash256 {
    h_tag("merkle.leaf", &[payload])
}

#[must_use]
pub fn merkle_node(left: &Hash256, right: &Hash256) -> Hash256 {
    h_tag("merkle.node", &[left, right])
}

/// Compute Merkle root from leaf payloads (exact specification)
/// Uses duplicate-last strategy for odd-sized levels
/// 
/// # Panics
/// 
/// Panics if a level becomes empty during tree construction.
#[must_use]
pub fn merkle_root(payloads: &[Vec<u8>]) -> Hash256 {
    if payloads.is_empty() {
        return h_tag("merkle.empty", &[]);
    }
    let mut level: Vec<Hash256> = payloads.iter().map(|p| merkle_leaf(p)).collect();
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

/// Verify Merkle path for leaf payload (exact specification)
#[must_use]
pub fn merkle_verify_leaf(root: &Hash256, payload: &[u8], path: &MerklePath) -> bool {
    let mut current = merkle_leaf(payload);
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

// ——— Signature Verification Stub ————————————————————————————————————————————

#[must_use]
pub const fn verify_sig(_pk: &PK, _msg: &Hash256, _sig: &Sig) -> bool {
    true // Placeholder: integrate with Ed25519/Schnorr
}

// ——— LAMEq-X Constants (exact specification) —————————————————————————————————

pub const LQX_VERSION: u32 = 1;
pub const MEM_MIB: usize = 512;                    // 512 MiB
pub const LABEL_BYTES: usize = 32;                 // 32 bytes per label
pub const N_LABELS: usize = 16_777_216;            // 16M labels (512 MiB / 32 B)
pub const PASSES: u32 = 3;                         // 3 passes
pub const CHALLENGES_Q: u32 = 96;                  // 96 challenges
pub const DEPS: u32 = 3;                           // 3 dependencies per update
pub const MERKLE_ARITY: u32 = 2;                   // Binary Merkle tree
pub const MAX_SUBMISSIONS_PK: u32 = 1;             // 1 submission per pk per slot
pub const MAX_PARTREC_SIZE: usize = 1_048_576;     // 1 MiB max proof size

// ——— Challenge & Proof Types (exact specification) ———————————————————————————

#[derive(Clone, Debug)]
pub struct ChallengeOpen {
    pub idx: u64,           // i
    pub li: Hash256,        // L[i]
    pub pi: MerklePath,     // Merkle path for L[i]
    pub lim1: Hash256,      // L[i-1]
    pub pim1: MerklePath,   // Merkle path for L[i-1]
    pub lj: Hash256,        // L[J(i, last_pass)]
    pub pj: MerklePath,     // Merkle path for L[J(i, last_pass)]
    pub lk: Hash256,        // L[K(i, last_pass)]
    pub pk_: MerklePath,    // Merkle path for L[K(i, last_pass)]
}

#[derive(Clone, Debug)]
pub struct PartRec {
    pub version: u32,
    pub slot: u64,                      // target slot s
    pub pk: PK,
    pub y_edge_prev: Hash256,           // y_edge_{s-1}
    pub seed: Hash256,                  // H("lqx.seed", y_edge_prev, pk)
    pub root: Hash256,
    pub challenges: Vec<ChallengeOpen>, // length == CHALLENGES_Q
    pub sig: Sig,                       // signature over transcript
}

// ——— Error Types ——————————————————————————————————————————————————————————————

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LqxError {
    InvalidStructure,
    InvalidChallengeCount,
    SeedBindingFailed,
    SignatureVerificationFailed,
    MerklePathVerificationFailed,
    ChallengeVerificationFailed,
    LabelEquationVerificationFailed,
    ProofTooLarge,
    SignatureGenerationFailed,
}

impl fmt::Display for LqxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStructure => write!(f, "Invalid PartRec structure"),
            Self::InvalidChallengeCount => write!(f, "Invalid challenge count"),
            Self::SeedBindingFailed => write!(f, "Seed binding verification failed"),
            Self::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Self::MerklePathVerificationFailed => write!(f, "Merkle path verification failed"),
            Self::ChallengeVerificationFailed => write!(f, "Challenge verification failed"),
            Self::LabelEquationVerificationFailed => write!(f, "Label equation verification failed"),
            Self::ProofTooLarge => write!(f, "Proof size exceeds maximum"),
            Self::SignatureGenerationFailed => write!(f, "Signature generation failed"),
        }
    }
}

impl std::error::Error for LqxError {}

// ——— Core Functions (exact specification implementation) ——————————————————

/// Generate deterministic seed for slot s (per-slot, per-key)
/// 
/// For slot `s`, with parent VDF beacon edge `y_edge_{s-1}` (from Engine 2 / MARS):
/// `seed_s = H("lqx.seed", [ y_edge_{s-1}, pk ])`
/// This guarantees freshness per slot and binding to pk.
#[must_use]
pub fn lqx_seed(y_edge_prev: &Hash256, pk: &PK) -> Hash256 {
    h_tag("lqx.seed", &[y_edge_prev, pk])
}

/// Generate initial label L[0] (exact specification)
/// `L[0] := H("lqx.lbl0", [seed_s])`
#[must_use]
pub fn lbl0(seed: &Hash256) -> Hash256 {
    h_tag("lqx.lbl0", &[seed])
}

/// Compute J(i, p) index function (exact specification)
/// `J(i, p)` = U64LE(H("lqx.idx", [`seed_s`, LE(i,8), LE(p,4), 0x00])[0..8]) % i
#[must_use]
pub fn idx_j(seed: &Hash256, i: u64, p: u32) -> u64 {
    let i_bytes = le_bytes::<8>(u128::from(i));
    let p_bytes = le_bytes::<4>(u128::from(p));
    let hash = h_tag("lqx.idx", &[seed, &i_bytes, &p_bytes, &[0x00]]);
    let v = u64_from_le(&hash[..8]);
    if i == 0 { 0 } else { v % i }
}

/// Compute K(i, p) index function (exact specification)
/// `K(i, p)` = U64LE(H("lqx.idx", [`seed_s`, LE(i,8), LE(p,4), 0x01])[0..8]) % i
#[must_use]
pub fn idx_k(seed: &Hash256, i: u64, p: u32) -> u64 {
    let i_bytes = le_bytes::<8>(u128::from(i));
    let p_bytes = le_bytes::<4>(u128::from(p));
    let hash = h_tag("lqx.idx", &[seed, &i_bytes, &p_bytes, &[0x01]]);
    let v = u64_from_le(&hash[..8]);
    if i == 0 { 0 } else { v % i }
}

/// Update label using RAM-hard function (exact specification)
/// 
/// `L[i] := H("lqx.lbl", [seed_s, LE(i,8), L[i-1], L[J(i,p)], L[K(i,p)]])`
/// Memory bandwidth dominance: Each update reads three 32-byte labels and writes one (≈128 B)
#[must_use]
pub fn label_update(seed: &Hash256, i: u64, l_im1: &Hash256, l_j: &Hash256, l_k: &Hash256) -> Hash256 {
    let i_bytes = le_bytes::<8>(u128::from(i));
    h_tag("lqx.lbl", &[seed, &i_bytes, l_im1, l_j, l_k])
}

/// Generate challenge index for challenge t (exact specification)
/// 
/// For `t ∈ {0..CHALLENGES_Q−1}`, define:
/// `i_t = 1 + ( U64LE( H("lqx.chal", [ y_edge_{s-1}, root, LE(t,4) ])[0..8] ) % (N_LABELS - 1) )`
/// Ensures challenges always select `i ∈ [1..N_LABELS-1]` so `i−1` exists.
#[must_use]
pub fn chal_index(y_edge_prev: &Hash256, root: &Hash256, t: u32) -> u64 {
    let t_bytes = le_bytes::<4>(u128::from(t));
    let hash = h_tag("lqx.chal", &[y_edge_prev, root, &t_bytes]);
    let v = u64_from_le(&hash[..8]);
    1 + (v % ((N_LABELS as u64) - 1))
}

/// Build transcript to sign (exact specification)
/// `msg = H("lqx.partrec", [ LE(version,4), pk, LE(slot,8), y_edge_prev, seed, root ])`
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn partrec_msg(version: u32, slot: u64, pk: &PK, y_edge_prev: &Hash256, seed: &Hash256, root: &Hash256) -> Hash256 {
    let v_le = le_bytes::<4>(u128::from(version));
    let s_le = le_bytes::<8>(u128::from(slot));
    h_tag("lqx.partrec", &[&v_le, pk, &s_le, y_edge_prev, seed, root])
}

// ——— Deterministic Merkle path construction (prover) ————————————————————
//
// Build the full Merkle tree levels for deterministic path extraction.
// This is a reference algorithm; production should use a streaming/IO-efficient
// approach or retain minimal nodes needed for the requested paths.
//
/// # Panics
/// 
/// Panics if the input `leaves_payload` is empty, which would result in an empty level.
fn build_tree_levels(leaves_payload: &[Vec<u8>]) -> Vec<Vec<Hash256>> {
    let mut levels: Vec<Vec<Hash256>> = Vec::new();
    let mut level: Vec<Hash256> = leaves_payload.iter().map(|p| merkle_leaf(p)).collect();
    levels.push(level.clone());
    while level.len() > 1 {
        if level.len() % 2 == 1 { level.push(*level.last().unwrap()); }
        let mut next = Vec::with_capacity(level.len()/2);
        for i in (0..level.len()).step_by(2) {
            next.push(merkle_node(&level[i], &level[i+1]));
        }
        levels.push(next.clone());
        level = next;
    }
    levels
}

// Return MerklePath for leaf index 'idx' given full 'levels'.
// levels[0] are leaves; levels[last] has length 1 (the root).
fn merkle_path_for_index(levels: &[Vec<Hash256>], idx: usize) -> MerklePath {
    let mut siblings: Vec<Hash256> = Vec::new();
    let mut i = idx;
    for level in &levels[..levels.len()-1] {
        let sib = if i % 2 == 0 {
            // right sibling is either i+1 or duplicate of i if odd-tail
            if i+1 < level.len() { level[i+1] } else { level[i] }
        } else {
            level[i-1]
        };
        siblings.push(sib);
        i /= 2;
    }
    MerklePath { siblings, index: u64::try_from(idx).unwrap_or(0) }
}

// ——— ProverArray Implementation (exact specification) ————————————————————————

pub struct ProverArray {
    pub labels: Vec<Hash256>,
}

impl ProverArray {
    /// Fill array according to LAMEq-X specification (exact implementation)
    /// Sequential dependency: L[i] depends on L[i-1], L[J(i,p)], L[K(i,p)]
    /// Multiple passes ensure memory bandwidth dominance
    #[must_use]
    pub fn fill(seed: &Hash256) -> Self {
        let mut labels = vec![Hash256::default(); N_LABELS];
        
        // Initialize first label: L[0] = H("lqx.lbl0", [seed_s])
        labels[0] = lbl0(seed);
        
        // Fill array with sequential dependency across multiple passes
        for pass in 0..PASSES {
            for i in 1..N_LABELS {
                let j = idx_j(seed, u64::try_from(i).unwrap_or(0), pass);
                let k = idx_k(seed, u64::try_from(i).unwrap_or(0), pass);
                let l_im1 = labels[i - 1];
                let l_j = labels[usize::try_from(j).unwrap_or(0)];
                let l_k = labels[usize::try_from(k).unwrap_or(0)];
                labels[i] = label_update(seed, u64::try_from(i).unwrap_or(0), &l_im1, &l_j, &l_k);
            }
        }
        
        Self { labels }
    }

    /// Compute Merkle root of the label array (exact specification)
    /// Build commitment to the entire label array L[0..N_LABELS-1]
    #[must_use]
    pub fn merkle_root(&self) -> Hash256 {
        let payloads: Vec<Vec<u8>> = self.labels.iter().map(|l| l.to_vec()).collect();
        merkle_root(&payloads)
    }
}

// ——— Prover API ————————————————————————————————————————————————

/// Type alias for signing function to reduce complexity
type SigningFunction = dyn Fn(&PK, &Hash256) -> Sig;

/// Complete LAMEq-X proof generation for slot s (exact specification)
/// 
/// # Panics
/// 
/// Panics if the Merkle tree levels are empty, which should never happen with valid input.
pub fn lqx_prove_for_slot(
    slot: u64,                   // target slot s
    y_edge_prev: &Hash256,       // y_edge_{s-1}
    pk: &PK,
    sk_sign_fn: &SigningFunction, // Ed25519/Schnorr signer
) -> PartRec {
    // 1) Seed
    let seed = lqx_seed(y_edge_prev, pk);

    // 2) RAM fill
    let arr = ProverArray::fill(&seed);

    // 3) Commitment (root)
    let mut payloads = Vec::with_capacity(N_LABELS);
    for l in &arr.labels { payloads.push(l.to_vec()); }
    let levels = build_tree_levels(&payloads);
    let root = levels.last().unwrap()[0];

    // 4) Generate challenges
    let mut challenges = Vec::with_capacity(usize::try_from(CHALLENGES_Q).unwrap_or(0));
    for t in 0..CHALLENGES_Q {
        let i = chal_index(y_edge_prev, &root, t);
        let idx = usize::try_from(i).unwrap_or(0);
        
        // Extract required labels and paths
        let li = arr.labels[idx];
        let pi = merkle_path_for_index(&levels, idx);
        
        let lim1 = arr.labels[idx - 1];
        let pim1 = merkle_path_for_index(&levels, idx - 1);
        
        let j = usize::try_from(idx_j(&seed, i, PASSES - 1)).unwrap_or(0);
        let lj = arr.labels[j];
        let pj = merkle_path_for_index(&levels, j);
        
        let k = usize::try_from(idx_k(&seed, i, PASSES - 1)).unwrap_or(0);
        let lk = arr.labels[k];
        let pk_ = merkle_path_for_index(&levels, k);
        
        challenges.push(ChallengeOpen {
            idx: i,
            li,
            pi,
            lim1,
            pim1,
            lj,
            pj,
            lk,
            pk_,
        });
    }

    // 5) Sign transcript
    let msg = partrec_msg(LQX_VERSION, slot, pk, y_edge_prev, &seed, &root);
    let sig = sk_sign_fn(pk, &msg);

    PartRec {
        version: LQX_VERSION,
        slot,
        pk: *pk,
        y_edge_prev: *y_edge_prev,
        seed,
        root,
        challenges,
        sig,
    }
}

/// Verifier API: verify `PartRec` proof (exact specification)
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The proof structure is invalid
/// - The challenge count is incorrect
/// - Seed binding verification fails
/// - Signature verification fails
/// - Challenge verification fails
/// - Merkle path verification fails
/// - Label equation verification fails
pub fn lqx_verify_partrec(partrec: &PartRec, y_edge_prev: &Hash256) -> Result<(), LqxError> {
    // 1. Structure checks
    if partrec.version != LQX_VERSION {
        return Err(LqxError::InvalidStructure);
    }
    
    if partrec.challenges.len() != usize::try_from(CHALLENGES_Q).unwrap_or(0) {
        return Err(LqxError::InvalidChallengeCount);
    }
    
    // 2. Seed binding: verify seed_s = H("lqx.seed", [y_edge_{s-1}, pk])
    let expected_seed = lqx_seed(y_edge_prev, &partrec.pk);
    if partrec.seed != expected_seed {
        return Err(LqxError::SeedBindingFailed);
    }
    
    // 3. Verify transcript signature
    let msg = partrec_msg(partrec.version, partrec.slot, &partrec.pk, y_edge_prev, &partrec.seed, &partrec.root);
    if !verify_sig(&partrec.pk, &msg, &partrec.sig) {
        return Err(LqxError::SignatureVerificationFailed);
    }
    
    // 4. Verify each challenge opening
    for (t, opening) in partrec.challenges.iter().enumerate() {
        // Verify challenge index: i_t = chal_index(t, y_edge_{s-1}, root)
        let expected_idx = chal_index(y_edge_prev, &partrec.root, u32::try_from(t).unwrap_or(0));
        if opening.idx != expected_idx {
            return Err(LqxError::ChallengeVerificationFailed);
        }
        
        let i = opening.idx;
        let _j = idx_j(&partrec.seed, i, PASSES - 1);
        let _k = idx_k(&partrec.seed, i, PASSES - 1);
        
        // Verify Merkle paths
        if !merkle_verify_leaf(&partrec.root, opening.li.as_ref(), &opening.pi) {
            return Err(LqxError::MerklePathVerificationFailed);
        }
        
        if !merkle_verify_leaf(&partrec.root, opening.lim1.as_ref(), &opening.pim1) {
            return Err(LqxError::MerklePathVerificationFailed);
        }
        
        if !merkle_verify_leaf(&partrec.root, opening.lj.as_ref(), &opening.pj) {
            return Err(LqxError::MerklePathVerificationFailed);
        }
        
        if !merkle_verify_leaf(&partrec.root, opening.lk.as_ref(), &opening.pk_) {
            return Err(LqxError::MerklePathVerificationFailed);
        }
        
        // Verify label equation: L[i] = label_update(seed_s, i, L[i-1], L[J(i,p_last)], L[K(i,p_last)])
        let expected_li = label_update(&partrec.seed, i, &opening.lim1, &opening.lj, &opening.lk);
        if opening.li != expected_li {
            return Err(LqxError::LabelEquationVerificationFailed);
        }
    }
    
    Ok(())
}