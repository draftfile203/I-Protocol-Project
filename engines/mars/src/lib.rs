//! Engine 3: MARS (Mathematical Absolute Resolution System)
//!
//! Byte-precise, production-grade implementation coherent with
//! LAMEq-X (E1), VDF (E2), and PADA (E4).
//!
//! Provides deterministic header validation with absolute finality.

#![no_std]
#![allow(unused)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;

// Re-export dependencies
pub use sha3;

// ——— Types ————————————————————————————————————————————————————————
pub type Hash256 = [u8; 32];
// Alias for VDF beacon fields to reduce type complexity in function signatures
pub type BeaconFields = (Hash256, Hash256, Hash256, Vec<u8>, Vec<u8>); // (seed_commit, y_core, y_edge, pi, ell)

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

// ——— Merkle (binary; duplicate last when odd) ————————————————
#[inline] 
pub fn merkle_leaf(payload: &[u8]) -> Hash256 { 
    h_tag("merkle.leaf", &[payload]) 
}

#[inline]
pub fn merkle_node(l: &Hash256, r: &Hash256) -> Hash256 {
    let mut cat = [0u8; 64];
    cat[..32].copy_from_slice(l);
    cat[32..].copy_from_slice(r);
    h_tag("merkle.node", &[&cat])
}

pub fn merkle_root(leaves_payload: &[Vec<u8>]) -> Hash256 {
    if leaves_payload.is_empty() { return h_tag("merkle.empty", &[]); }
    let mut lvl: Vec<Hash256> = leaves_payload.iter().map(|p| merkle_leaf(p)).collect();
    while lvl.len() > 1 {
        if lvl.len() % 2 == 1 { lvl.push(*lvl.last().unwrap()); }
        let mut nxt = Vec::with_capacity(lvl.len()/2);
        for i in (0..lvl.len()).step_by(2) { nxt.push(merkle_node(&lvl[i], &lvl[i+1])); }
        lvl = nxt;
    }
    lvl[0]
}

// ——— Canonical leaf encodings (normative) ————————————————
#[derive(Clone)]
pub struct TicketLeaf {
    pub ticket_id:   Hash256,
    pub txid:        Hash256,
    pub sender:      [u8; 32], // PK
    pub nonce:       u64,
    pub amount_iota: u128,
    pub fee_iota:    u128,
    pub s_admit:     u64,
    pub s_exec:      u64,
    pub commit_hash: Hash256,
}

pub fn enc_ticket_leaf(t: &TicketLeaf) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 32 + 8 + 16 + 16 + 8 + 8 + 32);
    out.extend_from_slice(&h_tag("ticket.leaf", &[]));
    out.extend_from_slice(&t.ticket_id);
    out.extend_from_slice(&t.txid);
    out.extend_from_slice(&t.sender);
    out.extend_from_slice(&le_bytes::<8>(t.nonce as u128));
    out.extend_from_slice(&le_bytes::<16>(t.amount_iota));
    out.extend_from_slice(&le_bytes::<16>(t.fee_iota));
    out.extend_from_slice(&le_bytes::<8>(t.s_admit as u128));
    out.extend_from_slice(&le_bytes::<8>(t.s_exec as u128));
    out.extend_from_slice(&t.commit_hash);
    out
}

#[inline]
pub fn enc_txid_leaf(txid: &Hash256) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32);
    out.extend_from_slice(&h_tag("txid.leaf", &[]));
    out.extend_from_slice(txid);
    out
}

// ——— VDF adapter (Engine 2) ————————————————————————————————

pub trait BeaconVerifier {
    /// Enforces all VDF equalities + size caps for (parent_id, slot).
    /// Returns true iff:
    ///   seed_commit == H("slot.seed", [parent_id, LE(slot,8)]) &&
    ///   backend proof verifies (reconstructs canonical Y_raw) &&
    ///   vdf_y_core == H("vdf.ycore.canon", [Y_raw]) &&
    ///   vdf_y_edge == H("vdf.edge", [vdf_y_core]) &&
    ///   |vdf_pi| ≤ MAX_PI_LEN, |vdf_ell| ≤ MAX_ELL_LEN
    #[allow(clippy::too_many_arguments)]
    fn verify_beacon(
        &self,
        parent_id: &Hash256,
        slot: u64,
        seed_commit: &Hash256,
        vdf_y_core: &Hash256,
        vdf_y_edge: &Hash256,
        vdf_pi: &[u8],
        vdf_ell: &[u8],
    ) -> bool;
}

// ——— Root providers (Engine 4) ——————————————————————————————
pub trait TicketRootProvider {
    /// Deterministically compute the ticket_root for slot `slot` using:
    ///   1) build the set of TicketRecord for slot `slot`
    ///   2) sort by ascending txid (raw bytes)
    ///   3) leaf payload = enc_ticket_leaf()
    ///   4) return Merkle root
    fn compute_ticket_root(&self, slot: u64) -> Hash256;
}

pub trait TxRootProvider {
    /// Deterministically compute the txroot for slot `slot` over executed txids:
    ///   1) build the txid set for slot `slot`
    ///   2) sort ascending (raw bytes)
    ///   3) leaf payload = enc_txid_leaf(txid)
    ///   4) return Merkle root
    fn compute_txroot(&self, slot: u64) -> Hash256;
}

// ——— MARS constants ————————————————————————————————————————
pub const MARS_VERSION: u32 = 1;

// ——— Header struct & canonical ID ————————————————————————————
#[derive(Clone, Debug)]
pub struct Header {
    pub parent_id:         Hash256,
    pub slot:              u64,
    pub consensus_version: u32,

    // VDF (E2)
    pub seed_commit:       Hash256,
    pub vdf_y_core:        Hash256,
    pub vdf_y_edge:        Hash256,
    pub vdf_pi:            Vec<u8>,  // len-prefixed when serialized
    pub vdf_ell:           Vec<u8>,  // len-prefixed when serialized

    // PADA (E4)
    pub ticket_root:       Hash256,  // slot s
    pub txroot_prev:       Hash256,  // slot s-1
}

impl Header {
    /// Serialize header to bytes (normative layout for network transport)
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.parent_id);                        // 32
        bytes.extend_from_slice(&le_bytes::<8>(self.slot as u128));      // 8
        bytes.extend_from_slice(&le_bytes::<4>(self.consensus_version as u128)); // 4

        bytes.extend_from_slice(&self.seed_commit);                      // 32
        bytes.extend_from_slice(&self.vdf_y_core);                       // 32
        bytes.extend_from_slice(&self.vdf_y_edge);                       // 32
        bytes.extend_from_slice(&le_bytes::<4>(self.vdf_pi.len() as u128)); // 4
        bytes.extend_from_slice(&self.vdf_pi);                           // |pi|
        bytes.extend_from_slice(&le_bytes::<4>(self.vdf_ell.len() as u128)); // 4
        bytes.extend_from_slice(&self.vdf_ell);                          // |ell|

        bytes.extend_from_slice(&self.ticket_root);                      // 32
        bytes.extend_from_slice(&self.txroot_prev);                      // 32
        bytes
    }

    /// Deserialize header from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 32 + 8 + 4 + 32 + 32 + 32 + 4 + 4 + 32 + 32 {
            return Err("Header too short");
        }

        let mut offset = 0;
        
        let mut parent_id = [0u8; 32];
        parent_id.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        let slot = u64_from_le(&bytes[offset..offset + 8]);
        offset += 8;
        
        let consensus_version = u32_from_le(&bytes[offset..offset + 4]);
        offset += 4;
        
        let mut seed_commit = [0u8; 32];
        seed_commit.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        let mut vdf_y_core = [0u8; 32];
        vdf_y_core.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        let mut vdf_y_edge = [0u8; 32];
        vdf_y_edge.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        let pi_len = u32_from_le(&bytes[offset..offset + 4]) as usize;
        offset += 4;
        
        if offset + pi_len > bytes.len() {
            return Err("Invalid pi length");
        }
        let vdf_pi = bytes[offset..offset + pi_len].to_vec();
        offset += pi_len;
        
        if offset + 4 > bytes.len() {
            return Err("Missing ell length");
        }
        let ell_len = u32_from_le(&bytes[offset..offset + 4]) as usize;
        offset += 4;
        
        if offset + ell_len > bytes.len() {
            return Err("Invalid ell length");
        }
        let vdf_ell = bytes[offset..offset + ell_len].to_vec();
        offset += ell_len;
        
        if offset + 64 > bytes.len() {
            return Err("Missing ticket_root or txroot_prev");
        }
        
        let mut ticket_root = [0u8; 32];
        ticket_root.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        let mut txroot_prev = [0u8; 32];
        txroot_prev.copy_from_slice(&bytes[offset..offset + 32]);
        
        Ok(Header {
            parent_id,
            slot,
            consensus_version,
            seed_commit,
            vdf_y_core,
            vdf_y_edge,
            vdf_pi,
            vdf_ell,
            ticket_root,
            txroot_prev,
        })
    }
}

pub fn header_id(header: &Header) -> Hash256 {
    h_tag("header.id", &[
        &header.parent_id,
        &le_bytes::<8>(header.slot as u128),
        &le_bytes::<4>(header.consensus_version as u128),
        &header.seed_commit,
        &header.vdf_y_core,
        &header.vdf_y_edge,
        &le_bytes::<4>(header.vdf_pi.len() as u128),
        &header.vdf_pi,
        &le_bytes::<4>(header.vdf_ell.len() as u128),
        &header.vdf_ell,
        &header.ticket_root,
        &header.txroot_prev,
    ])
}

// ——— Build & Validate ————————————————————————————————————————
#[derive(Debug)]
pub enum BuildErr { /* reserved for future: provider failures, etc. */ }

pub enum ValidateErr {
    BadParentLink,
    BadSlotProgression,
    BeaconInvalid,
    TicketRootMismatch,
    TxRootPrevMismatch,
    VersionMismatch,
}



/// Build Header_s given parent header, beacon fields, and deterministic providers.
pub fn mars_build_header(
    parent: &Header,
    beacon_fields: BeaconFields,
    ticket_roots: &impl TicketRootProvider,
    tx_roots: &impl TxRootProvider,
    consensus_version: u32,
) -> Result<Header, BuildErr> {
    let s = parent.slot + 1;
    let (seed_commit, y_core, y_edge, pi, ell) = beacon_fields;

    let ticket_root = ticket_roots.compute_ticket_root(s);
    let txroot_prev = tx_roots.compute_txroot(parent.slot);

    Ok(Header {
        parent_id: header_id(parent),
        slot: s,
        consensus_version,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: pi,
        vdf_ell: ell,
        ticket_root,
        txroot_prev,
    })
}

/// Validate Header_s strictly by equalities.
#[allow(clippy::too_many_arguments)]
pub fn mars_validate_header(
    h: &Header,
    parent: &Header,
    beacon: &impl BeaconVerifier,
    ticket_roots: &impl TicketRootProvider,
    tx_roots: &impl TxRootProvider,
    expected_consensus_version: u32,
) -> Result<(), ValidateErr> {
    // 1) Parent linkage and slot progression
    if h.parent_id != header_id(parent) { return Err(ValidateErr::BadParentLink); }
    if h.slot != parent.slot + 1 { return Err(ValidateErr::BadSlotProgression); }

    // 2) VDF equalities (Engine 2)
    if !beacon.verify_beacon(
        &h.parent_id, h.slot,
        &h.seed_commit, &h.vdf_y_core, &h.vdf_y_edge,
        &h.vdf_pi, &h.vdf_ell,
    ) { return Err(ValidateErr::BeaconInvalid); }

    // 3) Admission equality (slot s)
    let ticket_root_local = ticket_roots.compute_ticket_root(h.slot);
    if h.ticket_root != ticket_root_local { return Err(ValidateErr::TicketRootMismatch); }

    // 4) Execution equality (slot s-1)
    let txroot_prev_local = tx_roots.compute_txroot(parent.slot);
    if h.txroot_prev != txroot_prev_local { return Err(ValidateErr::TxRootPrevMismatch); }

    // 5) Version equality
    if h.consensus_version != expected_consensus_version { return Err(ValidateErr::VersionMismatch); }

    Ok(())
}

// ——— Public API ————————————————————————————————————————————————

/// Build a header for the given slot and parent.
pub fn build_header(
    parent: &Header,
    beacon_fields: BeaconFields,
    ticket_roots: &impl TicketRootProvider,
    tx_roots: &impl TxRootProvider,
    consensus_version: u32,
) -> Result<Header, BuildErr> {
    mars_build_header(parent, beacon_fields, ticket_roots, tx_roots, consensus_version)
}

/// Validate a header against its parent.
#[allow(clippy::too_many_arguments)]
pub fn validate_header(
    h: &Header,
    parent: &Header,
    beacon: &impl BeaconVerifier,
    ticket_roots: &impl TicketRootProvider,
    tx_roots: &impl TxRootProvider,
    expected_consensus_version: u32,
) -> Result<(), ValidateErr> {
    mars_validate_header(h, parent, beacon, ticket_roots, tx_roots, expected_consensus_version)
}

/// Calculate the canonical ID of a header.
pub fn get_header_id(header: &Header) -> Hash256 {
    header_id(header)
}

#[cfg(test)]
mod tests;