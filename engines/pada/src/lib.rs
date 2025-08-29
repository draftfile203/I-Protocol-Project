//! Engine 4: PADA (Protocol Admission = Deterministic Admission)
//!
//! Byte-precise, production-grade implementation coherent with
//! LAMEq-X (E1), VDF (E2), and MARS (E3).
//!
//! Provides deterministic transaction admission with finality within slot,
//! canonical ordering, and Merkle commitment for MARS validation.

#![no_std]
#![allow(unused)]

#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::{BTreeMap, BTreeSet};

// Re-export dependencies
pub use sha3;
pub use iprotocol_crypto::{Hash256, PK, Sig, h_tag, le_bytes, merkle_leaf, merkle_node, merkle_root as crypto_merkle_root, sha3_256, verify_sig};

// ——— Additional Types ———————————————————————————————————————————

/// Compute Merkle root from leaf payloads using crypto module
/// 
/// # Panics
/// 
/// Panics if the internal level vector is empty during tree construction
#[must_use]
pub fn merkle_root(leaves_payload: &[Vec<u8>]) -> Hash256 {
    crypto_merkle_root(leaves_payload)
}

// ——— Tokenomics constants ————————————————————————————————————
pub const MIN_TX_IOTA:       u128 = 10;
pub const FLAT_SWITCH_IOTA:  u128 = 1_000;  // ≤1000 => flat fee
pub const FLAT_FEE_IOTA:     u128 = 10;     // flat fee
pub const PCT_DEN:           u128 = 100;    // 1%

/// Calculate internal fee in IOTA for a given amount
/// 
/// # Panics
/// 
/// Panics if `amount_iota` is less than `MIN_TX_IOTA`
#[inline]
#[must_use]
pub fn fee_int_iota(amount_iota: u128) -> u128 {
    assert!(amount_iota >= MIN_TX_IOTA);
    if amount_iota <= FLAT_SWITCH_IOTA { FLAT_FEE_IOTA }
    else { amount_iota.div_ceil(PCT_DEN) }  // ceil(1% of amount)
}

// ——— Core PADA Functions ————————————————————————————————————————

// ——— Canonical admission function (single tx) ———————————————
pub fn pada_try_admit_and_finalize(
    tx: &TxBodyV1,
    sig: &Sig,
    s_now: u64,
    y_prev: &Hash256,      // y_{s-1} = parent.vdf_y_edge
    st: &mut PadaState,
) -> AdmitResult {
    // 1) Signature
    let msg = h_tag("tx.sig", &[&canonical_tx_bytes(tx)]);
    if !verify_sig(&tx.sender, &msg, sig) {
        return AdmitResult::Rejected(AdmitErr::BadSig);
    }

    // 2) Slot & beacon binding
    if tx.s_bind != s_now             { return AdmitResult::Rejected(AdmitErr::WrongSlot); }
    if tx.y_bind != *y_prev           { return AdmitResult::Rejected(AdmitErr::WrongBeacon); }

    // 3) Nonce
    if tx.nonce != st.nonce_of(&tx.sender) {
        return AdmitResult::Rejected(AdmitErr::NonceMismatch);
    }

    // 4) Amount & fee rule (integer-exact)
    if tx.amount_iota < MIN_TX_IOTA   { return AdmitResult::Rejected(AdmitErr::BelowMinAmount); }
    if tx.fee_iota != fee_int_iota(tx.amount_iota) {
        return AdmitResult::Rejected(AdmitErr::FeeMismatch);
    }

    // 5) Funds & reservation
    let total = tx.amount_iota.saturating_add(tx.fee_iota);
    if st.spendable_of(&tx.sender) < total {
        return AdmitResult::Rejected(AdmitErr::InsufficientFunds);
    }

    // Update spendable/reserved balances with zero-balance cleanup
    let new_spendable = st.spendable_of(&tx.sender).saturating_sub(total);
    if new_spendable == 0 {
        st.spendable_iota.remove(&tx.sender);
    } else {
        st.spendable_iota.insert(tx.sender, new_spendable);
    }
    *st.reserved_iota.entry(tx.sender).or_insert(0)  += total;
    *st.next_nonce.entry(tx.sender).or_insert(0)     += 1;

    // 6) Deterministic execution slot (same slot)
    let xid   = txid(tx);
    let s_exec = s_now;

    // 7) Emit TicketRecord
    let rec = TicketRecord {
        ticket_id:   h_tag("ticket.id", &[&xid, &le_bytes::<8>(u128::from(s_now))]),
        txid:        xid,
        sender:      tx.sender,
        nonce:       tx.nonce,
        amount_iota: tx.amount_iota,
        fee_iota:    tx.fee_iota,
        s_admit:     s_now,
        s_exec,
        commit_hash: tx_commit(tx),
    };

    st.admitted_by_slot.entry(s_now).or_default().push(rec.clone());
    st.tickets_by_txid.insert(rec.txid, rec.clone());

    AdmitResult::Finalized(rec)
}

// ——— Canonical per-slot processing (deterministic order) ——————
//
// Given a candidate set U_s (unique by txid), sorted by txid ascending,
// attempt admission for each under evolving state; return the list of
// successfully admitted TicketRecords for slot s.
//
pub fn pada_admit_slot_canonical(
    s_now: u64,
    y_prev: &Hash256,
    candidates_sorted: &[(TxBodyV1, Sig)], // sorted by txid asc
    st: &mut PadaState,
) -> Vec<TicketRecord> {
    // Build unique candidate set by txid and sort ascending by txid
    let mut uniq: CandidateMap = alloc::collections::BTreeMap::new();
    for (tx, sig) in candidates_sorted {
        let xid = txid(tx);
        // Keep first occurrence deterministically
        uniq.entry(xid).or_insert_with(|| (tx.clone(), *sig));
    }

    let mut out = Vec::new();
    for (_xid, (tx, sig)) in uniq {
        match pada_try_admit_and_finalize(&tx, &sig, s_now, y_prev, st) {
            AdmitResult::Finalized(rec) => out.push(rec),
            AdmitResult::Rejected(_)    => { /* ignore for this slot */ }
        }
    }
    out
}

// ——— Build per-slot ticket_root (leaves + root) ——————————————
 type TicketRootResult = (Vec<Vec<u8>>, Hash256);
 
// Simplify complex candidate map type used during admission
type CandidateMap = alloc::collections::BTreeMap<Hash256, (TxBodyV1, Sig)>;

#[allow(clippy::type_complexity)]
 pub fn pada_build_ticket_root_for_slot(s: u64, st: &PadaState) -> TicketRootResult {
     let mut l = st.admitted_by_slot.get(&s).cloned().unwrap_or_default();
     if l.is_empty() {
         // Tagged hash for empty slot, bound to slot index
         let root = h_tag("PADA/empty_slot", &[&le_bytes::<8>(u128::from(s))]);
         return (Vec::new(), root);
     }
     // Canonical order: ascending txid (raw bytes)
     l.sort_by(|a, b| a.txid.cmp(&b.txid));
     let leaves: Vec<Vec<u8>> = l.iter().map(enc_ticket_leaf).collect();
     let root = merkle_root(&leaves);
     (leaves, root)
 }

// ——— Access list & canonical encoding ————————————————————————
#[derive(Clone, Default)]
pub struct AccessList {
    pub read_accounts: Vec<PK>,
    pub write_accounts: Vec<PK>,
}

fn sort_dedup(mut v: Vec<PK>) -> Vec<PK> { v.sort_unstable(); v.dedup(); v }

#[must_use]
pub fn encode_access(a: &AccessList) -> Vec<u8> {
    let r = sort_dedup(a.read_accounts.clone());
    let w = sort_dedup(a.write_accounts.clone());
    let mut out = Vec::new();
    out.extend_from_slice(&h_tag("tx.access", &[]));
    out.extend_from_slice(&le_bytes::<4>(u128::try_from(r.len()).unwrap_or(0)));
    for pk in &r { out.extend_from_slice(pk); }
    out.extend_from_slice(&le_bytes::<4>(u128::try_from(w.len()).unwrap_or(0)));
    for pk in &w { out.extend_from_slice(pk); }
    out
}

// ——— Transaction body, canonical bytes, IDs ————————————————
#[derive(Clone)]
pub struct TxBodyV1 {
    pub sender: PK,
    pub recipient: PK,
    pub nonce: u64,
    pub amount_iota: u128,
    pub fee_iota: u128,
    pub s_bind: u64,
    pub y_bind: Hash256,
    pub access: AccessList,
    pub memo: Vec<u8>,
}

#[must_use]
pub fn canonical_tx_bytes(tx: &TxBodyV1) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h_tag("tx.body.v1", &[]));
    out.extend_from_slice(&tx.sender);
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&le_bytes::<8>(u128::from(tx.nonce)));
    out.extend_from_slice(&le_bytes::<16>(tx.amount_iota));
    out.extend_from_slice(&le_bytes::<16>(tx.fee_iota));
    out.extend_from_slice(&le_bytes::<8>(u128::from(tx.s_bind)));
    out.extend_from_slice(&tx.y_bind);
    out.extend_from_slice(&encode_access(&tx.access));
    out.extend_from_slice(&le_bytes::<4>(u128::try_from(tx.memo.len()).unwrap_or(0)));
    out.extend_from_slice(&tx.memo);
    out
}

#[must_use]
pub fn txid(tx: &TxBodyV1) -> Hash256 {
    h_tag("tx.id", &[&canonical_tx_bytes(tx)])
}

#[must_use]
pub fn tx_commit(tx: &TxBodyV1) -> Hash256 {
    h_tag("tx.commit", &[&canonical_tx_bytes(tx)])
}

// ——— TicketRecord & canonical leaf encoding ————————————————
#[derive(Clone)]
pub struct TicketRecord {
    pub ticket_id:   Hash256,
    pub txid:        Hash256,
    pub sender:      PK,
    pub nonce:       u64,
    pub amount_iota: u128,
    pub fee_iota:    u128,
    pub s_admit:     u64,
    pub s_exec:      u64,      // == s_admit
    pub commit_hash: Hash256,
}

#[must_use]
pub fn enc_ticket_leaf(t: &TicketRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h_tag("ticket.leaf", &[]));
    out.extend_from_slice(&t.ticket_id);
    out.extend_from_slice(&t.txid);
    out.extend_from_slice(&t.sender);
    out.extend_from_slice(&le_bytes::<8>(u128::from(t.nonce)));
    out.extend_from_slice(&le_bytes::<16>(t.amount_iota));
    out.extend_from_slice(&le_bytes::<16>(t.fee_iota));
    out.extend_from_slice(&le_bytes::<8>(u128::from(t.s_admit)));
    out.extend_from_slice(&le_bytes::<8>(u128::from(t.s_exec)));
    out.extend_from_slice(&t.commit_hash);
    out
}

// ——— PADA state (reference in-memory model) ————————————————
#[derive(Default)]
pub struct PadaState {
    // balances
    pub spendable_iota: BTreeMap<PK, u128>,
    pub reserved_iota:  BTreeMap<PK, u128>,
    pub next_nonce:     BTreeMap<PK, u64>,

    // per-slot admission artifacts
    pub admitted_by_slot: BTreeMap<u64, Vec<TicketRecord>>, // s -> TicketRecords
    pub tickets_by_txid:  BTreeMap<Hash256, TicketRecord>,  // txid -> record
}

impl PadaState {
    #[must_use]
    pub fn spendable_of(&self, pk: &PK) -> u128 { *self.spendable_iota.get(pk).unwrap_or(&0) }
    #[must_use]
    pub fn reserved_of(&self,  pk: &PK) -> u128 { *self.reserved_iota .get(pk).unwrap_or(&0) }
    #[must_use]
    pub fn nonce_of(&self,     pk: &PK) -> u64  { *self.next_nonce   .get(pk).unwrap_or(&0) }
}

// ——— Admission result types ————————————————————————————————
#[derive(Debug)]
pub enum AdmitErr {
    BadSig,
    WrongSlot,
    WrongBeacon,
    NonceMismatch,
    BelowMinAmount,
    FeeMismatch,
    InsufficientFunds,
}

pub enum AdmitResult {
    Finalized(TicketRecord), // admission success
    Rejected(AdmitErr),
}

// ——— Public API ————————————————————————————————————————————————

/// Public interface for single transaction admission
pub fn admit_transaction(
    tx: &TxBodyV1,
    sig: &Sig,
    s_now: u64,
    y_prev: &Hash256,
    state: &mut PadaState,
) -> AdmitResult {
    pada_try_admit_and_finalize(tx, sig, s_now, y_prev, state)
}

/// Public interface for batch transaction admission
pub fn admit_transactions_for_slot(
    s_now: u64,
    y_prev: &Hash256,
    candidates_sorted: &[(TxBodyV1, Sig)],
    state: &mut PadaState,
) -> Vec<TicketRecord> {
    pada_admit_slot_canonical(s_now, y_prev, candidates_sorted, state)
}

/// Public interface for ticket root generation
#[must_use]
pub fn get_ticket_root_for_slot(
    s: u64,
    state: &PadaState,
) -> Hash256 {
    let (_, root) = pada_build_ticket_root_for_slot(s, state);
    root
}

/// Public interface for getting admitted tickets for a slot
#[must_use]
pub fn get_admitted_tickets_for_slot(
    s: u64,
    state: &PadaState,
) -> Vec<TicketRecord> {
    state.admitted_by_slot.get(&s).cloned().unwrap_or_default()
}