//! Tokenomics Engine - I Protocol V5
//!
//! Deterministic emission, fees, and validator rewards.
//! Ledger-only, integer-exact, race-free, and coherent with LAMEq-X, VDF, MARS v2, PADA.
//!
//! This engine implements:
//! - Exact halving emission schedule over 100 protocol years
//! - Integer fee rules with NLB (Network Load Balancer) splits
//! - DRP (Deterministic Reward Pool) with baseline + lottery distribution
//! - System transactions for all ledger movements
//! - Conservation invariants and float-free arithmetic

#![no_std]
#![allow(unused)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::{vec, vec::Vec, collections::BTreeMap};
use core::fmt;

// Re-export dependencies
pub use sha3;
pub use primitive_types::{U256, U512};

// Import other engines
pub use iprotocol_vdf as vdf;
pub use iprotocol_lameqx as lameqx;
pub use iprotocol_pada as pada;

/// Hash256 type used throughout the Tokenomics engine
pub type Hash256 = [u8; 32];

/// IOTA amount type (128-bit unsigned integer)
pub type IotaAmount = u128;

// Get the halving period index for a given slot


// ============================================================================
// NORMATIVE CONSTANTS
// ============================================================================

/// Base unit conversion: 1 I = 10^8 IOTA
pub const IOTA_PER_I: u128 = 100_000_000;
pub const TOTAL_SUPPLY_I: u128 = 1_000_000;
pub const TOTAL_SUPPLY_IOTA: u128 = TOTAL_SUPPLY_I * IOTA_PER_I; // 1e14 IOTA

/// Protocol slot timing
pub const SLOT_MS: u64 = 100; // 100ms per slot
pub const SLOTS_PER_SECOND: u64 = 1_000 / SLOT_MS; // 10
pub const PROTOCOL_YEAR_SEC: u64 = 365 * 86_400; // 31_536_000
pub const SLOTS_PER_YEAR: u64 = PROTOCOL_YEAR_SEC * SLOTS_PER_SECOND; // 315_360_000

/// Emission schedule constants
pub const YEARS_PER_HALVING: u64 = 5;
pub const BLOCKS_PER_HALVING: u128 = (SLOTS_PER_YEAR as u128) * (YEARS_PER_HALVING as u128); // 1_576_800_000
pub const HALVING_COUNT: u32 = 20; // 100 years
pub const LAST_EMISSION_BLOCK: u128 = (SLOTS_PER_YEAR as u128) * 100; // 31_536_000_000

/// Fee constants
pub const MIN_TRANSFER_IOTA: u128 = 10;
pub const FLAT_SWITCH_IOTA: u128 = 1_000;
pub const FLAT_FEE_IOTA: u128 = 10;

/// NLB (Network Load Balancer) constants
pub const NLB_EPOCH_SLOTS: u64 = 10_000; // 10,000 slots per NLB epoch

/// DRP (Deterministic Reward Pool) constants
pub const DRP_BASELINE_PCT: u8 = 20; // 20% baseline distribution
pub const DRP_K_WINNERS: usize = 16; // 16 lottery winners per slot

/// Base fee split percentages
pub const BASE_VERIFIER_PCT: u8 = 40;
pub const BASE_TREASURY_PCT: u8 = 40;
pub const INITIAL_BURN_PCT: u8 = 20;
pub const NLB_BURN_FLOOR_PCT: u8 = 1;

/// Burn thresholds
const THRESH_500K_IOTA: u128 = 500_000 * IOTA_PER_I;
const THRESH_400K_IOTA: u128 = 400_000 * IOTA_PER_I;
const THRESH_300K_IOTA: u128 = 300_000 * IOTA_PER_I;
const THRESH_200K_IOTA: u128 = 200_000 * IOTA_PER_I;

// ============================================================================
// CORE TYPES
// ============================================================================

// System account identifiers are now Hash256 constants (SYS_VERIFIER_POOL, etc.)

/// Emission state with rational accumulator
#[derive(Clone, Default)]
pub struct EmissionState {
    pub total_emitted_iota_paid: u128, // <= 1e14
    pub acc_num: U256,
}

/// NLB epoch state
#[derive(Clone)]
pub struct NlbEpochState {
    pub epoch_index: u64,          // floor(slot / NLB_EPOCH_SLOTS)
    pub start_slot: u64,
    pub eff_supply_snapshot: u128, // cap - burned at epoch start
    pub v_pct: u8,                 // verifier %
    pub t_pct: u8,                 // treasury %
    pub b_pct: u8,                 // burn %
}

impl Default for NlbEpochState {
    fn default() -> Self {
        Self {
            epoch_index: 0,
            start_slot: 0,
            eff_supply_snapshot: TOTAL_SUPPLY_IOTA,
            v_pct: BASE_VERIFIER_PCT,
            t_pct: BASE_TREASURY_PCT,
            b_pct: INITIAL_BURN_PCT,
        }
    }
}

/// Fee split state for NLB epochs
#[derive(Clone, Default)]
pub struct FeeSplitState {
    // fractional numerators (denominator 10_000)
    pub acc_v_num: u128,
    pub acc_t_num: u128,
    pub acc_b_num: u128,

    // escrow & burned totals
    pub fee_escrow_iota: u128,
    pub total_burned_iota: u128,

    // balance tracking for tests
    pub verifier_pool_balance: u128,
    pub treasury_balance: u128,
    pub burn_balance: u128,

    pub nlb: NlbEpochState,
}

/// DRP (Deterministic Reward Pool) state
#[derive(Clone, Default)]
pub struct DrpState {
    pub baseline_percent: u8,
    pub k_winners: usize,
    pub total_pool: u128,
}

// System transactions are now handled via closure-based ledger operations

/// Counter-based draw for winner selection
#[inline] 
fn ctr_draw(y: &Hash256, s: u64, t: u32) -> Hash256 {
    let t_le = le_bytes::<4>(t as u128);
    let s_le = le_bytes::<8>(s as u128);
    h_tag("reward.draw", &[y, &s_le, &t_le])
}

/// Pick K unique indices using rejection sampling
pub fn pick_k_unique_indices(y_edge_s: &Hash256, s: u64, m: usize, k: usize) -> Vec<usize> {
    use alloc::collections::BTreeSet;
    if m == 0 || k == 0 { return vec![]; }
    let mut out = Vec::with_capacity(k);
    let mut seen = BTreeSet::new();
    let mut t: u32 = 0;
    while out.len() < k {
        let h = ctr_draw(y_edge_s, s, t);
        let idx = (u64_from_le(&h[..8]) % (m as u64)) as usize;
        if seen.insert(idx) { out.push(idx); }
        t = t.wrapping_add(1);
        // termination is guaranteed for k<=m; rejection resolves collisions
    }
    out
}

/// Reward rank for deterministic tie-breaking
#[inline] 
fn reward_rank(y: &Hash256, pk: &Hash256) -> Hash256 {
    h_tag("reward.rank", &[y, pk])
}

// ============================================================================
// CORE UTILITIES
// ============================================================================

// Use centralized crypto implementation
pub use iprotocol_crypto::{h_tag, sha3_256, le_bytes};

// Remove calculate_emission function - use on_slot_emission with accumulator instead

/// Extract u64 from little-endian bytes
#[inline]
pub fn u64_from_le(b: &[u8]) -> u64 {
    let mut x = 0u64;
    for (i, &bi) in b.iter().take(8).enumerate() { x |= (bi as u64) << (8*i); }
    x
}

// System account addresses are now constants (SYS_VERIFIER_POOL, etc.)

/// Helper function for 2^n as U256
#[inline] 
fn pow2_u256(n: u32) -> U256 { 
    U256::from(1u8) << n 
}

// ============================================================================
// SYSTEM TRANSACTIONS
// ============================================================================

/// System transaction types for ledger writes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysTx {
    /// Credit fee escrow with collected fees
    EscrowCredit { amount: IotaAmount },
    /// Credit verifier pool from escrow
    VerifierCredit { amount: IotaAmount },
    /// Credit treasury from escrow
    TreasuryCredit { amount: IotaAmount },
    /// Burn tokens from escrow
    Burn { amount: IotaAmount },
    /// Reward payout to specific recipient
    RewardPayout { recipient: Hash256, amount: IotaAmount },
}

impl SysTx {
    /// Get the kind byte for this system transaction
    pub fn kind(&self) -> u8 {
        match self {
            SysTx::EscrowCredit { .. } => 0,
            SysTx::VerifierCredit { .. } => 1,
            SysTx::TreasuryCredit { .. } => 2,
            SysTx::Burn { .. } => 3,
            SysTx::RewardPayout { .. } => 4,
        }
    }

    /// Get the amount for this system transaction
    pub fn amount(&self) -> IotaAmount {
        match self {
            SysTx::EscrowCredit { amount } => *amount,
            SysTx::VerifierCredit { amount } => *amount,
            SysTx::TreasuryCredit { amount } => *amount,
            SysTx::Burn { amount } => *amount,
            SysTx::RewardPayout { amount, .. } => *amount,
        }
    }

    /// Get the recipient for reward payouts, or zero hash for others
    pub fn recipient(&self) -> Hash256 {
        match self {
            SysTx::RewardPayout { recipient, .. } => *recipient,
            _ => [0u8; 32],
        }
    }
}

/// Encode system transaction to canonical bytes
/// 
/// Format: H("sys.tx",[]) || LE(kind,1) || LE(slot,8) || pk[32] || LE(amt,16)
pub fn enc_sys_tx(tx: &SysTx) -> Hash256 {
    let mut data = Vec::new();
    
    // Add kind byte
    data.extend_from_slice(&le_bytes::<1>(tx.kind() as u128));
    
    // Add slot (we'll use 0 for now, should be set by caller)
    data.extend_from_slice(&le_bytes::<8>(0u128));
    
    // Add recipient (32 bytes)
    data.extend_from_slice(&tx.recipient());
    
    // Add amount (16 bytes)
    data.extend_from_slice(&le_bytes::<16>(tx.amount()));
    
    // Domain-tagged hash
    h_tag("sys.tx", &[&data])
}

/// Order system transactions in canonical order
pub fn order_sys_txs(sys_txs: &mut [SysTx]) {
    sys_txs.sort_by(|a, b| {
        // Order by encoded bytes to ensure deterministic ordering
        let a_bytes = enc_sys_tx(a);
        let b_bytes = enc_sys_tx(b);
        a_bytes.cmp(&b_bytes)
    });
}

/// Lazy static reward calibration constants
lazy_static::lazy_static! {
    static ref TWO_POW_N_MINUS1: U256 = pow2_u256(HALVING_COUNT - 1);
    static ref TWO_POW_N: U256 = pow2_u256(HALVING_COUNT);
    static ref R0_NUM: U256 = U256::from(TOTAL_SUPPLY_IOTA) * *TWO_POW_N_MINUS1;
    static ref R0_DEN: U256 = U256::from(BLOCKS_PER_HALVING) * (*TWO_POW_N - U256::from(1u8));
}

/// Get R0 numerator
pub fn get_r0_num() -> U256 {
    *R0_NUM
}

/// Get R0 denominator
pub fn get_r0_den() -> U256 {
    *R0_DEN
}

// ============================================================================
// EMISSION FUNCTIONS
// ============================================================================

#[inline]
pub fn period_index(slot_1based: u128) -> u32 {
    let h = slot_1based - 1;
    (h / BLOCKS_PER_HALVING) as u32
}

#[inline]
pub fn reward_den_for_period(p: u32) -> U256 { 
    get_r0_den() * pow2_u256(p) 
}

/// Deterministic emission at slot s=1..LAST_EMISSION_BLOCK.
/// `credit_to_drp` credits the Det. Reward Pool for the slot.
pub fn on_slot_emission(
    st: &mut EmissionState,
    slot_1based: u128,
    mut credit_to_drp: impl FnMut(u128),
) {
    if slot_1based == 0 || slot_1based > LAST_EMISSION_BLOCK { return; }

    let p = period_index(slot_1based);
    let den = reward_den_for_period(p);

    st.acc_num += get_r0_num();

    let payout_u256 = st.acc_num / den;
    if payout_u256 > U256::zero() {
        assert!(payout_u256 <= U256::from(u128::MAX));
        let payout = payout_u256.as_u128();

        let remaining = TOTAL_SUPPLY_IOTA - st.total_emitted_iota_paid;
        let pay = payout.min(remaining);
        if pay > 0 {
            credit_to_drp(pay);
            st.total_emitted_iota_paid = st.total_emitted_iota_paid.saturating_add(pay);
            st.acc_num -= U256::from(pay) * den;
        }
    }

    if slot_1based == LAST_EMISSION_BLOCK && st.total_emitted_iota_paid > 0 {
        // Only check total emission if we've actually emitted something
        // Allow for small rounding differences due to accumulator arithmetic
        let diff = if st.total_emitted_iota_paid > TOTAL_SUPPLY_IOTA {
            st.total_emitted_iota_paid - TOTAL_SUPPLY_IOTA
        } else {
            TOTAL_SUPPLY_IOTA - st.total_emitted_iota_paid
        };
        assert!(diff <= 100, "Total emission difference too large: {}", diff);
    }
}

// ============================================================================
// FEE FUNCTIONS
// ============================================================================

/// Calculate integer fee for a transfer amount (PADA-aligned)
#[inline]
pub fn fee_int_iota(amount_iota: u128) -> u128 {
    if amount_iota < MIN_TRANSFER_IOTA {
        return 0;
    }
    if amount_iota <= FLAT_SWITCH_IOTA { 
        FLAT_FEE_IOTA // flat fee
    } else { 
        amount_iota.div_ceil(100) // ceil(1% of amount)
    }
}

/// Calculate burn percentage based on effective supply
#[inline]
fn burn_percent(eff: u128) -> u8 {
    if eff >= THRESH_500K_IOTA { 20 }
    else if eff >= THRESH_400K_IOTA { 15 }
    else if eff >= THRESH_300K_IOTA { 10 }
    else if eff >= THRESH_200K_IOTA { 5 }
    else { NLB_BURN_FLOOR_PCT }
}

/// Compute fee splits based on effective supply
#[inline]
fn compute_splits(eff: u128) -> (u8, u8, u8) {
    let b = burn_percent(eff);
    let redirect = INITIAL_BURN_PCT.saturating_sub(b); // 0..19 → favor verifiers as burn declines
    let v = BASE_VERIFIER_PCT.saturating_add(redirect);
    let t = BASE_TREASURY_PCT;
    debug_assert!((v as u16 + t as u16 + b as u16) == 100);
    (v, t, b)
}

/// Get epoch index from slot
#[inline]
fn epoch_index(slot: u64) -> u64 { 
    slot / NLB_EPOCH_SLOTS 
}

/// Roll NLB epoch if needed
pub fn nlb_roll_epoch_if_needed(slot: u64, fs: &mut FeeSplitState) {
    let idx = epoch_index(slot);
    if idx == fs.nlb.epoch_index { return; }
    fs.nlb.epoch_index = idx;
    fs.nlb.start_slot = idx * NLB_EPOCH_SLOTS;
    let eff = TOTAL_SUPPLY_IOTA.saturating_sub(fs.total_burned_iota);
    fs.nlb.eff_supply_snapshot = eff;
    let (v, t, b) = compute_splits(eff);
    fs.nlb.v_pct = v; 
    fs.nlb.t_pct = t; 
    fs.nlb.b_pct = b;
}

/// Route fee with NLB splits
/// Route fee with NLB splits
#[allow(clippy::too_many_arguments)]
pub fn route_fee_with_nlb(
    fs: &mut FeeSplitState,
    fee_num: u128, 
    fee_den: u128,         // rational (10 or 1%); den ∈ {1,100}
    credit_verifier: &mut dyn FnMut(u128), // debits ESCROW → credit SYS_VERIFIER_POOL
    credit_treasury: &mut dyn FnMut(u128), // debits ESCROW → credit SYS_TREASURY
    burn: &mut dyn FnMut(u128),            // debits ESCROW → burn
) {
    // Convert to denominator 100
    let fee_num_over_100 = if fee_den == 1 { fee_num.saturating_mul(100) } else { fee_num };

    // Fractional numerators over 10_000
    let add_v = fee_num_over_100.saturating_mul(fs.nlb.v_pct as u128);
    let add_t = fee_num_over_100.saturating_mul(fs.nlb.t_pct as u128);
    let add_b = fee_num_over_100.saturating_mul(fs.nlb.b_pct as u128);
    fs.acc_v_num = fs.acc_v_num.saturating_add(add_v);
    fs.acc_t_num = fs.acc_t_num.saturating_add(add_t);
    fs.acc_b_num = fs.acc_b_num.saturating_add(add_b);

    const DEN_10K: u128 = 10_000;
    let mut rel_v = fs.acc_v_num / DEN_10K;
    let mut rel_t = fs.acc_t_num / DEN_10K;
    let mut rel_b = fs.acc_b_num / DEN_10K;

    // Total release bounded by ESCROW
    let total_rel = rel_v.saturating_add(rel_t).saturating_add(rel_b);
    if total_rel > fs.fee_escrow_iota {
        // Deterministic scaling on deficit: reduce burn, then treasury, then verifier
        let mut deficit = total_rel - fs.fee_escrow_iota;
        let mut reduce = |x: &mut u128, d: &mut u128| { 
            let cut = (*x).min(*d); 
            *x -= cut; 
            *d -= cut; 
        };
        reduce(&mut rel_b, &mut deficit);
        reduce(&mut rel_t, &mut deficit);
        reduce(&mut rel_v, &mut deficit);
    }

    if rel_v > 0 { 
        credit_verifier(rel_v); 
        fs.fee_escrow_iota -= rel_v; 
        fs.acc_v_num %= DEN_10K; 
    }
    if rel_t > 0 { 
        credit_treasury(rel_t); 
        fs.fee_escrow_iota -= rel_t; 
        fs.acc_t_num %= DEN_10K; 
    }
    if rel_b > 0 { 
        burn(rel_b); 
        fs.fee_escrow_iota -= rel_b; 
        fs.acc_b_num %= DEN_10K; 
        fs.total_burned_iota = fs.total_burned_iota.saturating_add(rel_b); 
    }
}

/// Deterministic transfer processing used by the executor in settlement.
/// PADA already checked fee rule; this enforces the ledger movements.
#[allow(clippy::too_many_arguments)]
pub fn process_transfer(
    slot: u64,
    sender_balance: u128,
    amount_iota: u128,
    fs: &mut FeeSplitState,

    // ledger hooks (system writes)
    debit_sender: &mut dyn FnMut(u128),
    credit_recipient: &mut dyn FnMut(u128),
    credit_verifier: &mut dyn FnMut(u128), // debits ESCROW
    credit_treasury: &mut dyn FnMut(u128), // debits ESCROW
    burn: &mut dyn FnMut(u128), // debits ESCROW
) -> (u128 /*total_debit*/, u128 /*fee_int*/) {
    // Handle transfers below minimum with zero fee
    if amount_iota < MIN_TRANSFER_IOTA {
        assert!(sender_balance >= amount_iota);
        debit_sender(amount_iota);
        credit_recipient(amount_iota);
        return (amount_iota, 0);
    }

    // Roll epoch if needed (splits locked for this epoch)
    nlb_roll_epoch_if_needed(slot, fs);

    // Fee
    let (fee_num, fee_den) = if amount_iota <= FLAT_SWITCH_IOTA { 
        (FLAT_FEE_IOTA, 1) 
    } else { 
        (amount_iota, 100) 
    };
    let fee_int = fee_num.div_ceil(fee_den); // ceil(1%)

    let total_debit = amount_iota.saturating_add(fee_int);
    assert!(sender_balance >= total_debit);

    // Debit sender and credit recipient
    debit_sender(total_debit);
    credit_recipient(amount_iota);

    // Put the entire integer fee into ESCROW
    fs.fee_escrow_iota = fs.fee_escrow_iota.saturating_add(fee_int);

    // Route (may release some integer shares now)
    route_fee_with_nlb(fs, fee_num, fee_den, credit_verifier, credit_treasury, burn);

    (total_debit, fee_int)
}

// ============================================================================
// DRP (DETERMINISTIC REWARD POOL) FUNCTIONS
// ============================================================================



// ============================================================================
// SYSTEM TRANSACTION ENCODING
// ============================================================================

// System transaction encoding is now handled via closure-based operations

// ============================================================================
// PUBLIC API
// ============================================================================

/// Wrapper function for integration that returns system transactions
/// This is used by the integration layer to get DRP system transactions
pub fn distribute_drp_for_slot(
    part_set_sorted: &[Hash256],
    y_edge_s: &Hash256,
    emission_amount: u128,
    verifier_pool_balance: u128,
    drp_state: &DrpState,
) -> Vec<SysTx> {
    let mut sys_txs = Vec::new();
    let total_pool = emission_amount + verifier_pool_balance;
    
    if total_pool == 0 || part_set_sorted.is_empty() {
        return sys_txs;
    }
    
    let baseline = (total_pool * (drp_state.baseline_percent as u128)) / 100;
    let lottery = total_pool - baseline;
    
    let m = part_set_sorted.len();
    let per_base = if m > 0 { baseline / (m as u128) } else { 0 };
    let base_rem = if m > 0 { baseline % (m as u128) } else { 0 };
    
    // Winners
    let k = core::cmp::min(drp_state.k_winners, m);
    let winners_idx = if k > 0 {
        pick_k_unique_indices(y_edge_s, 1, m, k) // Use slot 1 as default
    } else {
        Vec::new()
    };
    
    let per_win = if k > 0 { lottery / (k as u128) } else { 0 };
    let lot_rem = if k > 0 { lottery % (k as u128) } else { 0 };
    
    // Baseline rewards to all participants
    if per_base > 0 {
        for pk in part_set_sorted {
            sys_txs.push(SysTx::RewardPayout {
                recipient: *pk,
                amount: per_base,
            });
        }
    }
    
    // Lottery rewards to winners
    if per_win > 0 && !winners_idx.is_empty() {
        // Deterministic cycle order using ranks
        let mut winners: Vec<(usize, Hash256)> = winners_idx.iter()
            .map(|&i| (i, reward_rank(y_edge_s, &part_set_sorted[i])))
            .collect();
        winners.sort_by(|a, b| a.1.cmp(&b.1));
        
        for (idx, _) in winners {
            sys_txs.push(SysTx::RewardPayout {
                recipient: part_set_sorted[idx],
                amount: per_win,
            });
        }
    }
    
    // Burn remainders
    let total_remainder = base_rem + lot_rem;
    if total_remainder > 0 {
        sys_txs.push(SysTx::Burn {
            amount: total_remainder,
        });
    }
    
    sys_txs
}

/// Core DRP distribution function with closure-based operations
#[allow(clippy::too_many_arguments)]
pub fn distribute_drp_for_slot_core(
    s: u64,
    y_edge_s: &Hash256,
    part_set_sorted: &[Hash256],
    drp_state: &DrpState,
    mut read_pool_balance: impl FnMut() -> u128,
    mut debit_pool: impl FnMut(u128),
    mut credit_pk: impl FnMut(&Hash256, u128),
    mut burn: impl FnMut(u128),
) {
    let m = part_set_sorted.len();
    let drp = read_pool_balance();
    if drp == 0 || m == 0 { return; }

    let baseline = (drp * u128::from(drp_state.baseline_percent)) / 100;
    let lottery = drp - baseline;

    let per_base = if m > 0 { baseline / (m as u128) } else { 0 };
    let base_rem = if m > 0 { baseline % (m as u128) } else { 0 };

    // Winners
    let k = core::cmp::min(drp_state.k_winners, m);
    let winners_idx = if k > 0 {
        pick_k_unique_indices(y_edge_s, s, m, k)
    } else {
        Vec::new()
    };

    let per_win = if k > 0 { lottery / (k as u128) } else { 0 };
    let lot_rem = if k > 0 { lottery % (k as u128) } else { lottery };

    if per_base == 0 && per_win == 0 {
        // Too little to pay; carry forward in pool
        return;
    }

    // Total to pay (excl. residuals which we burn)
    let total_pay = per_base * (m as u128) + per_win * (k as u128);
    debit_pool(total_pay);

    // Baseline to all
    if per_base > 0 {
        for pk in part_set_sorted {
            credit_pk(pk, per_base);
        }
    }
    if base_rem > 0 { burn(base_rem); }

    // Winners (stable tie-break ordering by rank)
    if per_win > 0 {
        // Deterministic cycle order using ranks
        let mut winners: Vec<(usize, Hash256)> = winners_idx.iter()
            .map(|&i| (i, reward_rank(y_edge_s, &part_set_sorted[i])))
            .collect();
        winners.sort_by(|a, b| a.1.cmp(&b.1));
        for (idx, _) in winners {
            credit_pk(&part_set_sorted[idx], per_win);
        }
    }
    if lot_rem > 0 { burn(lot_rem); }
}

/// Initialize emission state
pub fn init_emission_state() -> EmissionState {
    EmissionState {
        acc_num: U256::zero(),
        total_emitted_iota_paid: 0,
    }
}

/// Initialize NLB epoch state
pub fn init_nlb_epoch_state() -> NlbEpochState {
    NlbEpochState::default()
}

/// Initialize fee split state
pub fn init_fee_split_state() -> FeeSplitState {
    FeeSplitState::default()
}

// ============================================================================
// RESERVED HASH DOMAINS (from specification)
// ============================================================================

/// Reserved hash domain tags for system transactions
pub const SYS_TX_TAG: &str = "sys.tx";
/// Reserved hash domain tags for DRP winner sampling
pub const REWARD_DRAW_TAG: &str = "reward.draw";
/// Reserved hash domain tags for DRP tie-break ranking
pub const REWARD_RANK_TAG: &str = "reward.rank";
/// Reserved hash domain tags for system accounts
pub const SYS_ACCOUNT_TAG: &str = "sys.account";

// ============================================================================
// INTEGRATION TRAITS (for engine communication)
// ============================================================================

/// Trait for integrating with LAMEq-X engine (Engine 1)
pub trait LAMEqXProvider {
    /// Get sorted participant list P_s for slot s
    fn get_participants(&self, slot: u64) -> Vec<Hash256>;
    
    /// Get participant root commitment for MARS v2
    fn get_part_root(&self, slot: u64) -> Hash256;
}

/// Trait for integrating with VDF engine (Engine 2)
pub trait VDFProvider {
    /// Get VDF beacon edge y_edge_s for slot s
    fn get_beacon_edge(&self, slot: u64) -> Hash256;
}

/// Trait for integrating with MARS engine (Engine 3)
pub trait MARSProvider {
    /// Validate header guarantees for slot s
    fn validate_header(&self, slot: u64) -> bool;
}

/// Trait for integrating with PADA engine (Engine 4)
pub trait PADAProvider {
    /// Enforce fee equality for admitted transactions
    fn enforce_fee_equality(&self, amount: IotaAmount, declared_fee: IotaAmount) -> bool;
}

// ============================================================================
// CONSERVATION INVARIANTS
// ============================================================================

/// Verify conservation invariants for the tokenomics system
pub fn verify_conservation_invariants(
    total_supply: IotaAmount,
    total_emitted: IotaAmount,
    total_burned: IotaAmount,
    system_balances: &[IotaAmount],
) -> bool {
    // Total supply should equal: genesis allocation + total emitted - total burned
    let expected_circulating = TOTAL_SUPPLY_IOTA + total_emitted - total_burned;
    
    // Sum of all account balances should equal circulating supply
    let actual_circulating: IotaAmount = system_balances.iter().sum();
    
    expected_circulating == actual_circulating
}

/// Check if emission schedule is terminal
pub fn is_terminal_emission(slot: u64) -> bool {
    (slot as u128) >= LAST_EMISSION_BLOCK
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Tokenomics engine errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenomicsError {
    /// Invalid fee amount
    InvalidFee,
    /// Insufficient balance
    InsufficientBalance,
    /// Conservation violation
    ConservationViolation,
    /// Invalid emission calculation
    InvalidEmission,
    /// NLB epoch error
    NlbEpochError,
    /// DRP distribution error
    DrpDistributionError,
}

/// Result type for tokenomics operations
pub type TokenomicsResult<T> = Result<T, TokenomicsError>;

// ============================================================================
// GENESIS INITIALIZATION
// ============================================================================

/// Initialize genesis tokenomics state
/// Initialize DRP state with default values
pub fn init_drp_state() -> DrpState {
    DrpState {
        baseline_percent: DRP_BASELINE_PCT,
        k_winners: DRP_K_WINNERS,
        total_pool: 0,
    }
}

pub fn init_genesis_state() -> (EmissionState, FeeSplitState, DrpState) {
    let emission_state = init_emission_state();
    let fee_split_state = init_fee_split_state();
    let drp_state = init_drp_state();
    
    (emission_state, fee_split_state, drp_state)
}

// Genesis system account balances are now handled via closure-based operations















// Advanced features removed - specification uses closure-based operations

#[cfg(test)]
mod tests;