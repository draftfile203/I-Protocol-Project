//! Tests cover transaction admission, fee calculation, state management,
//! canonical encoding, Merkle operations, and edge cases.

use super::*;
use alloc::vec;



// ——— Test Helpers ————————————————————————————————————————————

/// Generate deterministic test data
fn test_pk(seed: u8) -> PK {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    seed_bytes[31] = seed.wrapping_mul(17);
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();
    verifying_key.to_bytes()
}

fn test_hash(seed: u8) -> Hash256 {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed.wrapping_mul(23);
    hash
}

fn test_sig(seed: u8) -> Sig {
    // This function should not be used for real signature verification
    // Use test_sign_tx instead for proper signatures
    let mut sig = [0u8; 64];
    sig[0] = seed;
    sig[63] = seed.wrapping_mul(31);
    sig
}

fn test_sign_tx(tx: &TxBodyV1, sender_seed: u8) -> Sig {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = sender_seed;
    seed_bytes[31] = sender_seed.wrapping_mul(17);
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    
    let body = canonical_tx_bytes(tx);
    let msg = h_tag("tx.sig", &[&body]);
    let signature: Signature = signing_key.sign(&msg);
    signature.to_bytes()
}

/// Create a test transaction with proper signature
fn create_signed_test_tx(sender_seed: u8, recipient_seed: u8, nonce: u64, amount: u128, slot: u64) -> (TxBodyV1, Sig) {
    let tx = create_test_tx(sender_seed, recipient_seed, nonce, amount, slot);
    let sig = test_sign_tx(&tx, sender_seed);
    (tx, sig)
}

fn create_test_tx(sender_seed: u8, recipient_seed: u8, nonce: u64, amount: u128, slot: u64) -> TxBodyV1 {
    TxBodyV1 {
        sender: test_pk(sender_seed),
        recipient: test_pk(recipient_seed),
        nonce,
        amount_iota: amount,
        fee_iota: fee_int_iota(amount),
        s_bind: slot,
        y_bind: test_hash((slot % 256) as u8),
        access: AccessList::default(),
        memo: vec![],
    }
}

fn setup_test_state() -> PadaState {
    let mut state = PadaState::default();
    // Give some accounts initial balances
    state.spendable_iota.insert(test_pk(1), 10000);
    state.spendable_iota.insert(test_pk(2), 5000);
    state.spendable_iota.insert(test_pk(3), 1000);
    state
}

/*
// ——— Basic Functionality Tests ——————————————————————————————

fn test_le_bytes_encoding() {
    assert_eq!(le_bytes::<4>(0u128), [0, 0, 0, 0]);
    assert_eq!(le_bytes::<4>(1u128), [1, 0, 0, 0]);
    assert_eq!(le_bytes::<4>(256u128), [0, 1, 0, 0]);
    assert_eq!(le_bytes::<8>(0xDEAD_BEEF_u128), [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);
}

fn test_sha3_256_deterministic() {
    let input1 = b"test";
    let input2 = b"test";
    let input3 = b"different";
    
    assert_eq!(sha3_256(input1), sha3_256(input2));
    assert_ne!(sha3_256(input1), sha3_256(input3));
}

fn test_h_tag_domain_separation() {
    let data = b"same_data";
    let tag1 = h_tag("domain1", &[data]);
    let tag2 = h_tag("domain2", &[data]);
    let tag3 = h_tag("domain1", &[data]);
    
    assert_ne!(tag1, tag2); // Different domains should produce different hashes
    assert_eq!(tag1, tag3); // Same domain and data should be deterministic
}

/// Merkle root/leaf/node operations should be deterministic and consistent.
/// # Panics
/// Panics if computed roots or nodes do not match expected values.
fn test_merkle_operations() {
    let leaf1 = vec![1, 2, 3];
    let leaf2 = vec![4, 5, 6];
    let leaf3 = vec![7, 8, 9];
    
    // Test single leaf
    let root1 = merkle_root(&[leaf1.clone()]);
    assert_eq!(root1, merkle_leaf(&leaf1));
    
    // Test multiple leaves
    let root2 = merkle_root(&[leaf1.clone(), leaf2.clone()]);
    let expected = merkle_node(&merkle_leaf(&leaf1), &merkle_leaf(&leaf2));
    assert_eq!(root2, expected);
    
    // Test determinism
    let root3 = merkle_root(&[leaf1.clone(), leaf2.clone(), leaf3.clone()]);
    let root4 = merkle_root(&[leaf1, leaf2, leaf3]);
    assert_eq!(root3, root4);
}

// ——— Fee Calculation Tests ———————————————————————————————————

/// Fee calculation should match flat fee up to threshold and percentage afterward.
/// # Panics
/// Panics if fee values for representative inputs differ from expected constants or calculations.
fn test_fee_calculation() {
    // Below minimum should panic
    assert_eq!(fee_int_iota(MIN_TX_IOTA), FLAT_FEE_IOTA);
    
    // Flat fee range
    assert_eq!(fee_int_iota(100), FLAT_FEE_IOTA);
    assert_eq!(fee_int_iota(FLAT_SWITCH_IOTA), FLAT_FEE_IOTA);
    
    // Percentage fee range
    assert_eq!(fee_int_iota(1001), 11); // ceil(1001/100) = 11
    assert_eq!(fee_int_iota(10000), 100); // 1% of 10000
    assert_eq!(fee_int_iota(9999), 100); // ceil(9999/100) = 100
}

fn test_fee_calculation_below_minimum() {
    fee_int_iota(MIN_TX_IOTA - 1);
}

// ——— Access List Tests ———————————————————————————————————————

/// Access list encoding should be domain-tagged and deterministic.
/// # Panics
/// Panics if the domain tag is missing or if two encodings of the same access list differ.
fn test_access_list_encoding() {
    let access = AccessList {
        read_accounts: vec![test_pk(1), test_pk(2)],
        write_accounts: vec![test_pk(3)],
    };
    
    let encoded = encode_access(&access);
    
    // Should start with domain tag
    assert!(encoded.starts_with(&h_tag("tx.access", &[])));
    
    // Should be deterministic
    let encoded2 = encode_access(&access);
    assert_eq!(encoded, encoded2);
}

/// Access list encoding should ignore duplicate entries by design of canonicalization.
/// # Panics
/// Panics if encoding with duplicates does not match encoding of a de-duplicated access list.
fn test_access_list_deduplication() {
    let access = AccessList {
        read_accounts: vec![test_pk(1), test_pk(1), test_pk(2)],
        write_accounts: vec![test_pk(3), test_pk(3)],
    };
    
    let encoded = encode_access(&access);
    
    // Create expected without duplicates
    let mut expected_access = AccessList {
        read_accounts: vec![test_pk(1), test_pk(2)],
        write_accounts: vec![test_pk(3)],
    };
    let expected_encoded = encode_access(&expected_access);
    
    assert_eq!(encoded, expected_encoded);
}

// ——— Transaction Encoding Tests ——————————————————————————————

/// Canonical transaction bytes encoding should be deterministic and domain-tagged.
/// # Panics
/// Panics if two encodings of the same transaction differ or if the domain tag is missing.
fn test_canonical_tx_bytes() {
    let tx = create_test_tx(1, 2, 0, 1000, 100);
    let bytes1 = canonical_tx_bytes(&tx);
    let bytes2 = canonical_tx_bytes(&tx);
    
    // Should be deterministic
    assert_eq!(bytes1, bytes2);
    
    // Should start with domain tag
    assert!(bytes1.starts_with(&h_tag("tx.body.v1", &[])));
}

/// `TxID` computation should be deterministic for the same transaction data.
/// # Panics
/// Panics if two invocations of `txid` for the same transaction produce different results.
fn test_txid_deterministic() {
    let tx = create_test_tx(1, 2, 0, 1000, 100);
    let id1 = txid(&tx);
    let id2 = txid(&tx);
    
    assert_eq!(id1, id2);
}

/// `TxID` should change when any transaction field that contributes to the hash changes.
/// # Panics
/// Panics if different transactions (nonce or sender changed) produce identical txids.
fn test_txid_uniqueness() {
    let tx1 = create_test_tx(1, 2, 0, 1000, 100);
    let tx2 = create_test_tx(1, 2, 1, 1000, 100); // Different nonce
    let tx3 = create_test_tx(2, 2, 0, 1000, 100); // Different sender
    
    let id1 = txid(&tx1);
    let id2 = txid(&tx2);
    let id3 = txid(&tx3);
    
    assert_ne!(id1, id2);
    assert_ne!(id1, id3);
    assert_ne!(id2, id3);
}

/// Commitment hash should be deterministic and distinct from the transaction id.
/// # Panics
/// Panics if two invocations of `tx_commit` for the same transaction differ or if the commit equals the txid.
fn test_tx_commit() {
    let tx = create_test_tx(1, 2, 0, 1000, 100);
    let commit1 = tx_commit(&tx);
    let commit2 = tx_commit(&tx);
    
    assert_eq!(commit1, commit2);
    
    // Commit should be different from txid
    assert_ne!(commit1, txid(&tx));
}

// ——— Ticket Record Tests ——————————————————————————————————————

/// Ticket leaf encoding should be deterministic and domain-tagged.
/// # Panics
/// Panics if two encodings of the same ticket differ or if the domain tag is missing.
fn test_ticket_leaf_encoding() {
    let ticket = TicketRecord {
        ticket_id: test_hash(1),
        txid: test_hash(2),
        sender: test_pk(1),
        nonce: 42,
        amount_iota: 1000,
        fee_iota: 10,
        s_admit: 100,
        s_exec: 100,
        commit_hash: test_hash(3),
    };
    
    let encoded1 = enc_ticket_leaf(&ticket);
    let encoded2 = enc_ticket_leaf(&ticket);
    
    // Should be deterministic
    assert_eq!(encoded1, encoded2);
    
    // Should start with domain tag
    assert!(encoded1.starts_with(&h_tag("ticket.leaf", &[])));
}

// ——— State Management Tests ———————————————————————————————————

/// Basic accessors on `PadaState` should reflect initial setup state.
/// # Panics
/// Panics if state accessors return unexpected values.
fn test_pada_state_accessors() {
    let state = setup_test_state();
    
    assert_eq!(state.spendable_of(&test_pk(1)), 10000);
    assert_eq!(state.spendable_of(&test_pk(99)), 0); // Non-existent
    
    assert_eq!(state.reserved_of(&test_pk(1)), 0);
    assert_eq!(state.nonce_of(&test_pk(1)), 0);
}

// ——— Transaction Admission Tests ——————————————————————————————

/// Successful admission should finalize and reflect correct ticket fields and state updates.
/// # Panics
/// Panics if admission fails or if ticket/state fields do not match expectations.
fn test_successful_admission() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(ticket) => {
            assert_eq!(ticket.sender, tx.sender);
            assert_eq!(ticket.nonce, tx.nonce);
            assert_eq!(ticket.amount_iota, tx.amount_iota);
            assert_eq!(ticket.s_admit, 100);
            assert_eq!(ticket.s_exec, 100);
        }
        AdmitResult::Rejected(_) => panic!("Expected successful admission"),
    }
    
    // Check state updates
    let total_cost = tx.amount_iota + tx.fee_iota;
    assert_eq!(state.spendable_of(&tx.sender), 10000 - total_cost);
    assert_eq!(state.reserved_of(&tx.sender), total_cost);
    assert_eq!(state.nonce_of(&tx.sender), 1);
}

/// Admission should reject transactions for the wrong slot.
/// # Panics
/// Panics if a transaction for a mismatched slot is not rejected.
#[test]
fn test_admission_wrong_slot() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let beacon = test_hash(101);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 101, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::WrongSlot) => {},
        _ => panic!("Expected WrongSlot error"),
    }
}

/// Admission should reject transactions signed against the wrong beacon.
/// # Panics
/// Panics if a transaction with the wrong beacon is not rejected.
#[test]
fn test_admission_wrong_beacon() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let wrong_beacon = test_hash(99);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &wrong_beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::WrongBeacon) => {},
        _ => panic!("Expected WrongBeacon error"),
    }
}

/// Admission should reject transactions whose nonce does not match the tracked sender nonce.
/// # Panics
/// Panics if a transaction with a mismatched nonce is not rejected.
#[test]
fn test_admission_nonce_mismatch() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 5, 1000, 100); // Wrong nonce
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::NonceMismatch) => {},
        _ => panic!("Expected NonceMismatch error"),
    }
}

/// Admission should reject transactions with below-minimum amount.
/// # Panics
/// Panics if a below-minimum transaction is not rejected.
#[test]
fn test_admission_below_min_amount() {
    let mut state = setup_test_state();
    // Create transaction manually to avoid fee calculation panic
    let tx = TxBodyV1 {
        sender: test_pk(1),
        recipient: test_pk(2),
        nonce: 0,
        amount_iota: MIN_TX_IOTA - 1,
        fee_iota: FLAT_FEE_IOTA,
        s_bind: 100,
        y_bind: test_hash(100),
        access: AccessList::default(),
        memo: vec![],
    };
    let sig = test_sign_tx(&tx, 1);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::BelowMinAmount) => {},
        _ => panic!("Expected BelowMinAmount error"),
    }
}

/// Admission should reject transactions with fee mismatch.
/// # Panics
/// Panics if a transaction with incorrect fee is not rejected.
#[test]
fn test_admission_fee_mismatch() {
    let mut state = setup_test_state();
    let mut tx = create_test_tx(1, 2, 0, 1000, 100);
    tx.fee_iota = 5; // Wrong fee
    let sig = test_sign_tx(&tx, 1);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::FeeMismatch) => {},
        _ => panic!("Expected FeeMismatch error"),
    }
}

/// Admission should reject transactions when funds are insufficient.
/// # Panics
/// Panics if an overdrawn transaction is not rejected.
#[test]
fn test_admission_insufficient_funds() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 20000, 100); // More than available
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::InsufficientFunds) => {},
        _ => panic!("Expected InsufficientFunds error"),
    }
}

// ——— Batch Admission Tests ————————————————————————————————————

/// Canonical ordering should sort admitted transactions by txid.
/// # Panics
/// Panics if the number of admitted transactions or their order does not match expectations.
#[test]
fn test_batch_admission_canonical_ordering() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(2, 1, 0, 100, 100),
        create_signed_test_tx(1, 2, 0, 200, 100),
        create_signed_test_tx(3, 1, 0, 150, 100), // Use different sender to avoid nonce conflicts
    ];
    
    let admitted = pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    // Should admit all valid transactions (sorted by txid)
    assert_eq!(admitted.len(), 3);
    
    // Verify transactions are sorted by txid
    let mut txids: Vec<_> = admitted.iter().map(|t| t.txid).collect();
    let mut sorted_txids = txids.clone();
    sorted_txids.sort_unstable();
    assert_eq!(txids, sorted_txids, "Transactions should be sorted by txid");
}

/// Batch admission should admit only valid transactions and reject invalid ones.
/// # Panics
/// Panics if the number or order of admitted transactions does not match expectations.
#[test]
fn test_batch_admission_with_rejections() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100), // Valid
        create_signed_test_tx(1, 2, 5, 200, 100), // Wrong nonce
        create_signed_test_tx(2, 1, 0, 150, 100), // Valid
    ];
    
    let admitted = pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    // Should only admit valid transactions
    assert_eq!(admitted.len(), 2);
    assert_eq!(admitted[0].nonce, 0);
    assert_eq!(admitted[1].nonce, 0);
}

// ——— Ticket Root Generation Tests —————————————————————————————

/// Ticket root for an empty slot should match the tagged hash convention.
/// # Panics
/// Panics if the computed root differs from the expected tagged hash.
#[test]
fn test_ticket_root_empty_slot() {
    let state = PadaState::default();
    let (_, root) = pada_build_ticket_root_for_slot(100, &state);
    
    // Should return tagged hash for empty slot
    let expected = h_tag("PADA/empty_slot", &[&le_bytes::<8>(100u128)]);
    assert_eq!(root, expected);
}

/// Ticket root should be the Merkle root over ticket leaves when tickets exist.
/// # Panics
/// Panics if the computed root does not match the Merkle root of the leaves.
#[test]
fn test_ticket_root_with_tickets() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let tx1 = create_test_tx(1, 2, 0, 100, 100);
    let tx2 = create_test_tx(2, 1, 0, 200, 100);
    let candidates = vec![
        (tx1.clone(), test_sign_tx(&tx1, 1)),
        (tx2.clone(), test_sign_tx(&tx2, 2)),
    ];
    
    let admitted = pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    let (_, root1) = pada_build_ticket_root_for_slot(100, &state);
    
    // Should compute Merkle root of ticket leaves
    let leaves: Vec<Vec<u8>> = admitted.iter().map(enc_ticket_leaf).collect();
    let expected = merkle_root(&leaves);
    assert_eq!(root1, expected);
}

/// Building the ticket root twice without state changes must be deterministic.
/// # Panics
/// Panics if the two computed roots differ.
#[test]
fn test_ticket_root_deterministic() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
    ];
    
    pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    let (_, root1) = pada_build_ticket_root_for_slot(100, &state);
    let (_, root2) = pada_build_ticket_root_for_slot(100, &state);
    
    assert_eq!(root1, root2);
}

// ——— Public API Tests —————————————————————————————————————————

/// Public API admission should finalize a valid transaction.
/// # Panics
/// Panics if a well-formed transaction is rejected by the public API.
#[test]
fn test_public_api_admit_transaction() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let beacon = test_hash(100);
    
    let result = admit_transaction(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(_) => {},
        AdmitResult::Rejected(_) => panic!("Expected successful admission"),
    }
}

/// Batch admission should admit valid candidates and return their count.
/// # Panics
/// Panics if batch admission returns an unexpected number of admitted transactions.
#[test]
fn test_public_api_admit_transactions_for_slot() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
        create_signed_test_tx(2, 1, 0, 200, 100),
    ];
    
    let admitted = admit_transactions_for_slot(100, &beacon, &candidates, &mut state);
    assert_eq!(admitted.len(), 2);
}

/// Public API should return a non-zero ticket root for a non-empty slot.
/// # Panics
/// Panics if the returned root is the zero hash.
#[test]
fn test_public_api_get_ticket_root_for_slot() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
    ];
    
    admit_transactions_for_slot(100, &beacon, &candidates, &mut state);
    let root = get_ticket_root_for_slot(100, &state);
    
    // Should be non-zero (not empty slot)
    assert_ne!(root, [0u8; 32]);
}

// ——— Edge Cases and Error Conditions ——————————————————————————

/// After spending exact balance (amount + fee), sender should have no spendable balance.
/// # Panics
/// Panics if the sender's spendable balance is not removed or if admission fails.
#[test]
fn test_zero_balance_after_transaction() {
    let mut state = PadaState::default();
    let exact_amount = 1000u128;
    let fee = fee_int_iota(exact_amount);
    let total = exact_amount + fee;
    
    // Set exact balance
    state.spendable_iota.insert(test_pk(1), total);
    
    let (tx, sig) = create_signed_test_tx(1, 2, 0, exact_amount, 100);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(_) => {
            // Balance should be removed (not set to 0)
            assert!(!state.spendable_iota.contains_key(&test_pk(1)));
            assert_eq!(state.reserved_of(&test_pk(1)), total);
        }
        AdmitResult::Rejected(_) => panic!("Expected successful admission"),
    }
}

/// Admission should support very large amounts within u128 without overflow issues.
/// # Panics
/// Panics if a large, but valid, transaction is rejected.
#[test]
fn test_large_amounts() {
    let mut state = PadaState::default();
    let large_amount = u128::MAX / 2;
    state.spendable_iota.insert(test_pk(1), u128::MAX);
    
    let (tx, sig) = create_signed_test_tx(1, 2, 0, large_amount, 100);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(_) => {},
        AdmitResult::Rejected(_) => panic!("Expected successful admission with large amounts"),
    }
}

/// Nonces must increase sequentially for a given sender across admitted transactions.
/// # Panics
/// Panics if a sequentially valid transaction is rejected or if the tracked nonce does not increment as expected.
#[test]
fn test_sequential_nonces() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    // Submit transactions with sequential nonces
    for nonce in 0..5 {
        let (tx, sig) = create_signed_test_tx(1, 2, nonce, 100, 100);
        
        let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
        match result {
            AdmitResult::Finalized(_) => {},
            AdmitResult::Rejected(err) => panic!("Transaction {} rejected: {:?}", nonce, err),
        }
        
        assert_eq!(state.nonce_of(&test_pk(1)), nonce + 1);
    }
}

// ——— Mathematical Properties Tests ————————————————————————————

/// Fee function monotonicity properties.
/// # Panics
/// Panics if increasing the amount ever produces a lower fee.
#[test]
fn test_fee_calculation_properties() {
    // Fee should be monotonic
    for amount in [MIN_TX_IOTA, 100, 500, 1000, 1001, 5000, 10000] {
        let fee1 = fee_int_iota(amount);
        let fee2 = fee_int_iota(amount + 1);
        assert!(fee2 >= fee1, "Fee should be monotonic: {fee1} vs {fee2}");
    }
}

/// Merkle root properties sanity checks.
/// # Panics
/// Panics if Merkle root invariants are violated, e.g., different orderings produce different roots when there is more than one leaf.
#[test]
fn test_merkle_root_properties() {
    let leaves = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
        vec![10, 11, 12],
    ];
    
    // Different orderings should produce different roots
    let root1 = merkle_root(&leaves);
    let mut reversed = leaves.clone();
    reversed.reverse();
    let root2 = merkle_root(&reversed);
    
    if leaves.len() > 1 {
        assert_ne!(root1, root2, "Different orderings should produce different roots");
    }
}

/// State accounting should conserve total iota across admission.
/// # Panics
/// Panics if the final spendable plus reserved does not equal the initial total.
#[test]
fn test_state_consistency() {
    let mut state = setup_test_state();
    let initial_total: u128 = state.spendable_iota.values().sum();
    
    let beacon = test_hash(100);
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
        create_signed_test_tx(2, 1, 0, 200, 100),
    ];
    
    pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    let final_spendable: u128 = state.spendable_iota.values().sum();
    let final_reserved: u128 = state.reserved_iota.values().sum();
    
    // Total should be conserved
    assert_eq!(initial_total, final_spendable + final_reserved);
}

// ——— Constants and Limits Tests ———————————————————————————————

/// Runtime checks for fee constants and thresholds.
/// # Panics
/// Panics if fee calculation behavior at the minimum, switch threshold, or just above the switch does not match expectations.
#[test]
fn test_constants_validity() {
    // Validate relationships via runtime behavior checks instead of asserting on constants
    // MIN bound should be admissible for flat fee
    assert_eq!(fee_int_iota(MIN_TX_IOTA), FLAT_FEE_IOTA);
    // Flat fee should apply up to the switch threshold
    assert_eq!(fee_int_iota(FLAT_SWITCH_IOTA), FLAT_FEE_IOTA);
    // Just above switch should use percentage fee equal to ceil(amount / PCT_DEN)
    let just_above = FLAT_SWITCH_IOTA.saturating_add(1);
    assert_eq!(fee_int_iota(just_above), just_above.div_ceil(PCT_DEN));
 }



/// Bench-like performance smoke test for building ticket root.
///
/// # Panics
/// - If the resulting root is the zero hash, which would indicate a logic error.
fn test_ticket_root_performance() {
    let mut state = setup_test_state();
    state.spendable_iota.insert(test_pk(1), 1_000_000);
    
    let beacon = test_hash(100);
    let mut candidates = Vec::new();
    
    // Create 50 transactions
    for nonce in 0..50 {
        candidates.push(create_signed_test_tx(1, 2, nonce, 100, 100));
    }
    
    pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    // Should compute root efficiently
    let (_, root) = pada_build_ticket_root_for_slot(100, &state);
    assert_ne!(root, [0u8; 32]);
}
fn test_le_bytes_encoding() {
    // Little-endian byte conversion should produce fixed-width arrays per type size.
    // # Panics
    // Panics if the byte representation does not match expected little-endian arrays for representative values.
    #[test]
    assert_eq!(le_bytes::<4>(0u128), [0, 0, 0, 0]);
    assert_eq!(le_bytes::<4>(1u128), [1, 0, 0, 0]);
    assert_eq!(le_bytes::<4>(256u128), [0, 1, 0, 0]);
    assert_eq!(le_bytes::<8>(0xDEAD_BEEF_u128), [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);
}

*/
/// `sha3_256` should be deterministic and collision-resistant over simple inputs.
/// # Panics
/// Panics if identical inputs hash differently or if different inputs hash identically in these cases.
#[test]
fn test_sha3_256_deterministic() {
    let input1 = b"test";
    let input2 = b"test";
    let input3 = b"different";
    
    assert_eq!(sha3_256(input1), sha3_256(input2));
    assert_ne!(sha3_256(input1), sha3_256(input3));
}

/// Domain separation via `h_tag` should differentiate hashes across domains while remaining deterministic within a domain.
/// # Panics
/// Panics if equal-domain hashes for equal data differ or if different-domain hashes for equal data are equal.
#[test]
fn test_h_tag_domain_separation() {
    let data = b"same_data";
    let tag1 = h_tag("domain1", &[data]);
    let tag2 = h_tag("domain2", &[data]);
    let tag3 = h_tag("domain1", &[data]);
    
    assert_ne!(tag1, tag2); // Different domains should produce different hashes
    assert_eq!(tag1, tag3); // Same domain and data should be deterministic
}

/// Merkle root/leaf/node operations should be deterministic and consistent.
/// # Panics
/// Panics if computed roots or nodes do not match expected values.
#[test]
fn test_merkle_operations() {
    let leaf1 = vec![1, 2, 3];
    let leaf2 = vec![4, 5, 6];
    let leaf3 = vec![7, 8, 9];
    
    // Test single leaf
    let root1 = merkle_root(&[leaf1.clone()]);
    assert_eq!(root1, merkle_leaf(&leaf1));
    
    // Test multiple leaves
    let root2 = merkle_root(&[leaf1.clone(), leaf2.clone()]);
    let expected = merkle_node(&merkle_leaf(&leaf1), &merkle_leaf(&leaf2));
    assert_eq!(root2, expected);
    
    // Test determinism
    let root3 = merkle_root(&[leaf1.clone(), leaf2.clone(), leaf3.clone()]);
    let root4 = merkle_root(&[leaf1, leaf2, leaf3]);
    assert_eq!(root3, root4);
}

// ——— Fee Calculation Tests ———————————————————————————————————

/// Fee calculation should match flat fee up to threshold and percentage afterward.
/// # Panics
/// Panics if fee values for representative inputs differ from expected constants or calculations.
#[test]
fn test_fee_calculation() {
    // Below minimum should panic
    assert_eq!(fee_int_iota(MIN_TX_IOTA), FLAT_FEE_IOTA);
    
    // Flat fee range
    assert_eq!(fee_int_iota(100), FLAT_FEE_IOTA);
    assert_eq!(fee_int_iota(FLAT_SWITCH_IOTA), FLAT_FEE_IOTA);
    
    // Percentage fee range
    assert_eq!(fee_int_iota(1001), 11); // ceil(1001/100) = 11
    assert_eq!(fee_int_iota(10000), 100); // 1% of 10000
    assert_eq!(fee_int_iota(9999), 100); // ceil(9999/100) = 100
}

fn test_fee_calculation_below_minimum() {
    fee_int_iota(MIN_TX_IOTA - 1);
}

// ——— Access List Tests ———————————————————————————————————————

/// Access list encoding should be domain-tagged and deterministic.
/// # Panics
/// Panics if the domain tag is missing or if two encodings of the same access list differ.
#[test]
fn test_access_list_encoding() {
    let access = AccessList {
        read_accounts: vec![test_pk(1), test_pk(2)],
        write_accounts: vec![test_pk(3)],
    };
    
    let encoded = encode_access(&access);
    
    // Should start with domain tag
    assert!(encoded.starts_with(&h_tag("tx.access", &[])));
    
    // Should be deterministic
    let encoded2 = encode_access(&access);
    assert_eq!(encoded, encoded2);
}

/// Access list encoding should ignore duplicate entries by design of canonicalization.
/// # Panics
/// Panics if encoding with duplicates does not match encoding of a de-duplicated access list.
#[test]
fn test_access_list_deduplication() {
    let access = AccessList {
        read_accounts: vec![test_pk(1), test_pk(1), test_pk(2)],
        write_accounts: vec![test_pk(3), test_pk(3)],
    };
    
    let encoded = encode_access(&access);
    
    // Create expected without duplicates
    let mut expected_access = AccessList {
        read_accounts: vec![test_pk(1), test_pk(2)],
        write_accounts: vec![test_pk(3)],
    };
    let expected_encoded = encode_access(&expected_access);
    
    assert_eq!(encoded, expected_encoded);
}

// ——— Transaction Encoding Tests ——————————————————————————————

/// Canonical transaction bytes encoding should be deterministic and domain-tagged.
/// # Panics
/// Panics if two encodings of the same transaction differ or if the domain tag is missing.
#[test]
fn test_canonical_tx_bytes() {
    let tx = create_test_tx(1, 2, 0, 1000, 100);
    let bytes1 = canonical_tx_bytes(&tx);
    let bytes2 = canonical_tx_bytes(&tx);
    
    // Should be deterministic
    assert_eq!(bytes1, bytes2);
    
    // Should start with domain tag
    assert!(bytes1.starts_with(&h_tag("tx.body.v1", &[])));
}

/// `TxID` computation should be deterministic for the same transaction data.
/// # Panics
/// Panics if two invocations of `txid` for the same transaction produce different results.
#[test]
fn test_txid_deterministic() {
    let tx = create_test_tx(1, 2, 0, 1000, 100);
    let id1 = txid(&tx);
    let id2 = txid(&tx);
    
    assert_eq!(id1, id2);
}

/// `TxID` should change when any transaction field that contributes to the hash changes.
/// # Panics
/// Panics if different transactions (nonce or sender changed) produce identical txids.
#[test]
fn test_txid_uniqueness() {
    let tx1 = create_test_tx(1, 2, 0, 1000, 100);
    let tx2 = create_test_tx(1, 2, 1, 1000, 100); // Different nonce
    let tx3 = create_test_tx(2, 2, 0, 1000, 100); // Different sender
    
    let id1 = txid(&tx1);
    let id2 = txid(&tx2);
    let id3 = txid(&tx3);
    
    assert_ne!(id1, id2);
    assert_ne!(id1, id3);
    assert_ne!(id2, id3);
}

/// Commitment hash should be deterministic and distinct from the transaction id.
/// # Panics
/// Panics if two invocations of `tx_commit` for the same transaction differ or if the commit equals the txid.
#[test]
fn test_tx_commit() {
    let tx = create_test_tx(1, 2, 0, 1000, 100);
    let commit1 = tx_commit(&tx);
    let commit2 = tx_commit(&tx);
    
    assert_eq!(commit1, commit2);
    
    // Commit should be different from txid
    assert_ne!(commit1, txid(&tx));
}

// ——— Ticket Record Tests ——————————————————————————————————————

/// Ticket leaf encoding should be deterministic and domain-tagged.
/// # Panics
/// Panics if two encodings of the same ticket differ or if the domain tag is missing.
#[test]
fn test_ticket_leaf_encoding() {
    let ticket = TicketRecord {
        ticket_id: test_hash(1),
        txid: test_hash(2),
        sender: test_pk(1),
        nonce: 42,
        amount_iota: 1000,
        fee_iota: 10,
        s_admit: 100,
        s_exec: 100,
        commit_hash: test_hash(3),
    };
    
    let encoded1 = enc_ticket_leaf(&ticket);
    let encoded2 = enc_ticket_leaf(&ticket);
    
    // Should be deterministic
    assert_eq!(encoded1, encoded2);
    
    // Should start with domain tag
    assert!(encoded1.starts_with(&h_tag("ticket.leaf", &[])));
}

// ——— State Management Tests ———————————————————————————————————

/// Basic accessors on `PadaState` should reflect initial setup state.
/// # Panics
/// Panics if state accessors return unexpected values.
#[test]
fn test_pada_state_accessors() {
    let state = setup_test_state();
    
    assert_eq!(state.spendable_of(&test_pk(1)), 10000);
    assert_eq!(state.spendable_of(&test_pk(99)), 0); // Non-existent
    
    assert_eq!(state.reserved_of(&test_pk(1)), 0);
    assert_eq!(state.nonce_of(&test_pk(1)), 0);
}

// ——— Transaction Admission Tests ——————————————————————————————

/// Successful admission should finalize and reflect correct ticket fields and state updates.
/// # Panics
/// Panics if admission fails or if ticket/state fields do not match expectations.
fn test_successful_admission() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(ticket) => {
            assert_eq!(ticket.sender, tx.sender);
            assert_eq!(ticket.nonce, tx.nonce);
            assert_eq!(ticket.amount_iota, tx.amount_iota);
            assert_eq!(ticket.s_admit, 100);
            assert_eq!(ticket.s_exec, 100);
        }
        AdmitResult::Rejected(_) => panic!("Expected successful admission"),
    }
    
    // Check state updates
    let total_cost = tx.amount_iota + tx.fee_iota;
    assert_eq!(state.spendable_of(&tx.sender), 10000 - total_cost);
    assert_eq!(state.reserved_of(&tx.sender), total_cost);
    assert_eq!(state.nonce_of(&tx.sender), 1);
}

/// Admission should reject transactions for the wrong slot.
/// # Panics
/// Panics if a transaction for a mismatched slot is not rejected.
fn test_admission_wrong_slot() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let beacon = test_hash(101);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 101, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::WrongSlot) => {},
        _ => panic!("Expected WrongSlot error"),
    }
}

/// Admission should reject transactions signed against the wrong beacon.
/// # Panics
/// Panics if a transaction with the wrong beacon is not rejected.
fn test_admission_wrong_beacon() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let wrong_beacon = test_hash(99);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &wrong_beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::WrongBeacon) => {},
        _ => panic!("Expected WrongBeacon error"),
    }
}

/// Admission should reject transactions whose nonce does not match the tracked sender nonce.
/// # Panics
/// Panics if a transaction with a mismatched nonce is not rejected.
fn test_admission_nonce_mismatch() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 5, 1000, 100); // Wrong nonce
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::NonceMismatch) => {},
        _ => panic!("Expected NonceMismatch error"),
    }
}

/// Admission should reject transactions with below-minimum amount.
/// # Panics
/// Panics if a below-minimum transaction is not rejected.
fn test_admission_below_min_amount() {
    let mut state = setup_test_state();
    // Create transaction manually to avoid fee calculation panic
    let tx = TxBodyV1 {
        sender: test_pk(1),
        recipient: test_pk(2),
        nonce: 0,
        amount_iota: MIN_TX_IOTA - 1,
        fee_iota: FLAT_FEE_IOTA,
        s_bind: 100,
        y_bind: test_hash(100),
        access: AccessList::default(),
        memo: vec![],
    };
    let sig = test_sign_tx(&tx, 1);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::BelowMinAmount) => {},
        _ => panic!("Expected BelowMinAmount error"),
    }
}

/// Admission should reject transactions with fee mismatch.
/// # Panics
/// Panics if a transaction with incorrect fee is not rejected.
fn test_admission_fee_mismatch() {
    let mut state = setup_test_state();
    let mut tx = create_test_tx(1, 2, 0, 1000, 100);
    tx.fee_iota = 5; // Wrong fee
    let sig = test_sign_tx(&tx, 1);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::FeeMismatch) => {},
        _ => panic!("Expected FeeMismatch error"),
    }
}

/// Admission should reject transactions when funds are insufficient.
/// # Panics
/// Panics if an overdrawn transaction is not rejected.
fn test_admission_insufficient_funds() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 20000, 100); // More than available
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Rejected(AdmitErr::InsufficientFunds) => {},
        _ => panic!("Expected InsufficientFunds error"),
    }
}

// ——— Batch Admission Tests ————————————————————————————————————

/// Canonical ordering should sort admitted transactions by txid.
/// # Panics
/// Panics if the number of admitted transactions or their order does not match expectations.
fn test_batch_admission_canonical_ordering() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(2, 1, 0, 100, 100),
        create_signed_test_tx(1, 2, 0, 200, 100),
        create_signed_test_tx(3, 1, 0, 150, 100), // Use different sender to avoid nonce conflicts
    ];
    
    let admitted = pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    // Should admit all valid transactions (sorted by txid)
    assert_eq!(admitted.len(), 3);
    
    // Verify transactions are sorted by txid
    let mut txids: Vec<_> = admitted.iter().map(|t| t.txid).collect();
    let mut sorted_txids = txids.clone();
    sorted_txids.sort_unstable();
    assert_eq!(txids, sorted_txids, "Transactions should be sorted by txid");
}

/// Batch admission should admit only valid transactions and reject invalid ones.
/// # Panics
/// Panics if the number or order of admitted transactions does not match expectations.
fn test_batch_admission_with_rejections() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100), // Valid
        create_signed_test_tx(1, 2, 5, 200, 100), // Wrong nonce
        create_signed_test_tx(2, 1, 0, 150, 100), // Valid
    ];
    
    let admitted = pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    // Should only admit valid transactions
    assert_eq!(admitted.len(), 2);
    assert_eq!(admitted[0].nonce, 0);
    assert_eq!(admitted[1].nonce, 0);
}

// ——— Ticket Root Generation Tests —————————————————————————————

/// Ticket root for an empty slot should match the tagged hash convention.
/// # Panics
/// Panics if the computed root differs from the expected tagged hash.
fn test_ticket_root_empty_slot() {
    let state = PadaState::default();
    let (_, root) = pada_build_ticket_root_for_slot(100, &state);
    
    // Should return tagged hash for empty slot
    let expected = h_tag("PADA/empty_slot", &[&le_bytes::<8>(100u128)]);
    assert_eq!(root, expected);
}

/// Ticket root should be the Merkle root over ticket leaves when tickets exist.
/// # Panics
/// Panics if the computed root does not match the Merkle root of the leaves.
fn test_ticket_root_with_tickets() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let tx1 = create_test_tx(1, 2, 0, 100, 100);
    let tx2 = create_test_tx(2, 1, 0, 200, 100);
    let candidates = vec![
        (tx1.clone(), test_sign_tx(&tx1, 1)),
        (tx2.clone(), test_sign_tx(&tx2, 2)),
    ];
    
    let admitted = pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    let (_, root1) = pada_build_ticket_root_for_slot(100, &state);
    
    // Should compute Merkle root of ticket leaves
    let leaves: Vec<Vec<u8>> = admitted.iter().map(enc_ticket_leaf).collect();
    let expected = merkle_root(&leaves);
    assert_eq!(root1, expected);
}

/// Building the ticket root twice without state changes must be deterministic.
/// # Panics
/// Panics if the two computed roots differ.
fn test_ticket_root_deterministic() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
    ];
    
    pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    let (_, root1) = pada_build_ticket_root_for_slot(100, &state);
    let (_, root2) = pada_build_ticket_root_for_slot(100, &state);
    
    assert_eq!(root1, root2);
}

// ——— Public API Tests —————————————————————————————————————————

/// Public API admission should finalize a valid transaction.
/// # Panics
/// Panics if a well-formed transaction is rejected by the public API.
#[test]
fn test_public_api_admit_transaction() {
    let mut state = setup_test_state();
    let (tx, sig) = create_signed_test_tx(1, 2, 0, 1000, 100);
    let beacon = test_hash(100);
    
    let result = admit_transaction(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(_) => {},
        AdmitResult::Rejected(_) => panic!("Expected successful admission"),
    }
}

/// Batch admission should admit valid candidates and return their count.
/// # Panics
/// Panics if batch admission returns an unexpected number of admitted transactions.
#[test]
fn test_public_api_admit_transactions_for_slot() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
        create_signed_test_tx(2, 1, 0, 200, 100),
    ];
    
    let admitted = admit_transactions_for_slot(100, &beacon, &candidates, &mut state);
    assert_eq!(admitted.len(), 2);
}

/// Public API should return a non-zero ticket root for a non-empty slot.
/// # Panics
/// Panics if the returned root is the zero hash.
#[test]
fn test_public_api_get_ticket_root_for_slot() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
    ];
    
    admit_transactions_for_slot(100, &beacon, &candidates, &mut state);
    let root = get_ticket_root_for_slot(100, &state);
    
    // Should be non-zero (not empty slot)
    assert_ne!(root, [0u8; 32]);
}

// ——— Edge Cases and Error Conditions ——————————————————————————

/// After spending exact balance (amount + fee), sender should have no spendable balance.
/// # Panics
/// Panics if the sender's spendable balance is not removed or if admission fails.
#[test]
fn test_zero_balance_after_transaction() {
    let mut state = PadaState::default();
    let exact_amount = 1000u128;
    let fee = fee_int_iota(exact_amount);
    let total = exact_amount + fee;
    
    // Set exact balance
    state.spendable_iota.insert(test_pk(1), total);
    
    let (tx, sig) = create_signed_test_tx(1, 2, 0, exact_amount, 100);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(_) => {
            // Balance should be removed (not set to 0)
            assert!(!state.spendable_iota.contains_key(&test_pk(1)));
            assert_eq!(state.reserved_of(&test_pk(1)), total);
        }
        AdmitResult::Rejected(_) => panic!("Expected successful admission"),
    }
}

/// Admission should support very large amounts within u128 without overflow issues.
/// # Panics
/// Panics if a large, but valid, transaction is rejected.
#[test]
fn test_large_amounts() {
    let mut state = PadaState::default();
    let large_amount = u128::MAX / 2;
    state.spendable_iota.insert(test_pk(1), u128::MAX);
    
    let (tx, sig) = create_signed_test_tx(1, 2, 0, large_amount, 100);
    let beacon = test_hash(100);
    
    let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
    
    match result {
        AdmitResult::Finalized(_) => {},
        AdmitResult::Rejected(_) => panic!("Expected successful admission with large amounts"),
    }
}

/// Nonces must increase sequentially for a given sender across admitted transactions.
/// # Panics
/// Panics if a sequentially valid transaction is rejected or if the tracked nonce does not increment as expected.
#[test]
fn test_sequential_nonces() {
    let mut state = setup_test_state();
    let beacon = test_hash(100);
    
    // Submit transactions with sequential nonces
    for nonce in 0..5 {
        let (tx, sig) = create_signed_test_tx(1, 2, nonce, 100, 100);
        
        let result = pada_try_admit_and_finalize(&tx, &sig, 100, &beacon, &mut state);
        match result {
            AdmitResult::Finalized(_) => {},
            AdmitResult::Rejected(err) => panic!("Transaction {} rejected: {:?}", nonce, err),
        }
        
        assert_eq!(state.nonce_of(&test_pk(1)), nonce + 1);
    }
}

// ——— Mathematical Properties Tests ————————————————————————————

/// Fee function monotonicity properties.
/// # Panics
/// Panics if increasing the amount ever produces a lower fee.
#[test]
fn test_fee_calculation_properties() {
    // Fee should be monotonic
    for amount in [MIN_TX_IOTA, 100, 500, 1000, 1001, 5000, 10000] {
        let fee1 = fee_int_iota(amount);
        let fee2 = fee_int_iota(amount + 1);
        assert!(fee2 >= fee1, "Fee should be monotonic: {fee1} vs {fee2}");
    }
}

/// Merkle root properties sanity checks.
/// # Panics
/// Panics if Merkle root invariants are violated, e.g., different orderings produce different roots when there is more than one leaf.
#[test]
fn test_merkle_root_properties() {
    let leaves = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
        vec![10, 11, 12],
    ];
    
    // Different orderings should produce different roots
    let root1 = merkle_root(&leaves);
    let mut reversed = leaves.clone();
    reversed.reverse();
    let root2 = merkle_root(&reversed);
    
    if leaves.len() > 1 {
        assert_ne!(root1, root2, "Different orderings should produce different roots");
    }
}

/// State accounting should conserve total iota across admission.
/// # Panics
/// Panics if the final spendable plus reserved does not equal the initial total.
#[test]
fn test_state_consistency() {
    let mut state = setup_test_state();
    let initial_total: u128 = state.spendable_iota.values().sum();
    
    let beacon = test_hash(100);
    let candidates = vec![
        create_signed_test_tx(1, 2, 0, 100, 100),
        create_signed_test_tx(2, 1, 0, 200, 100),
    ];
    
    pada_admit_slot_canonical(100, &beacon, &candidates, &mut state);
    
    let final_spendable: u128 = state.spendable_iota.values().sum();
    let final_reserved: u128 = state.reserved_iota.values().sum();
    
    // Total should be conserved
    assert_eq!(initial_total, final_spendable + final_reserved);
}

// ——— Constants and Limits Tests ———————————————————————————————

/// Runtime checks for fee constants and thresholds.
/// # Panics
/// Panics if fee calculation behavior at the minimum, switch threshold, or just above the switch does not match expectations.
#[test]
fn test_constants_validity() {
    // Validate relationships via runtime behavior checks instead of asserting on constants
    // MIN bound should be admissible for flat fee
    assert_eq!(fee_int_iota(MIN_TX_IOTA), FLAT_FEE_IOTA);
    // Flat fee should apply up to the switch threshold
    assert_eq!(fee_int_iota(FLAT_SWITCH_IOTA), FLAT_FEE_IOTA);
    // Just above switch should use percentage fee equal to ceil(amount / PCT_DEN)
    let just_above = FLAT_SWITCH_IOTA.saturating_add(1);
    assert_eq!(fee_int_iota(just_above), just_above.div_ceil(PCT_DEN));
 }