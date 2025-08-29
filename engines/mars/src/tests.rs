//! Comprehensive unit tests for the MARS engine
//! Tests header validation, parent linkage, consensus equalities, and deterministic root computation

use crate::*;
use alloc::vec;
use alloc::vec::Vec;
use alloc::format;

// ——— Test Helpers ————————————————————————————————————————————

/// Generate deterministic test data for consistent testing
fn test_hash(seed: u8) -> Hash256 {
    let mut data = [0u8; 32];
    data[0] = seed;
    data[31] = seed.wrapping_mul(17); // Add some variation
    sha3_256(&data)
}

fn test_parent_id() -> Hash256 {
    test_hash(42)
}

fn test_slot() -> u64 {
    1000
}

/// Mock beacon verifier for testing
struct MockBeaconVerifier {
    should_pass: bool,
}

impl MockBeaconVerifier {
    fn new(should_pass: bool) -> Self {
        Self { should_pass }
    }
}

impl BeaconVerifier for MockBeaconVerifier {
    fn verify_beacon(
        &self,
        _parent_id: &Hash256,
        _slot: u64,
        _seed_commit: &Hash256,
        _vdf_y_core: &Hash256,
        _vdf_y_edge: &Hash256,
        _vdf_pi: &[u8],
        _vdf_ell: &[u8],
    ) -> bool {
        self.should_pass
    }
}

/// Mock ticket root provider for testing
struct MockTicketProvider {
    roots: Vec<(u64, Hash256)>,
}

impl MockTicketProvider {
    fn new() -> Self {
        Self { roots: Vec::new() }
    }
    
    fn with_root(mut self, slot: u64, root: Hash256) -> Self {
        self.roots.push((slot, root));
        self
    }
}

impl TicketRootProvider for MockTicketProvider {
    fn compute_ticket_root(&self, slot: u64) -> Hash256 {
        for (s, root) in &self.roots {
            if *s == slot {
                return *root;
            }
        }
        // Default deterministic root
        h_tag("test.ticket.root", &[&le_bytes::<8>(slot as u128)])
    }
}

/// Mock transaction root provider for testing
struct MockTxProvider {
    roots: Vec<(u64, Hash256)>,
}

impl MockTxProvider {
    fn new() -> Self {
        Self { roots: Vec::new() }
    }
    
    fn with_root(mut self, slot: u64, root: Hash256) -> Self {
        self.roots.push((slot, root));
        self
    }
}

impl TxRootProvider for MockTxProvider {
    fn compute_txroot(&self, slot: u64) -> Hash256 {
        for (s, root) in &self.roots {
            if *s == slot {
                return *root;
            }
        }
        // Default deterministic root
        h_tag("test.tx.root", &[&le_bytes::<8>(slot as u128)])
    }
}

// ——— Basic Functionality Tests ————————————————————————————————

#[test]
fn test_le_bytes_encoding() {
    // Test little-endian byte encoding
    let val: u128 = 0x123456789ABCDEF0;
    let bytes_8 = le_bytes::<8>(val);
    let bytes_4 = le_bytes::<4>(val);
    
    // Verify little-endian encoding
    assert_eq!(bytes_8[0], 0xF0);
    assert_eq!(bytes_8[7], 0x12);
    assert_eq!(bytes_4[0], 0xF0);
    assert_eq!(bytes_4[3], 0x9A);
}

#[test]
fn test_sha3_256_deterministic() {
    let input1 = b"test input";
    let input2 = b"test input";
    let input3 = b"different input";
    
    let hash1 = sha3_256(input1);
    let hash2 = sha3_256(input2);
    let hash3 = sha3_256(input3);
    
    assert_eq!(hash1, hash2); // Same input produces same hash
    assert_ne!(hash1, hash3); // Different input produces different hash
    assert_eq!(hash1.len(), 32); // Correct length
}

#[test]
fn test_h_tag_domain_separation() {
    let tag1 = "domain1";
    let tag2 = "domain2";
    let data = b"same data";
    
    let hash1 = h_tag(tag1, &[data]);
    let hash2 = h_tag(tag2, &[data]);
    let hash3 = h_tag(tag1, &[data]); // Same as hash1
    
    assert_ne!(hash1, hash2); // Different domains produce different hashes
    assert_eq!(hash1, hash3); // Same domain and data produce same hash
}

#[test]
fn test_merkle_operations() {
    // Test merkle leaf
    let payload = b"test payload";
    let leaf = merkle_leaf(payload);
    assert_eq!(leaf.len(), 32);
    
    // Test merkle node
    let left = test_hash(1);
    let right = test_hash(2);
    let node = merkle_node(&left, &right);
    assert_eq!(node.len(), 32);
    assert_ne!(node, left);
    assert_ne!(node, right);
    
    // Test merkle root with multiple leaves
    let leaves = vec![
        b"leaf1".to_vec(),
        b"leaf2".to_vec(),
        b"leaf3".to_vec(),
        b"leaf4".to_vec(),
    ];
    let root = merkle_root(&leaves);
    assert_eq!(root.len(), 32);
    
    // Test empty leaves
    let empty_root = merkle_root(&[]);
    assert_eq!(empty_root, h_tag("merkle.empty", &[]));
}

// ——— Ticket Leaf Tests ————————————————————————————————————————

#[test]
fn test_ticket_leaf_encoding() {
    let ticket = TicketLeaf {
        ticket_id: test_hash(1),
        txid: test_hash(2),
        sender: [3u8; 32],
        nonce: 12345,
        amount_iota: 1000000,
        fee_iota: 1000,
        s_admit: 100,
        s_exec: 101,
        commit_hash: test_hash(4),
    };
    
    let encoded = enc_ticket_leaf(&ticket);
    
    // Verify encoding includes all fields
    assert!(encoded.len() > 32 * 3 + 8 + 16 + 16 + 8 + 8); // Minimum expected size
    
    // Test deterministic encoding
    let encoded2 = enc_ticket_leaf(&ticket);
    assert_eq!(encoded, encoded2);
}

#[test]
fn test_txid_leaf_encoding() {
    let txid = test_hash(42);
    let encoded = enc_txid_leaf(&txid);
    
    // Should be domain tag (32 bytes) + txid (32 bytes) = 64 bytes
    assert_eq!(encoded.len(), 64);
    
    // First 32 bytes should be the domain tag
    let expected_tag = h_tag("txid.leaf", &[]);
    assert_eq!(&encoded[0..32], &expected_tag);
    
    // Last 32 bytes should be the txid
    assert_eq!(&encoded[32..64], &txid);
}

// ——— Header Tests ————————————————————————————————————————————

#[test]
fn test_header_id_deterministic() {
    let header = Header {
        parent_id: test_hash(1),
        slot: 1000,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(2),
        vdf_y_core: test_hash(3),
        vdf_y_edge: test_hash(4),
        vdf_pi: vec![1, 2, 3, 4],
        vdf_ell: vec![5, 6, 7, 8],
        ticket_root: test_hash(5),
        txroot_prev: test_hash(6),
    };
    
    let id1 = header_id(&header);
    let id2 = header_id(&header);
    let id3 = get_header_id(&header);
    
    assert_eq!(id1, id2); // Deterministic
    assert_eq!(id1, id3); // Public API consistency
    assert_eq!(id1.len(), 32); // Correct length
}

#[test]
fn test_header_id_uniqueness() {
    let mut header1 = Header {
        parent_id: test_hash(1),
        slot: 1000,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(2),
        vdf_y_core: test_hash(3),
        vdf_y_edge: test_hash(4),
        vdf_pi: vec![1, 2, 3, 4],
        vdf_ell: vec![5, 6, 7, 8],
        ticket_root: test_hash(5),
        txroot_prev: test_hash(6),
    };
    
    let mut header2 = header1.clone();
    header2.slot = 1001; // Different slot
    
    let id1 = header_id(&header1);
    let id2 = header_id(&header2);
    
    assert_ne!(id1, id2); // Different headers have different IDs
}

// ——— Header Building Tests ————————————————————————————————————

#[test]
fn test_mars_build_header_basic() {
    let parent_id = test_parent_id();
    let slot = test_slot();
    
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: slot - 1,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let beacon_fields = (
        test_hash(10), // seed_commit
        test_hash(11), // y_core
        test_hash(12), // y_edge
        vec![7, 8, 9], // pi
        vec![10, 11, 12], // ell
    );
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let result = mars_build_header(
        &parent_header,
        beacon_fields,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    
    assert!(result.is_ok());
    let header = result.unwrap();
    
    // Verify basic header structure
    assert_eq!(header.parent_id, header_id(&parent_header));
    assert_eq!(header.slot, slot);
    assert_eq!(header.consensus_version, MARS_VERSION);
    
    // Verify beacon fields are set correctly
    assert_eq!(header.seed_commit, test_hash(10));
    assert_eq!(header.vdf_y_core, test_hash(11));
    assert_eq!(header.vdf_y_edge, test_hash(12));
}

#[test]
fn test_build_header_public_api() {
    let parent_id = test_parent_id();
    let slot = test_slot();
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: slot - 1,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let beacon_fields = (
        test_hash(10), // seed_commit
        test_hash(11), // y_core
        test_hash(12), // y_edge
        vec![7, 8, 9], // pi
        vec![10, 11, 12], // ell
    );
    
    let result = build_header(
        &parent_header,
        beacon_fields,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    
    assert!(result.is_ok());
}

#[test]
fn test_build_header_genesis_case() {
    let parent_id = test_hash(0); // Genesis parent
    let slot = 0; // Genesis slot
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 0, // Genesis parent slot
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let beacon_fields = (
        test_hash(10), // seed_commit
        test_hash(11), // y_core
        test_hash(12), // y_edge
        vec![7, 8, 9], // pi
        vec![10, 11, 12], // ell
    );
    
    let result = mars_build_header(
        &parent_header,
        beacon_fields,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    
    assert!(result.is_ok());
    let header = result.unwrap();
    
    // Genesis case should use the computed txroot from provider
    let expected_txroot = tx_provider.compute_txroot(parent_header.slot);
    assert_eq!(header.txroot_prev, expected_txroot);
}

// ——— Header Validation Tests ————————————————————————————————————

#[test]
fn test_mars_validate_header_valid() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    let slot = parent_header.slot + 1;
    
    let header = Header {
        parent_id,
        slot,
        consensus_version: MARS_VERSION,
        seed_commit: h_tag("slot.seed", &[&parent_id, &le_bytes::<8>(slot as u128)]),
        vdf_y_core: test_hash(10),
        vdf_y_edge: test_hash(11),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(12),
        txroot_prev: test_hash(13),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new()
        .with_root(slot, header.ticket_root);
    let tx_provider = MockTxProvider::new()
        .with_root(slot - 1, header.txroot_prev);
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    
    assert!(result.is_ok());
}

#[test]
fn test_validate_header_bad_parent_link() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let header = Header {
        parent_id: test_hash(99), // Wrong parent ID
        slot: parent_header.slot + 1,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(6),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(9),
        txroot_prev: test_hash(10),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ValidateErr::BadParentLink));
}

#[test]
fn test_validate_header_bad_slot_progression() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    
    let header = Header {
        parent_id,
        slot: parent_header.slot + 2, // Wrong slot progression (should be +1)
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(6),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(9),
        txroot_prev: test_hash(10),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ValidateErr::BadSlotProgression));
}

#[test]
fn test_validate_header_version_mismatch() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    
    let header = Header {
        parent_id,
        slot: parent_header.slot + 1,
        consensus_version: 999, // Wrong version
        seed_commit: test_hash(6),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(9),
        txroot_prev: test_hash(10),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new()
        .with_root(header.slot, header.ticket_root);
    let tx_provider = MockTxProvider::new()
        .with_root(parent_header.slot, header.txroot_prev);
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ValidateErr::VersionMismatch));
}

#[test]
fn test_validate_header_beacon_invalid() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    let slot = parent_header.slot + 1;
    
    let header = Header {
        parent_id,
        slot,
        consensus_version: MARS_VERSION,
        seed_commit: h_tag("slot.seed", &[&parent_id, &le_bytes::<8>(slot as u128)]),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(9),
        txroot_prev: test_hash(10),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(false); // Beacon verification fails
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ValidateErr::BeaconInvalid));
}

#[test]
fn test_validate_header_ticket_root_mismatch() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    let slot = parent_header.slot + 1;
    
    let header = Header {
        parent_id,
        slot,
        consensus_version: MARS_VERSION,
        seed_commit: h_tag("slot.seed", &[&parent_id, &le_bytes::<8>(slot as u128)]),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(99), // Wrong ticket root
        txroot_prev: test_hash(10),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new()
        .with_root(slot, test_hash(88)); // Different from header
    let tx_provider = MockTxProvider::new();
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ValidateErr::TicketRootMismatch));
}

#[test]
fn test_validate_header_txroot_prev_mismatch() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    let slot = parent_header.slot + 1;
    
    let header = Header {
        parent_id,
        slot,
        consensus_version: MARS_VERSION,
        seed_commit: h_tag("slot.seed", &[&parent_id, &le_bytes::<8>(slot as u128)]),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(9),
        txroot_prev: test_hash(99), // Wrong txroot_prev
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new()
        .with_root(slot, header.ticket_root);
    let tx_provider = MockTxProvider::new()
        .with_root(slot - 1, test_hash(88)); // Different from header
    
    let result = mars_validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ValidateErr::TxRootPrevMismatch));
}

#[test]
fn test_validate_header_public_api() {
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 999,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let parent_id = header_id(&parent_header);
    let slot = parent_header.slot + 1;
    
    let header = Header {
        parent_id,
        slot,
        consensus_version: MARS_VERSION,
        seed_commit: h_tag("slot.seed", &[&parent_id, &le_bytes::<8>(slot as u128)]),
        vdf_y_core: test_hash(7),
        vdf_y_edge: test_hash(8),
        vdf_pi: vec![7, 8, 9],
        vdf_ell: vec![10, 11, 12],
        ticket_root: test_hash(9),
        txroot_prev: test_hash(10),
    };
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new()
        .with_root(slot, header.ticket_root);
    let tx_provider = MockTxProvider::new()
        .with_root(slot - 1, header.txroot_prev);
    
    let result = validate_header(
        &header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    
    assert!(result.is_ok());
}

// ——— Integration Tests ————————————————————————————————————————

#[test]
fn test_header_build_validate_integration() {
    let parent_id = test_parent_id();
    let slot = test_slot();
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    // Create a parent header for building
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: slot - 1,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let beacon_fields = (
        test_hash(10), // seed_commit
        test_hash(11), // y_core
        test_hash(12), // y_edge
        vec![7, 8, 9], // pi
        vec![10, 11, 12], // ell
    );
    
    // Build a header
    let build_result = mars_build_header(
        &parent_header,
        beacon_fields,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    assert!(build_result.is_ok());
    let header = build_result.unwrap();
    
    // Create a parent header for validation
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: slot - 1,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    // Ensure parent_id matches
    let actual_parent_id = header_id(&parent_header);
    let mut corrected_header = header;
    corrected_header.parent_id = actual_parent_id;
    
    // Update providers to match header values
    let ticket_provider = MockTicketProvider::new()
        .with_root(slot, corrected_header.ticket_root);
    let tx_provider = MockTxProvider::new()
        .with_root(slot - 1, corrected_header.txroot_prev);
    
    // Validate the header
    let validate_result = mars_validate_header(
        &corrected_header,
        &parent_header,
        &beacon_verifier,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    assert!(validate_result.is_ok());
}

// ——— Edge Cases and Error Conditions ————————————————————————————

#[test]
fn test_header_with_empty_proofs() {
    let header = Header {
        parent_id: test_hash(1),
        slot: 1000,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(2),
        vdf_y_core: test_hash(3),
        vdf_y_edge: test_hash(4),
        vdf_pi: vec![], // Empty proof
        vdf_ell: vec![], // Empty ell
        ticket_root: test_hash(5),
        txroot_prev: test_hash(6),
    };
    
    let id = header_id(&header);
    assert_eq!(id.len(), 32);
    
    // Should still be deterministic
    let id2 = header_id(&header);
    assert_eq!(id, id2);
}

#[test]
fn test_header_with_large_proofs() {
    let large_proof = vec![42u8; 1000]; // Large proof
    let large_ell = vec![84u8; 500]; // Large ell
    
    let header = Header {
        parent_id: test_hash(1),
        slot: 1000,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(2),
        vdf_y_core: test_hash(3),
        vdf_y_edge: test_hash(4),
        vdf_pi: large_proof,
        vdf_ell: large_ell,
        ticket_root: test_hash(5),
        txroot_prev: test_hash(6),
    };
    
    let id = header_id(&header);
    assert_eq!(id.len(), 32);
}

#[test]
fn test_genesis_slot_handling() {
    let parent_id = test_hash(0);
    let slot = 0; // Genesis slot
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    let ticket_provider = MockTicketProvider::new();
    let tx_provider = MockTxProvider::new();
    
    let parent_header = Header {
        parent_id: test_hash(0),
        slot: 0, // Genesis parent slot
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![4, 5, 6],
        ticket_root: test_hash(4),
        txroot_prev: test_hash(5),
    };
    
    let beacon_fields = (
        test_hash(10), // seed_commit
        test_hash(11), // y_core
        test_hash(12), // y_edge
        vec![7, 8, 9], // pi
        vec![10, 11, 12], // ell
    );
    
    let result = mars_build_header(
        &parent_header,
        beacon_fields,
        &ticket_provider,
        &tx_provider,
        MARS_VERSION,
    );
    
    assert!(result.is_ok());
    let header = result.unwrap();
    
    // Genesis should use the computed txroot from provider
    let expected_txroot = tx_provider.compute_txroot(parent_header.slot);
    assert_eq!(header.txroot_prev, expected_txroot);
}

// ——— Mathematical Properties Tests ————————————————————————————————

#[test]
fn test_header_id_collision_resistance() {
    // Test that different headers produce different IDs
    let base_header = Header {
        parent_id: test_hash(1),
        slot: 1000,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(2),
        vdf_y_core: test_hash(3),
        vdf_y_edge: test_hash(4),
        vdf_pi: vec![1, 2, 3, 4],
        vdf_ell: vec![5, 6, 7, 8],
        ticket_root: test_hash(5),
        txroot_prev: test_hash(6),
    };
    
    let mut headers = Vec::new();
    let mut ids = Vec::new();
    
    // Generate variations
    for i in 0..10 {
        let mut header = base_header.clone();
        header.slot = 1000 + i;
        header.seed_commit = test_hash((i + 10) as u8);
        
        let id = header_id(&header);
        
        // Check for collisions
        for existing_id in &ids {
            assert_ne!(id, *existing_id, "Header ID collision detected!");
        }
        
        headers.push(header);
        ids.push(id);
    }
}

#[test]
fn test_merkle_tree_properties() {
    // Test merkle tree mathematical properties
    let leaves = vec![
        b"leaf1".to_vec(),
        b"leaf2".to_vec(),
        b"leaf3".to_vec(),
        b"leaf4".to_vec(),
    ];
    
    let root1 = merkle_root(&leaves);
    let root2 = merkle_root(&leaves); // Same input
    assert_eq!(root1, root2); // Deterministic
    
    // Different order should produce different root
    let mut shuffled_leaves = leaves.clone();
    shuffled_leaves.reverse();
    let root3 = merkle_root(&shuffled_leaves);
    assert_ne!(root1, root3); // Order matters
    
    // Single leaf
    let single_leaf = vec![b"single".to_vec()];
    let single_root = merkle_root(&single_leaf);
    assert_eq!(single_root, merkle_leaf(b"single"));
}

#[test]
fn test_domain_separation_properties() {
    // Test that domain tags provide proper separation
    let data = b"same data for all";
    
    let domains = [
        "header.id",
        "slot.seed",
        "vdf.ycore.canon",
        "vdf.edge",
        "genesis.txroot",
        "test.ticket.root",
        "test.tx.root",
        "merkle.empty",
    ];
    
    let mut hashes = Vec::new();
    
    for domain in &domains {
        let hash = h_tag(domain, &[data]);
        
        // Check for collisions
        for existing_hash in &hashes {
            assert_ne!(hash, *existing_hash, "Domain separation failed for {}", domain);
        }
        
        hashes.push(hash);
    }
}

// ——— Constants and Version Tests ————————————————————————————————

#[test]
fn test_mars_version_constant() {
    assert_eq!(MARS_VERSION, 1);
}

#[test]
fn test_error_types_completeness() {
    // Ensure all error types can be constructed and matched
    let errors = [
        ValidateErr::BadParentLink,
        ValidateErr::BadSlotProgression,
        ValidateErr::BeaconInvalid,
        ValidateErr::TicketRootMismatch,
        ValidateErr::TxRootPrevMismatch,
        ValidateErr::VersionMismatch,
    ];
    
    for error in &errors {
        // Should be able to match each error type
        match error {
            ValidateErr::BadParentLink => {},
            ValidateErr::BadSlotProgression => {},
            ValidateErr::BeaconInvalid => {},
            ValidateErr::TicketRootMismatch => {},
            ValidateErr::TxRootPrevMismatch => {},
            ValidateErr::VersionMismatch => {},
        }
    }
}

// ——— Performance and Stress Tests ————————————————————————————————

#[test]
fn test_header_chain_validation() {
    // Test validating a chain of headers
    let mut headers = Vec::new();
    
    // Genesis header
    let genesis = Header {
        parent_id: test_hash(0),
        slot: 0,
        consensus_version: MARS_VERSION,
        seed_commit: test_hash(1),
        vdf_y_core: test_hash(2),
        vdf_y_edge: test_hash(3),
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: test_hash(4),
        txroot_prev: h_tag("genesis.txroot", &[]),
    };
    headers.push(genesis);
    
    let beacon_verifier = MockBeaconVerifier::new(true);
    
    // Build a chain of 5 headers
    for i in 1..=5 {
        let parent = &headers[i - 1];
        let parent_id = header_id(parent);
        let slot = i as u64;
        
        let ticket_provider = MockTicketProvider::new()
            .with_root(slot, test_hash((i + 10) as u8));
        let tx_provider = MockTxProvider::new()
            .with_root(slot - 1, test_hash((i + 20) as u8));
        
        let header = Header {
            parent_id,
            slot,
            consensus_version: MARS_VERSION,
            seed_commit: h_tag("slot.seed", &[&parent_id, &le_bytes::<8>(slot as u128)]),
            vdf_y_core: test_hash((i + 30) as u8),
            vdf_y_edge: test_hash((i + 40) as u8),
            vdf_pi: vec![i as u8],
            vdf_ell: vec![i as u8 + 100],
            ticket_root: test_hash((i + 10) as u8),
            txroot_prev: test_hash((i + 20) as u8),
        };
        
        // Validate against parent
        let result = mars_validate_header(
            &header,
            parent,
            &beacon_verifier,
            &ticket_provider,
            &tx_provider,
            MARS_VERSION,
        );
        assert!(result.is_ok(), "Header {} validation failed", i);
        
        headers.push(header);
    }
    
    // Verify chain properties
    assert_eq!(headers.len(), 6); // Genesis + 5 headers
    
    for i in 1..headers.len() {
        let header = &headers[i];
        let parent = &headers[i - 1];
        
        assert_eq!(header.parent_id, header_id(parent));
        assert_eq!(header.slot, parent.slot + 1);
    }
}