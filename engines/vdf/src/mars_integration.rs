//! VDF-MARS integration module
//!
//! Provides concrete implementation of MARS BeaconVerifier trait using VDF engine.
//! This bridges the VDF engine with MARS header validation.

use crate::*;
use alloc::vec::Vec;

/// VDF-based beacon verifier for MARS integration
pub struct VdfBeaconVerifier<B: VdfBackend> {
    _phantom: core::marker::PhantomData<B>,
}

impl<B: VdfBackend> VdfBeaconVerifier<B> {
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<B: VdfBackend> Default for VdfBeaconVerifier<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// MARS BeaconVerifier trait implementation
/// This is the bridge between VDF engine and MARS header validation
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

impl<B: VdfBackend> BeaconVerifier for VdfBeaconVerifier<B> {
    /// Verify a VDF-based beacon for MARS validation
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
    ) -> bool {
        // 1) Seed equality
        let seed_expected = slot_seed(parent_id, slot);
        if *seed_commit != seed_expected {
            return false;
        }

        // 2) Size caps (enforce prior to backend work)
        if vdf_pi.len() > constants::MAX_PI_LEN {
            return false;
        }
        if vdf_ell.len() > constants::MAX_ELL_LEN {
            return false;
        }

        // 3) Backend verify (returns canonical Y_raw if ok)
        let (ok, y_raw) = B::verify(seed_commit, constants::VDF_DELAY_T, vdf_pi, vdf_ell);
        if !ok {
            return false;
        }

        // 4) y_core equality
        let y_core_expected = ycore_from_raw(&y_raw);
        if *vdf_y_core != y_core_expected {
            return false;
        }

        // 5) y_edge equality
        let y_edge_expected = yedge_from_ycore(vdf_y_core);
        if *vdf_y_edge != y_edge_expected {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_backend::MockVdfBackend;
    use alloc::vec; // bring vec! macro into scope for no_std tests

    #[test]
    fn test_vdf_beacon_verifier_valid() {
        let verifier = VdfBeaconVerifier::<MockVdfBackend>::new();
        let parent_id = [1u8; 32];
        let slot = 42;
        
        // Build a valid beacon
        let beacon = build_beacon::<MockVdfBackend>(&parent_id, slot).unwrap();
        
        // Verify it
        let result = verifier.verify_beacon(
            &parent_id,
            slot,
            &beacon.seed_commit,
            &beacon.vdf_y_core,
            &beacon.vdf_y_edge,
            &beacon.vdf_pi,
            &beacon.vdf_ell,
        );
        
        assert!(result, "Valid beacon should pass verification");
    }

    #[test]
    fn test_vdf_beacon_verifier_invalid_seed() {
        let verifier = VdfBeaconVerifier::<MockVdfBackend>::new();
        let parent_id = [1u8; 32];
        let slot = 42;
        
        // Build a valid beacon
        let beacon = build_beacon::<MockVdfBackend>(&parent_id, slot).unwrap();
        
        // Use wrong seed
        let wrong_seed = [2u8; 32];
        
        let result = verifier.verify_beacon(
            &parent_id,
            slot,
            &wrong_seed,
            &beacon.vdf_y_core,
            &beacon.vdf_y_edge,
            &beacon.vdf_pi,
            &beacon.vdf_ell,
        );
        
        assert!(!result, "Invalid seed should fail verification");
    }

    #[test]
    fn test_vdf_beacon_verifier_oversized_proof() {
        let verifier = VdfBeaconVerifier::<MockVdfBackend>::new();
        let parent_id = [1u8; 32];
        let slot = 42;
        
        // Build a valid beacon
        let beacon = build_beacon::<MockVdfBackend>(&parent_id, slot).unwrap();
        
        // Create oversized proof
        let oversized_pi = vec![0u8; constants::MAX_PI_LEN + 1];
        
        let result = verifier.verify_beacon(
            &parent_id,
            slot,
            &beacon.seed_commit,
            &beacon.vdf_y_core,
            &beacon.vdf_y_edge,
            &oversized_pi,
            &beacon.vdf_ell,
        );
        
        assert!(!result, "Oversized proof should fail verification");
    }

    #[test]
    fn test_vdf_beacon_verifier_invalid_y_core() {
        let verifier = VdfBeaconVerifier::<MockVdfBackend>::new();
        let parent_id = [1u8; 32];
        let slot = 42;
        
        // Build a valid beacon
        let beacon = build_beacon::<MockVdfBackend>(&parent_id, slot).unwrap();
        
        // Use wrong y_core
        let wrong_y_core = [3u8; 32];
        
        let result = verifier.verify_beacon(
            &parent_id,
            slot,
            &beacon.seed_commit,
            &wrong_y_core,
            &beacon.vdf_y_edge,
            &beacon.vdf_pi,
            &beacon.vdf_ell,
        );
        
        assert!(!result, "Invalid y_core should fail verification");
    }

    #[test]
    fn test_vdf_beacon_verifier_invalid_y_edge() {
        let verifier = VdfBeaconVerifier::<MockVdfBackend>::new();
        let parent_id = [1u8; 32];
        let slot = 42;
        
        // Build a valid beacon
        let beacon = build_beacon::<MockVdfBackend>(&parent_id, slot).unwrap();
        
        // Use wrong y_edge
        let wrong_y_edge = [4u8; 32];
        
        let result = verifier.verify_beacon(
            &parent_id,
            slot,
            &beacon.seed_commit,
            &beacon.vdf_y_core,
            &wrong_y_edge,
            &beacon.vdf_pi,
            &beacon.vdf_ell,
        );
        
        assert!(!result, "Invalid y_edge should fail verification");
    }
}