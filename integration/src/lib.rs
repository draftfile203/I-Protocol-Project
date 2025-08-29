#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::println;

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;
use rand::SeedableRng;

// Public interface module re-exported for external crates (examples)
pub mod interface;

/// Proof inbox for collecting LAMEq-X proofs off-path
#[derive(Debug, Clone, Default)]
pub struct ProofInbox {
    /// Proofs submitted for future slots, keyed by slot number
    pub proofs_by_slot: BTreeMap<u64, Vec<lameqx::PartRec>>,
    /// Maximum number of proofs to store per slot
    pub max_proofs_per_slot: usize,
}

impl ProofInbox {
    /// Create new proof inbox with default capacity
    pub fn new() -> Self {
        Self {
            proofs_by_slot: BTreeMap::new(),
            max_proofs_per_slot: 1000, // Default limit
        }
    }
    
    /// Submit a proof for a future slot
    pub fn submit_proof(&mut self, slot: u64, proof: lameqx::PartRec) -> Result<(), ProtocolError> {
        let proofs = self.proofs_by_slot.entry(slot).or_default();
        
        if proofs.len() >= self.max_proofs_per_slot {
            return Err(ProtocolError::LameqxError(
                format!("Proof inbox full for slot {}", slot)
            ));
        }
        
        proofs.push(proof);
        Ok(())
    }
    
    /// Get and remove all proofs for a specific slot
    pub fn take_proofs_for_slot(&mut self, slot: u64) -> Vec<lameqx::PartRec> {
        self.proofs_by_slot.remove(&slot).unwrap_or_default()
    }
    
    /// Clean up old proofs (for slots that have passed)
    pub fn cleanup_old_proofs(&mut self, current_slot: u64) {
        // Only remove proofs for slots that are definitely old (more than 1 slot behind)
        self.proofs_by_slot.retain(|&slot, _| slot >= current_slot.saturating_sub(1));
    }
    
    /// Get number of proofs waiting for a slot
    pub fn proof_count_for_slot(&self, slot: u64) -> usize {
        self.proofs_by_slot.get(&slot).map(|v| v.len()).unwrap_or(0)
    }
}

/// Helper function to pre-generate LAMEq-X proofs for testing
pub fn pre_generate_test_proofs(
    inbox: &mut ProofInbox,
    slot: u64,
    y_edge_prev: &Hash256,
    num_participants: usize,
) -> Result<(), ProtocolError> {
    println!("[TEST] Pre-generating {} proofs for slot {} using y_edge_prev: {:02x?}", 
             num_participants, slot, &y_edge_prev[..4]);
    
    for i in 0..num_participants {
        // Generate deterministic keypair for testing
        let mut seed = [0u8; 32];
        seed[0] = i as u8 + 3; // Different from transaction keys
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let (pk, _sk) = iprotocol_crypto::generate_keypair(&mut rng);
        
        // Use the secret key directly for LAMEq-X
        
        let proof = lameqx::lqx_prove_for_slot(slot, y_edge_prev, &pk, &|_pk, _msg| {
            // Simple mock signature for now - in real implementation this would use actual signing
            [0u8; 64]
        });
        inbox.submit_proof(slot, proof)?;
        println!("[TEST] Generated proof {} for participant {}", i + 1, i + 1);
    }
    
    println!("[TEST] Successfully pre-generated {} proofs for slot {}", num_participants, slot);
    Ok(())
}

// Re-export all engine modules
pub use iprotocol_vdf as vdf;
pub use iprotocol_lameqx as lameqx;
pub use iprotocol_mars as mars;
pub use iprotocol_pada as pada;
pub use iprotocol_tokenomics as tokenomics;

/// Slot context for tracking previous beacon for LAMEq-X proof generation
#[derive(Debug, Clone)]
pub struct SlotCtx {
    slot: u64,              // s
    parent_id: Hash256,     // header_id(parent)
    y_edge_prev: Hash256,   // == parent.vdf_y_edge = y_{s-1}
}

const GENESIS_Y0: Hash256 = [0u8; 32]; // Genesis beacon for slot 0

// Common types
pub type Hash256 = [u8; 32];

/// Parameters for block creation to avoid too many function arguments
#[derive(Clone, Debug)]
struct BlockCreationParams {
    slot: u64,
    _timestamp: u64,
    beacon: vdf::Beacon,
    _participants: Vec<lameqx::PartRec>,
    system_transactions: Vec<tokenomics::SysTx>,
}

/// VDF backend types
#[derive(Clone, Debug)]
pub enum VdfBackendType {
    Mock,
    Rsa,
    ClassGroup,
}

impl Default for VdfBackendType {
    fn default() -> Self {
        Self::Mock
    }
}

/// Protocol configuration
#[derive(Clone, Debug)]
pub struct ProtocolConfig {
    pub genesis_slot: u64,
    pub genesis_timestamp: u64,
    pub genesis_accounts: BTreeMap<Hash256, u128>, // Simplified to just balances
    pub vdf_backend: VdfBackendType,
    pub max_mempool_size: usize,
    pub max_block_size: usize,
}

// Utilities module used by examples
pub mod utils {
    use super::{ProtocolConfig, VdfBackendType, Hash256};
    use alloc::collections::BTreeMap;
    use ed25519_dalek::VerifyingKey;

    /// Provide a sensible default configuration for quick-start examples
    pub fn default_config() -> ProtocolConfig {
        ProtocolConfig {
            genesis_slot: 0,
            genesis_timestamp: 0,
            genesis_accounts: BTreeMap::new(),
            vdf_backend: VdfBackendType::Mock,
            max_mempool_size: 10_000,
            max_block_size: 1_000_000,
        }
    }

    /// Create a genesis account entry (currently just the balance)
    pub fn create_genesis_account(balance: u128) -> u128 {
        balance
    }

    /// Derive an address from an ed25519 public key
    pub fn address_from_public_key(pk: &VerifyingKey) -> Hash256 {
        // Use the shared crypto helper to derive a 32-byte address deterministically
        iprotocol_crypto::h_tag("addr", &[pk.as_bytes()])
    }
}

/// Main protocol state combining all engines
pub struct ProtocolState {
    // MARS state
    pub current_header: Option<mars::Header>,
    pub headers: BTreeMap<Hash256, mars::Header>,
    
    // PADA state
    pub pada_state: pada::PadaState,
    
    // Integration mempool (transactions waiting for admission)
    pub mempool: Vec<(pada::TxBodyV1, pada::Sig)>,
    
    // Tokenomics states
    pub emission_state: tokenomics::EmissionState,
    pub fee_split_state: tokenomics::FeeSplitState,
    pub nlb_epoch_state: tokenomics::NlbEpochState,
    pub drp_state: tokenomics::DrpState,
    
    // Protocol state
    pub current_slot: u64,
    pub vdf_backend_type: VdfBackendType,
    
    // Slot context for LAMEq-X
    pub slot_ctx: SlotCtx,
    
    // LAMEq-X proof inbox
    pub proof_inbox: ProofInbox,
}

impl Default for ProtocolState {
    fn default() -> Self {
        Self {
            current_header: None,
            headers: BTreeMap::new(),
            pada_state: pada::PadaState::default(),
            mempool: Vec::new(),
            emission_state: tokenomics::init_emission_state(),
            fee_split_state: tokenomics::init_fee_split_state(),
            nlb_epoch_state: tokenomics::NlbEpochState::default(),
            drp_state: tokenomics::init_drp_state(),
            current_slot: 0,
            vdf_backend_type: VdfBackendType::Mock,
            slot_ctx: SlotCtx::default(),
            proof_inbox: ProofInbox::new(),
        }
    }
}

impl Default for SlotCtx {
    fn default() -> Self {
        Self {
            slot: 1,
            parent_id: GENESIS_Y0, // Genesis parent header ID
            y_edge_prev: GENESIS_Y0, // Genesis beacon
        }
    }
}

/// Transaction type used in the protocol
#[derive(Clone, Debug)]
pub struct Transaction {
    pub id: Hash256,
    pub from: Hash256,
    pub to: Hash256,
    pub amount: tokenomics::IotaAmount,
    pub fee: tokenomics::IotaAmount,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

/// Block structure for the protocol
#[derive(Clone, Debug)]
pub struct Block {
    pub header: mars::Header,
    pub transactions: Vec<Transaction>,
    pub system_transactions: Vec<tokenomics::SysTx>,
}

/// Result of processing a slot
#[derive(Clone, Debug)]
pub struct SlotResult {
    pub slot: u64,
    pub beacon: vdf::Beacon,
    pub participants: Vec<lameqx::PartRec>,
    pub winners: Vec<Hash256>,
    pub emission_amount: tokenomics::IotaAmount,
    pub fees_collected: tokenomics::IotaAmount,
    pub system_transactions: Vec<tokenomics::SysTx>,
    pub block: Option<Block>,
}

/// Protocol error types
#[derive(Clone, Debug)]
pub enum ProtocolError {
    InvalidTransaction(String),
    VdfError(String),
    LameqxError(String),
    TokenomicsError(String),
    StateError(String),
    PadaError(String),
    MarsError(String),
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            ProtocolError::VdfError(msg) => write!(f, "VDF error: {}", msg),
            ProtocolError::LameqxError(msg) => write!(f, "LAMEq-X error: {}", msg),
            ProtocolError::TokenomicsError(msg) => write!(f, "Tokenomics error: {}", msg),
            ProtocolError::StateError(msg) => write!(f, "State error: {}", msg),
            ProtocolError::PadaError(msg) => write!(f, "PADA error: {}", msg),
            ProtocolError::MarsError(msg) => write!(f, "MARS error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}

/// Main protocol implementation
pub struct IProtocolV5 {
    state: ProtocolState,
}

impl IProtocolV5 {
    /// Create new protocol instance
    pub fn new(config: ProtocolConfig) -> Self {
        let mut state = ProtocolState {
            current_slot: config.genesis_slot,
            vdf_backend_type: config.vdf_backend,
            ..Default::default()
        };
        
        // Initialize PADA state with genesis accounts
        for (address, balance) in config.genesis_accounts {
            state.pada_state.spendable_iota.insert(address, balance);
            state.pada_state.next_nonce.insert(address, 0);
        }
        
        Self { state }
    }
    
    /// Get an immutable reference to the protocol state (for inspection in examples)
    pub fn get_state(&self) -> &ProtocolState {
        &self.state
    }
    
    /// Get a mutable reference to the protocol state (if needed by external tools)
    pub fn get_state_mut(&mut self) -> &mut ProtocolState {
        &mut self.state
    }
    
    /// Process the next slot with comprehensive inter-engine coordination
    pub fn process_next_slot(&mut self, timestamp: u64) -> Result<SlotResult, ProtocolError> {
        let slot = self.state.current_slot + 1;
        self.state.current_slot = slot;
        
        println!("[SLOT {}] Starting slot processing at timestamp {}", slot, timestamp);
        
        // CRITICAL: Update slot context at the beginning of slot processing
        // The slot context should already have y_edge_prev from the previous slot
        println!("[SLOT {}] Current slot context y_edge_prev: {:02x?}", slot, &self.state.slot_ctx.y_edge_prev[..4]);
        println!("[SLOT {}] Current slot context slot: {}", slot, self.state.slot_ctx.slot);
        
        // 1. Calculate emission using proper tokenomics state (Tokenomics)
        println!("[SLOT {}] Calculating emission for slot", slot);
        let mut emission_amount = 0u128;
        tokenomics::on_slot_emission(&mut self.state.emission_state, slot as u128, |amount| {
            emission_amount = amount;
        });
        println!("[SLOT {}] Emission calculated: {} IOTA", slot, emission_amount);
        
        // 2. Update NLB epoch state for fee splits (Tokenomics)
        println!("[SLOT {}] Updating NLB epoch state", slot);
        tokenomics::nlb_roll_epoch_if_needed(slot, &mut self.state.fee_split_state);
        println!("[SLOT {}] NLB epoch: {}, verifier: {}%, treasury: {}%, burn: {}%", 
                slot, 
                self.state.fee_split_state.nlb.epoch_index,
                self.state.fee_split_state.nlb.v_pct,
                self.state.fee_split_state.nlb.t_pct,
                self.state.fee_split_state.nlb.b_pct);
        
        // 3. Generate VDF beacon with proper backend selection (VDF)
        println!("[SLOT {}] Generating VDF beacon", slot);
        let parent_id = self.state.current_header
            .as_ref()
            .map(mars::header_id)
            .unwrap_or([0u8; 32]);
        
        // Generate VDF beacon (using mock backend for now)
        // TODO: Enable RSA and ClassGroup backends when features are available
        println!("[SLOT {}] Using Mock VDF backend", slot);
        let beacon = vdf::build_beacon::<vdf::mock_backend::MockVdfBackend>(&parent_id, slot)
            .map_err(|e| ProtocolError::VdfError(format!("{:?}", e)))?;
        
        println!("[SLOT {}] VDF beacon generated: y_edge = {:02x?}", slot, &beacon.vdf_y_edge[..4]);
        
        // 4. Process admitted transactions and collect fees (PADA + Tokenomics)
        println!("[SLOT {}] Processing admitted transactions from PADA", slot);
        let mut fees_collected: tokenomics::IotaAmount = 0;
        let mut fee_system_transactions = Vec::new();
        
        // Get admitted transactions from PADA for this slot
        let admitted_tickets = pada::get_admitted_tickets_for_slot(slot, &self.state.pada_state);
        println!("[SLOT {}] Found {} admitted tickets", slot, admitted_tickets.len());
        
        // Process fees from admitted transactions
        for ticket in &admitted_tickets {
            let fee = ticket.fee_iota;
            if fee > 0 {
                fees_collected += fee;
                // Add fee to escrow first
                self.state.fee_split_state.fee_escrow_iota += fee;
                
                // Route the fee through the fee split system using closures
                let mut verifier_amount = 0u128;
                let mut treasury_amount = 0u128;
                let mut burn_amount = 0u128;
                
                tokenomics::route_fee_with_nlb(
                    &mut self.state.fee_split_state,
                    fee, // fee_num
                    1,   // fee_den (since we're passing the full fee amount)
                    &mut |amount| {
                        verifier_amount += amount;
                    },
                    &mut |amount| {
                        treasury_amount += amount;
                    },
                    &mut |amount| {
                        burn_amount += amount;
                    },
                );
                
                // Add the collected amounts to system transactions
                if verifier_amount > 0 {
                    fee_system_transactions.push(tokenomics::SysTx::VerifierCredit { amount: verifier_amount });
                }
                if treasury_amount > 0 {
                    fee_system_transactions.push(tokenomics::SysTx::TreasuryCredit { amount: treasury_amount });
                }
                if burn_amount > 0 {
                    fee_system_transactions.push(tokenomics::SysTx::Burn { amount: burn_amount });
                }
            }
        }
        
        println!("[SLOT {}] Total fees collected: {} IOTA", slot, fees_collected);
        
        // 5. Collect pre-submitted participation proofs (LAMEq-X)
        println!("[SLOT {}] Collecting pre-submitted participation proofs", slot);
        
        // Clean up old proofs and get proofs submitted for this slot
        self.state.proof_inbox.cleanup_old_proofs(slot);
        let submitted_proofs = self.state.proof_inbox.take_proofs_for_slot(slot);
        println!("[SLOT {}] Found {} pre-submitted proofs", slot, submitted_proofs.len());
        
        // Use the previous beacon from slot context for LAMEq-X verification
        let y_edge_for_verification = self.state.slot_ctx.y_edge_prev;
        println!("[SLOT {}] Using y_edge_prev for verification: {:02x?}", slot, &y_edge_for_verification[..4]);
        
        // Verify each submitted proof against the previous beacon
        let mut verified_proofs = Vec::new();
        for (i, proof) in submitted_proofs.iter().enumerate() {
            match lameqx::lqx_verify_partrec(proof, &y_edge_for_verification) {
                Ok(()) => {
                    verified_proofs.push(proof.clone());
                    println!("[SLOT {}] Proof {} verified successfully", slot, i + 1);
                },
                Err(e) => {
                    println!("[SLOT {}] Proof {} verification failed: {:?}", slot, i + 1, e);
                }
            }
        }
        
        println!("[SLOT {}] Verified {} out of {} submitted proofs", slot, verified_proofs.len(), submitted_proofs.len());
        
        // Add LAMEq-X debug print as suggested by user
        println!("[LQX] submitted {} proofs, verified {}", 
                submitted_proofs.len(), verified_proofs.len());
        
        // Build participation set from verified proofs
        let mut sorted_participants: Vec<Hash256> = verified_proofs
            .iter()
            .map(|proof| proof.pk)
            .collect();
        sorted_participants.sort();
        let _participation_root = [0u8; 32]; // Placeholder for participation root
        
        println!("[SLOT {}] Built participation set with {} participants", slot, sorted_participants.len());
        
        // 6. Distribute DRP rewards using actual participation set (Tokenomics)
        println!("[SLOT {}] Distributing DRP rewards", slot);
        let verifier_pool_balance = self.state.fee_split_state.verifier_pool_balance;
        let drp_system_transactions = tokenomics::distribute_drp_for_slot(
            &sorted_participants,
            &beacon.vdf_y_edge,
            emission_amount,
            verifier_pool_balance,
            &self.state.drp_state,
        );
        
        println!("[SLOT {}] Generated {} DRP system transactions", slot, drp_system_transactions.len());
        
        // 7. Combine and order all system transactions
        println!("[SLOT {}] Combining and ordering system transactions", slot);
        let mut all_system_transactions = fee_system_transactions;
        all_system_transactions.extend(drp_system_transactions);
        tokenomics::order_sys_txs(&mut all_system_transactions);
        
        println!("[SLOT {}] Total system transactions: {}", slot, all_system_transactions.len());
        
        // 8. Try to create a block with proper commitments
        println!("[SLOT {}] Creating block", slot);
        let block = self.try_create_block(BlockCreationParams {
            slot,
            _timestamp: timestamp,
            beacon: beacon.clone(),
            _participants: submitted_proofs.clone(),
            system_transactions: all_system_transactions.clone(),
        })?;
        
        // Extract winners from DRP distribution
        let winners: Vec<Hash256> = all_system_transactions
            .iter()
            .filter_map(|tx| match tx {
                tokenomics::SysTx::RewardPayout { recipient, .. } => Some(*recipient),
                _ => None,
            })
            .collect();
        
        // Update slot context for next slot
        self.state.slot_ctx.y_edge_prev = beacon.vdf_y_edge;
        self.state.slot_ctx.parent_id = block.as_ref().map(|b| mars::header_id(&b.header)).unwrap_or(GENESIS_Y0);
        self.state.slot_ctx.slot = slot + 1;
        
        println!("[SLOT {}] Updated slot context: y_edge_prev={:02x?}, next_slot={}", 
                slot, &self.state.slot_ctx.y_edge_prev[..4], self.state.slot_ctx.slot);
        
        println!("[SLOT {}] Slot processing completed successfully", slot);
        println!("[SLOT {}] Block created: {}", slot, block.is_some());
        println!("[SLOT {}] Winners: {}", slot, winners.len());
        println!("[SLOT {}] Updated slot context for next slot: {}", slot, slot + 1);
        
        Ok(SlotResult {
            slot,
            beacon,
            participants: submitted_proofs,
            winners,
            emission_amount,
            fees_collected,
            system_transactions: all_system_transactions,
            block,
        })
    }
    
    /// Submit a transaction to the protocol
    pub fn submit_transaction(&mut self, transaction: Transaction, _timestamp: u64) -> Result<(), ProtocolError> {
        // Convert to PADA transaction format
        let tx_body = pada::TxBodyV1 {
            sender: transaction.from,
            recipient: transaction.to,
            amount_iota: transaction.amount,
            fee_iota: transaction.fee,
            nonce: transaction.nonce,
            s_bind: self.state.current_slot,
            y_bind: self.state.current_header
                .as_ref()
                .map(mars::header_id)
                .unwrap_or([0u8; 32]),
            access: pada::AccessList::default(),
            memo: Vec::new(),
        };
        
        // Add to mempool for later processing
        self.state.mempool.push((tx_body, transaction.signature));
        
        Ok(())
    }
    /// Return current mempool size
    pub fn mempool_size(&self) -> usize {
        self.state.mempool.len()
    }
     
     /// Try to create a block for the current slot
     fn try_create_block(
         &mut self,
         params: BlockCreationParams,
     ) -> Result<Option<Block>, ProtocolError> {
         let BlockCreationParams {
             slot,
             _timestamp,
             beacon,
             _participants,
             system_transactions,
         } = params;
         
         println!("[BLOCK {}] Starting block creation with {} mempool transactions", slot, self.state.mempool.len());
         
         // Collect transactions from mempool for admission
         let candidates: Vec<(pada::TxBodyV1, pada::Sig)> = self.state.mempool
             .iter()
             .map(|(tx_body, sig)| (tx_body.clone(), *sig))
             .collect();
         
         // Use PADA to admit transactions for this slot
         println!("[BLOCK {}] Attempting to admit {} candidates with slot={}, y_edge={:02x?}", 
                 slot, candidates.len(), slot, &beacon.vdf_y_edge[..4]);
         
         // Debug: Check each transaction before admission
         for (i, (tx, _sig)) in candidates.iter().enumerate() {
             println!("[BLOCK {}] Candidate {}: s_bind={}, y_bind={:02x?}, nonce={}, sender_balance={}", 
                     slot, i, tx.s_bind, &tx.y_bind[..4], tx.nonce, 
                     self.state.pada_state.spendable_iota.get(&tx.sender).unwrap_or(&0));
         }
         
         // CRITICAL FIX: Use the previous beacon (y_{s-1}) for PADA admission, not current beacon
         let y_prev_for_admission = self.state.slot_ctx.y_edge_prev;
         println!("[BLOCK {}] Using y_prev for admission: {:02x?}", slot, &y_prev_for_admission[..4]);
         
         let ticket_records = pada::admit_transactions_for_slot(
             slot,
             &y_prev_for_admission,
             &candidates,
             &mut self.state.pada_state,
         );
         
         println!("[BLOCK {}] PADA admitted {} transactions, generated {} tickets", 
                 slot, candidates.len(), ticket_records.len());
         
         // PADA admission result: compute ticket_root for this slot and log
         let ticket_root = if ticket_records.is_empty() {
             [0u8; 32]
         } else {
             pada::get_ticket_root_for_slot(slot, &self.state.pada_state)
         };
         println!("[ADMISSION] admitted {} tickets, ticket_root={:02x?}", 
                 ticket_records.len(), &ticket_root[..8]);
         
         // Debug: If no tickets were generated, log the issue
         if ticket_records.is_empty() && !candidates.is_empty() {
             println!("[BLOCK {}] WARNING: No tickets generated from {} candidates!", slot, candidates.len());
             println!("[BLOCK {}] This suggests PADA admission failures - check beacon binding, nonces, and balances", slot);
         }
         // Build header using MARS and return block
         // Compute txroot_prev for slot s-1 (no executed txs stored yet -> empty merkle)
         let empty_leaves: Vec<Vec<u8>> = Vec::new();
         let txroot_prev = mars::merkle_root(&empty_leaves);
 
         let header = mars::Header {
             parent_id: self.state.slot_ctx.parent_id,
             slot,
             consensus_version: mars::MARS_VERSION,
             seed_commit: beacon.seed_commit,
             vdf_y_core: beacon.vdf_y_core,
             vdf_y_edge: beacon.vdf_y_edge,
             vdf_pi: beacon.vdf_pi.clone(),
             vdf_ell: beacon.vdf_ell.clone(),
             ticket_root,
             txroot_prev,
         };
 
         println!("[BLOCK {}] Built header: parent_id={:02x?}, y_edge={:02x?}, ticket_root={:02x?}, txroot_prev={:02x?}",
             slot, &header.parent_id[..4], &header.vdf_y_edge[..4], &header.ticket_root[..4], &header.txroot_prev[..4]);
 
         let block = Block {
             header,
             transactions: Vec::new(),
             system_transactions,
         };
 
         // Clear mempool after inclusion
         self.state.mempool.clear();
 
        Ok(Some(block))
     }
}