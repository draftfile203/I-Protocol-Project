//! I Protocol V5 Examples
//!
//! This crate provides examples and demonstrations of the I Protocol V5
//! blockchain implementation, showcasing all five engines working together.

#![allow(unused)]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Import the integration layer and all engines
use iprotocol_integration::{
    interface::IProtocolV5,
    utils::{default_config, create_genesis_account, address_from_public_key},
    ProtocolConfig, ProtocolError,
    vdf, lameqx, pada, mars, tokenomics,
    Hash256,
};
use iprotocol_pada::{TxBodyV1, AccessList};
use iprotocol_integration::Transaction;

use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use rand::rngs::OsRng;

/// Example error type
#[derive(Debug)]
pub enum ExampleError {
    Protocol(ProtocolError),
    Crypto(String),
    Io(std::io::Error),
    Other(String),
}

impl From<ProtocolError> for ExampleError {
    fn from(err: ProtocolError) -> Self {
        ExampleError::Protocol(err)
    }
}

impl From<std::io::Error> for ExampleError {
    fn from(err: std::io::Error) -> Self {
        ExampleError::Io(err)
    }
}

/// Simple validator example
pub mod simple_validator {
    use super::*;
    
    /// Simple validator that processes slots and creates blocks
    pub struct SimpleValidator {
        protocol: IProtocolV5,
        signing_key: SigningKey,
        public_key: VerifyingKey,
        address: Hash256,
    }
    
    impl SimpleValidator {
        /// Create new simple validator
        pub fn new() -> Result<Self, ExampleError> {
            let mut rng = OsRng;
            let signing_key = SigningKey::generate(&mut rng);
            let public_key = signing_key.verifying_key();
            let address = address_from_public_key(&public_key);
            
            // Create genesis configuration with initial balance for validator
            let mut config = default_config();
            let genesis_balance = 1000 * tokenomics::IOTA_PER_I; // 1000 I
            config.genesis_accounts.insert(address, create_genesis_account(genesis_balance));
            
            let protocol = IProtocolV5::new(config);
            
            Ok(Self {
                protocol,
                signing_key,
                public_key,
                address,
            })
        }
        
        /// Run validator for specified number of slots
        pub fn run(&mut self, num_slots: u64) -> Result<(), ExampleError> {
            println!("Starting simple validator for {} slots", num_slots);
            println!("Validator address: {:?}", hex::encode(self.address));
            
            for i in 0..num_slots {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                
                println!("\n--- Processing Slot {} ---", self.protocol.get_state().current_slot + 1);
                
                let result = self.protocol.process_next_slot(timestamp)?;
                
                println!("Slot: {}", result.slot);
                println!("Emission: {} IOTA", result.emission_amount);
                println!("Fees collected: {} IOTA", result.fees_collected);
                println!("Participants: {}", result.participants.len());
                println!("Winners: {}", result.winners.len());
                
                if let Some(block) = &result.block {
                    println!("Block created with {} transactions", block.transactions.len());
                    println!("Block ID: {:?}", hex::encode(mars::header_id(&block.header)));
                } else {
                    println!("No block created (empty slot)");
                }
                
                // Show account balance
                let balance = self.protocol.get_state().pada_state.spendable_of(&self.address);
                println!("Validator balance: {} IOTA", balance);
                
                // Sleep for slot duration
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            
            Ok(())
        }
        
        /// Get validator statistics
        pub fn get_stats(&self) -> ValidatorStats {
            let state = self.protocol.get_state();
            let balance = state.pada_state.spendable_of(&self.address);
            let nonce = state.pada_state.nonce_of(&self.address);
            
            ValidatorStats {
                current_slot: state.current_slot,
                balance,
                nonce,
                total_emitted: state.emission_state.total_emitted_iota_paid,
                mempool_size: state.mempool.len(),
                chain_head: state.current_header.as_ref().map(mars::header_id),
                finalized_block: None, // Not tracked in current implementation
            }
        }
    }
    
    /// Validator statistics
    #[derive(Debug, Clone)]
    pub struct ValidatorStats {
        pub current_slot: u64,
        pub balance: u128,
        pub nonce: u64,
        pub total_emitted: u128,
        pub mempool_size: usize,
        pub chain_head: Option<Hash256>,
        pub finalized_block: Option<Hash256>,
    }
}

/// Transaction demonstration
pub mod transaction_demo {
    use super::*;
    
    /// Demonstrate transaction creation and processing
    pub fn run_transaction_demo() -> Result<(), ExampleError> {
        println!("=== Transaction Demo ===");
        
        let mut rng = OsRng;
        
        // Create two accounts
        let sender_key = SigningKey::generate(&mut rng);
        let sender_pk = sender_key.verifying_key();
        let sender_address = address_from_public_key(&sender_pk);
        
        let receiver_key = SigningKey::generate(&mut rng);
        let receiver_pk = receiver_key.verifying_key();
        let receiver_address = address_from_public_key(&receiver_pk);
        
        // Create protocol with genesis accounts
        let mut config = default_config();
        config.genesis_accounts.insert(
            sender_address,
            create_genesis_account(10000 * tokenomics::IOTA_PER_I),
        );
        config.genesis_accounts.insert(
            receiver_address,
            create_genesis_account(1000 * tokenomics::IOTA_PER_I),
        );
        
        let mut protocol = IProtocolV5::new(config);
        
        println!("Sender address: {:?}", hex::encode(sender_address));
        println!("Receiver address: {:?}", hex::encode(receiver_address));
        
        // Show initial balances
        let sender_initial = protocol.get_state().pada_state.spendable_of(&sender_address);
        let receiver_initial = protocol.get_state().pada_state.spendable_of(&receiver_address);
        let sender_nonce = protocol.get_state().pada_state.nonce_of(&sender_address);
        
        println!("\nInitial balances:");
        println!("Sender: {} IOTA", sender_initial);
        println!("Receiver: {} IOTA", receiver_initial);
        
        // Create transaction
        let amount = 5 * tokenomics::IOTA_PER_I; // 5 I
        let fee = tokenomics::fee_int_iota(amount);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let tx_body = pada::TxBodyV1 {
            sender: sender_address,
            recipient: receiver_address,
            nonce: sender_nonce + 1,
            amount_iota: amount,
            fee_iota: fee,
            s_bind: 0, // Current slot
            y_bind: [0u8; 32], // Previous beacon
            access: pada::AccessList::default(),
            memo: Vec::new(),
        };
        
        let tx_data = iprotocol_crypto::h_tag("tx.sig", &[&pada::canonical_tx_bytes(&tx_body)]);

        
        let signature = sender_key.sign(&tx_data);
        
        // Create the final transaction for submission
        let transaction = Transaction {
            id: iprotocol_crypto::h_tag("tx.id", &[&pada::canonical_tx_bytes(&tx_body)]),
            from: sender_address,
            to: receiver_address,
            amount,
            fee,
            nonce: sender_nonce + 1,
            signature: signature.into(),
            timestamp,
        };
        
        println!("\nTransaction details:");
        println!("Amount: {} IOTA", amount);
        println!("Fee: {} IOTA", fee);
        println!("Transaction ID: {:?}", hex::encode(transaction.id));
        
        // Submit transaction
        protocol.submit_transaction(transaction, timestamp)?;
        println!("\nTransaction submitted to mempool");
        
        // Process a few slots to include the transaction
        for i in 0..5 {
            let slot_timestamp = timestamp + (i * 100);
            let result = protocol.process_next_slot(slot_timestamp)?;
            
            println!("\nSlot {}: ", result.slot);
            if let Some(block) = &result.block {
                println!("  Block created with {} transactions", block.transactions.len());
                if !block.transactions.is_empty() {
                    println!("  Transaction included!");
                    break;
                }
            } else {
                println!("  No block created");
            }
        }
        
        // Show final balances
        let sender_final = protocol.get_state().pada_state.spendable_of(&sender_address);
        let receiver_final = protocol.get_state().pada_state.spendable_of(&receiver_address);
        
        println!("\nFinal balances:");
        println!("Sender: {} IOTA (change: {})", 
                sender_final, 
                sender_final as i64 - sender_initial as i64);
        println!("Receiver: {} IOTA (change: {})", 
                receiver_final,
                receiver_final as i64 - receiver_initial as i64);
        
        Ok(())
    }
}

/// VDF demonstration
pub mod vdf_demo {
    use super::*;
    use iprotocol_vdf::{build_beacon, verify_beacon, mock_backend::MockVdfBackend};
    
    /// Demonstrate VDF functionality
    pub fn run_vdf_demo() -> Result<(), ExampleError> {
        println!("=== VDF Demo ===");
        
        // Test VDF evaluation
        let parent_id = [1u8; 32];
        let slot = 42;
        
        println!("Building beacon for slot {}...", slot);
        let beacon = build_beacon::<MockVdfBackend>(&parent_id, slot)
            .map_err(|e| ExampleError::Other(format!("VDF error: {:?}", e)))?;
        
        println!("\nBeacon created:");
        println!("  Seed commit: {:?}", hex::encode(beacon.seed_commit));
        println!("  VDF y_core: {:?}", hex::encode(beacon.vdf_y_core));
        println!("  VDF y_edge: {:?}", hex::encode(beacon.vdf_y_edge));
        println!("  VDF proof size: {} bytes", beacon.vdf_pi.len());
        println!("  VDF aux size: {} bytes", beacon.vdf_ell.len());
        
        // Verify beacon
        println!("\nVerifying beacon...");
        let verification_result = verify_beacon::<MockVdfBackend>(&parent_id, slot, &beacon);
        let is_valid = verification_result.is_ok();
        if let Err(e) = verification_result {
            println!("VDF verification error: {:?}", e);
        }
        
        println!("Beacon verification: {}", if is_valid { "VALID" } else { "INVALID" });
        
        Ok(())
    }
}

/// Full protocol demonstration
pub mod full_protocol_demo {
    use super::*;
    
    /// Demonstrate the complete protocol with all engines
    pub fn run_full_demo() -> Result<(), ExampleError> {
        println!("=== Full Protocol Demo ===");
        println!("Demonstrating all five engines working together:\n");
        
        // Create multiple validators
        let mut validators = Vec::new();
        for i in 0..3 {
            let mut validator = simple_validator::SimpleValidator::new()?;
            println!("Created validator {}", i + 1);
            validators.push(validator);
        }
        
        println!("\n--- Running Protocol for 10 slots ---");
        
        // Run each validator for a few slots
        for (i, validator) in validators.iter_mut().enumerate() {
            println!("\n=== Validator {} ===", i + 1);
            validator.run(3)?;
            
            let stats = validator.get_stats();
            println!("\nValidator {} final stats:", i + 1);
            println!("  Current slot: {}", stats.current_slot);
            println!("  Balance: {} IOTA", stats.balance);
            println!("  Total emitted: {} IOTA", stats.total_emitted);
            println!("  Mempool size: {}", stats.mempool_size);
        }
        
        println!("\n=== Demo Complete ===");
        println!("All five engines (LAMEq-X, VDF, MARS, PADA, Tokenomics) demonstrated!");
        
        Ok(())
    }
}

/// Utility functions for examples
pub mod utils {
    use super::*;
    use ed25519_dalek::Signer;
    
    /// Print protocol state summary
    pub fn print_protocol_state(protocol: &IProtocolV5) {
        let state = protocol.get_state();
        
        println!("=== Protocol State ===");
        println!("Current slot: {}", state.current_slot);
        println!("Total emitted: {} IOTA", state.emission_state.total_emitted_iota_paid);
        println!("Mempool size: {}", state.mempool.len());
        
        if let Some(head) = &state.current_header {
            let head_id = mars::header_id(head);
            println!("Chain head: {:?}", hex::encode(head_id));
        } else {
            println!("Chain head: None (genesis)");
        }
        
        // Note: Finalized block tracking not implemented in current state structure
        println!("Finalized block: Not tracked in current implementation");
        
        println!("Fee escrow balance: {} IOTA", state.fee_split_state.fee_escrow_iota);
        println!("Treasury balance: {} IOTA", state.fee_split_state.treasury_balance);
        println!("Burn balance: {} IOTA", state.fee_split_state.burn_balance);
    }
    
    /// Generate random transaction
    pub fn generate_random_transaction(
        from_key: &SigningKey,
        to_address: Hash256,
        amount: u64,
        nonce: u64,
    ) -> Result<Transaction, ExampleError> {
        let from_pk = from_key.verifying_key();
        let from_address = address_from_public_key(&from_pk);
        
        let fee = tokenomics::fee_int_iota(amount.into());
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let mut transaction = Transaction {
            id: [0u8; 32],
            from: from_address,
            to: to_address,
            amount: amount as u128,
            fee,
            nonce,
            signature: [0u8; 64],
            timestamp,
        };
        
        // Create signing message
        let tx_bytes = format!("{:?}", transaction).into_bytes();
        let msg = iprotocol_crypto::h_tag("tx.sig", &[&tx_bytes]);
        let from_key_bytes = from_key.to_bytes();
        let signature = iprotocol_crypto::sign_message(&from_key_bytes, &msg)
            .map_err(|e| ExampleError::Crypto(format!("Signing failed: {:?}", e)))?;
        transaction.signature = signature;
        
        // Calculate ID
        let tx_bytes = format!("{:?}", transaction).into_bytes();
        transaction.id = iprotocol_crypto::h_tag("tx.id", &[&tx_bytes]);
        
        Ok(transaction)
    }
}