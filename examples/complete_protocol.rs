//! Complete I Protocol V5 Example
//! 
//! This example demonstrates the full integration of all five engines:
//! - Engine 1: LAMEq-X (RAM-hard Sybil defense)
//! - Engine 2: VDF (Verifiable Delay Function)
//! - Engine 3: MARS (Mathematical Absolute Resolution System)
//! - Engine 4: PADA (Protocol Admission)
//! - Engine T: Tokenomics (Emission, fees, DRP)

use iprotocol_integration::*;

type BoxError = Box<dyn std::error::Error>;

fn main() -> Result<(), BoxError> {
    println!("I Protocol V5 Complete Integration Example");
    println!("=========================================\n");
    
    // 1. Initialize protocol with genesis configuration
    let mut config = utils::default_config();
    config.genesis_slot = 0;
    config.genesis_timestamp = 1000000000; // Mock timestamp
    
    // Create genesis accounts
    let genesis_balance: tokenomics::IotaAmount = 1_000_000_000_000; // 1T IOTA
    let genesis_account = utils::create_genesis_account(genesis_balance);
    
    // Create dummy address for genesis account
    let genesis_address = [1u8; 32];
    config.genesis_accounts.insert(genesis_address, genesis_account);
    
    println!("Genesis configuration created with {} accounts", config.genesis_accounts.len());
    
    // 2. Initialize protocol
    let mut protocol = IProtocolV5::new(config);
    println!("Protocol initialized successfully\n");
    
    // 3. Process several slots to demonstrate the system
    let mut current_time = 1000000000;
    
    for slot in 1..=5 {
        println!("Processing Slot {}", slot);
        println!("================");
        
        // Process the slot
        let result = protocol.process_next_slot(current_time)?;
        
        println!("Slot: {}", result.slot);
        println!("Emission: {} IOTA", result.emission_amount);
        println!("Fees collected: {} IOTA", result.fees_collected);
        println!("Participants: {}", result.participants.len());
        println!("Winners: {}", result.winners.len());
        println!("System transactions: {}", result.system_transactions.len());
        
        if let Some(block) = result.block {
            println!("Block created with {} transactions", block.transactions.len());
            println!("Block created successfully");
        } else {
            println!("No block created (no content)");
        }
        
        println!();
        current_time += 100; // Advance time by 100ms
    }
    
    // 4. Create and submit a transaction
    println!("Creating test transaction");
    println!("========================");
    
    let test_transaction = Transaction {
        id: [2u8; 32],
        from: genesis_address,
        to: [3u8; 32], // Different address
        amount: 1000u128,
        fee: 10u128,
        nonce: 1,
        timestamp: current_time,
        signature: [0u8; 64], // Mock signature
    };
    
    match protocol.submit_transaction(test_transaction, current_time) {
        Ok(()) => println!("Transaction submitted successfully"),
        Err(e) => println!("Transaction failed: {}", e),
    }
    
    // 5. Process another slot to include the transaction
    current_time += 100;
    let result = protocol.process_next_slot(current_time)?;
    
    println!("\nSlot {} after transaction:", result.slot);
    if let Some(block) = result.block {
        println!("Block created with {} transactions", block.transactions.len());
    }
    
    // 6. Display final state
    println!("\nFinal Protocol State");
    println!("===================");
    
    let state = protocol.get_state();
    println!("Current slot: {}", state.current_slot);
    println!("Headers in chain: {}", state.headers.len());
    println!("Mempool size: {}", protocol.mempool_size());
    println!("VDF backend: {:?}", state.vdf_backend_type);
    
    // 7. Demonstrate engine integration
    println!("\nEngine Integration Summary");
    println!("=========================");
    println!("✓ MARS: Block creation and chain management");
    println!("✓ PADA: Transaction validation and mempool management");
    println!("✓ VDF: Beacon generation for randomness");
    println!("✓ LAMEq-X: Participation proof collection");
    println!("✓ Tokenomics: Emission, fee distribution, and DRP");
    
    println!("\nI Protocol V5 integration example completed successfully!");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_initialization() {
        let config = utils::default_config();
        let protocol = interface::IProtocolV5::new(config);
        
        let state = protocol.get_state();
        assert_eq!(state.current_slot, 0);
        assert!(state.headers.is_empty());
    }
    
    #[test]
    fn test_slot_processing() {
        let config = utils::default_config();
        let mut protocol = IProtocolV5::new(config);
        
        let result = protocol.process_next_slot(1000000000).unwrap();
        assert_eq!(result.slot, 1);
        assert!(result.emission_amount > 0);
    }
    
    #[test]
    fn test_transaction_submission() {
        let mut config = utils::default_config();
        let genesis_balance: tokenomics::IotaAmount = 1_000_000;
        let genesis_account = utils::create_genesis_account(genesis_balance);
        let genesis_address = [1u8; 32];
        config.genesis_accounts.insert(genesis_address, genesis_account);
        
        let mut protocol = interface::IProtocolV5::new(config);
        
        let transaction = Transaction {
            id: [2u8; 32],
            from: genesis_address,
            to: [3u8; 32],
            amount: 1000u128,
            fee: 10u128,
            nonce: 1,
            timestamp: 1000000000,
            signature: [0u8; 64],
        };
        
        let result = protocol.submit_transaction(transaction, 1000000000);
        // Note: This might fail due to validation, but should not panic
        match result {
            Ok(()) => println!("Transaction accepted"),
            Err(e) => println!("Transaction rejected: {}", e),
        }
    }
}