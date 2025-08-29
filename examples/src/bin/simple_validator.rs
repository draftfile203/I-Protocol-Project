//! Simple Validator Binary
//!
//! A standalone binary that runs a simple validator demonstration.

use std::env;
use iprotocol_examples::{
    simple_validator::SimpleValidator,
    ExampleError,
};

fn main() -> Result<(), ExampleError> {
    let args: Vec<String> = env::args().collect();
    
    let num_slots = if args.len() > 1 {
        args[1].parse::<u64>()
            .map_err(|_| ExampleError::Other("Invalid number of slots".to_string()))?
    } else {
        10
    };
    
    println!("=== I Protocol V5 - Simple Validator ===");
    println!("Running validator for {} slots\n", num_slots);
    
    let mut validator = SimpleValidator::new()?;
    validator.run(num_slots)?;
    
    let stats = validator.get_stats();
    println!("\n=== Final Statistics ===");
    println!("Current slot: {}", stats.current_slot);
    println!("Validator balance: {} IOTA", stats.balance);
    println!("Total emitted: {} IOTA", stats.total_emitted);
    println!("Mempool size: {}", stats.mempool_size);
    
    println!("\nSimple validator demo completed!");
    Ok(())
}