//! I Protocol V5 Examples - Main Entry Point
//!
//! This binary provides a command-line interface to run various
//! demonstrations of the I Protocol V5 blockchain implementation.

use std::env;
use std::process;

use iprotocol_examples::{
    simple_validator,
    transaction_demo,
    vdf_demo,
    full_protocol_demo,
    ExampleError,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let result = match args[1].as_str() {
        "validator" => run_simple_validator(&args[2..]),
        "transaction" => run_transaction_demo(),
        "vdf" => run_vdf_demo(),
        "full" => run_full_demo(),
        "help" | "--help" | "-h" => {
            print_usage(&args[0]);
            Ok(())
        },
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage(&args[0]);
            process::exit(1);
        }
    };
    
    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        process::exit(1);
    }
}

fn print_usage(program_name: &str) {
    println!("I Protocol V5 Examples");
    println!();
    println!("USAGE:");
    println!("    {} <COMMAND> [OPTIONS]", program_name);
    println!();
    println!("COMMANDS:");
    println!("    validator [SLOTS]    Run a simple validator for specified slots (default: 10)");
    println!("    transaction          Demonstrate transaction creation and processing");
    println!("    vdf                  Demonstrate VDF (Verifiable Delay Function) operations");
    println!("    full                 Run complete protocol demonstration with all engines");
    println!("    help                 Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    {} validator 20      # Run validator for 20 slots", program_name);
    println!("    {} transaction       # Demo transaction processing", program_name);
    println!("    {} vdf               # Demo VDF operations", program_name);
    println!("    {} full              # Complete protocol demo", program_name);
    println!();
    println!("DESCRIPTION:");
    println!("    This program demonstrates the I Protocol V5 blockchain implementation,");
    println!("    showcasing all five engines working together:");
    println!("    ");
    println!("    • Engine 1 (LAMEq-X): RAM-hard Sybil defense");
    println!("    • Engine 2 (VDF): Verifiable Delay Function for randomness");
    println!("    • Engine 3 (MARS): Mathematical Absolute Resolution System");
    println!("    • Engine 4 (PADA): Protocol Admission for transaction processing");
    println!("    • Engine T (Tokenomics): Deterministic emission and fee system");
}

fn run_simple_validator(args: &[String]) -> Result<(), ExampleError> {
    let num_slots = if args.is_empty() {
        10
    } else {
        args[0].parse::<u64>()
            .map_err(|_| ExampleError::Other("Invalid number of slots".to_string()))?
    };
    
    println!("=== Simple Validator Demo ===");
    println!("Running validator for {} slots\n", num_slots);
    
    let mut validator = simple_validator::SimpleValidator::new()?;
    validator.run(num_slots)?;
    
    let stats = validator.get_stats();
    println!("\n=== Final Validator Statistics ===");
    println!("Current slot: {}", stats.current_slot);
    println!("Validator balance: {} IOTA", stats.balance);
    println!("Account nonce: {}", stats.nonce);
    println!("Total emitted: {} IOTA", stats.total_emitted);
    println!("Mempool size: {}", stats.mempool_size);
    
    if let Some(head) = stats.chain_head {
        println!("Chain head: {:?}", hex::encode(head));
    } else {
        println!("Chain head: None (genesis)");
    }
    
    if let Some(finalized) = stats.finalized_block {
        println!("Finalized block: {:?}", hex::encode(finalized));
    } else {
        println!("Finalized block: None");
    }
    
    println!("\nValidator demo completed successfully!");
    Ok(())
}

fn run_transaction_demo() -> Result<(), ExampleError> {
    transaction_demo::run_transaction_demo()
}

fn run_vdf_demo() -> Result<(), ExampleError> {
    vdf_demo::run_vdf_demo()
}

fn run_full_demo() -> Result<(), ExampleError> {
    full_protocol_demo::run_full_demo()
}