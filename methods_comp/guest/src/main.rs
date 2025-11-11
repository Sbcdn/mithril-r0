#![no_main]

use risc0_zkvm::guest::env;
use methods::OAKSHIELD_ID;
use oakshield_common::{CertificateStepOutput, ChainProofOutput};
risc0_zkvm::guest::entry!(main);

fn main() {
    let start = env::cycle_count();
    eprintln!("Starting composition guest");
    
    // Read all journals (in backwards order: Tip -> Genesis)
    let journals: Vec<Vec<u8>> = env::read();

    let cert_count = journals.len();
    assert!(cert_count > 0, "Empty certificate chain");
    
    let end = env::cycle_count();
    eprintln!("Read {} journals in {} cycles", cert_count, end - start);

    // Debug: Check first journal structure
    if journals.len() > 0 {
        let first = &journals[0];
        eprintln!("First journal: {} bytes", first.len());
        if first.len() >= 8 {
            eprintln!("  First 8 bytes: {:02x?}", &first[..8]);
        }
    }

    // Parse all certificate outputs
    let start = env::cycle_count();
    let mut outputs: Vec<CertificateStepOutput> = Vec::with_capacity(cert_count);
    
    for (idx, journal) in journals.iter().enumerate() {
        eprintln!("Parsing journal {}: {} bytes", idx, journal.len());
        
        match CertificateStepOutput::from_bytes(journal) {
            Ok(output) => {
                eprintln!("  Parsed: control={}, msgs={}", 
                    if output.previous_hash.is_some() { 1 } else { 0 },
                    output.protocol_messages.len()
                );
                outputs.push(output);
            }
            Err(e) => {
                env::log(&format!("FAILED to parse journal {}: {}", idx, e));
                env::log(&format!("  Journal length: {}", journal.len()));
                if journal.len() >= 32 {
                    env::log(&format!("  First 32 bytes: {:02x?}", &journal[..32]));
                }
                panic!("Journal parsing failed at index {}: {}", idx, e);
            }
        }
    }
    
    let end = env::cycle_count();
    eprintln!("Parsed {} certificates in {} cycles", outputs.len(), end - start);

    // Use the hardcoded OAKSHIELD image ID
    let image_id = OAKSHIELD_ID;

    // Verify each certificate receipt (adds assumptions)
    let start = env::cycle_count();
    for (idx, journal) in journals.iter().enumerate() {
        let v = env::verify(image_id, journal)
            .expect(&format!("Receipt verification failed at position {}", idx));
        eprintln!("Verification Result: {:?}",v);
    }
    let end = env::cycle_count();
    eprintln!("Verified {} receipts in {} cycles", journals.len(), end - start);

    // Verify backwards chain linkage: outputs[i].previous_hash == outputs[i+1].current_hash
    let start = env::cycle_count();
    for i in 0..outputs.len() - 1 {
        let current = &outputs[i];
        let next = &outputs[i + 1];

        match current.previous_hash {
            Some(prev_hash) => {
                assert_eq!(
                    prev_hash, next.current_hash,
                    "Chain link broken at position {}: prev_hash != next.current_hash",
                    i
                );
            }
            None => {
                panic!("Certificate at position {} has None previous_hash but is not genesis", i);
            }
        }
    }

    // Verify genesis (last element) has None previous_hash
    let genesis = outputs.last().unwrap();
    assert!(
        genesis.previous_hash.is_none(),
        "Genesis certificate must have None previous_hash"
    );
    
    let end = env::cycle_count();
    eprintln!("Verified chain linkage in {} cycles", end - start);

    // Extract tip and genesis
    let start = env::cycle_count();
    let tip = &outputs[0];
    let genesis_hash = genesis.current_hash;
    let tip_hash = tip.current_hash;
    let tip_protocol_messages = tip.protocol_messages.clone();

    // Build and commit the aggregated chain proof
    let chain_output = ChainProofOutput {
        genesis_hash,
        tip_hash,
        tip_protocol_messages,
        certificate_count: cert_count as u64,
    };

    // Commit output as bytes
    let output_bytes = chain_output.to_bytes();
    env::commit_slice(&output_bytes);
    
    let end = env::cycle_count();
    eprintln!("Built and committed chain output in {} cycles", end - start);
    
    eprintln!(
        "Composition complete: {} certificates verified from tip to genesis",
        cert_count
    );
}