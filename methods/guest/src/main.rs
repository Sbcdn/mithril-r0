use mithril_dwarf::*;
use risc0_zkvm::guest::env;

fn main() {
    let start = env::cycle_count();
    // Read Execution Flaf
    let control_bytes : u32 = env::read();

    let mut cert_bytes = Vec::new();
    let mut prev_cert_bytes = Vec::new();
    let mut genesis_key = None;

    let (cert, prev_cert) = match control_bytes {
        0 => {
            let mut gk = [0u8; 32];
            env::read_slice(&mut gk);
            genesis_key = Some(gk);
            
            cert_bytes = read_certificate();
            let cert = certificate_from_bytes(&cert_bytes).expect("Failed to parse certificate 1");
            (cert, None)
        },
        1 => {         
            let len = env::read();
            
            prev_cert_bytes = vec![0u8; len];
            env::read_slice(&mut prev_cert_bytes);
            let prev_cert = certificate_from_bytes(&prev_cert_bytes)
                .expect("Failed to parse previous certificate");
                        
            cert_bytes = read_certificate();
            let cert = certificate_from_bytes(&cert_bytes)
                .expect("Failed to parse certificate 1");

            (cert, Some(prev_cert))
        },
        _ => panic!("wrong argument")
    };
    let end = env::cycle_count();
    eprintln!("Read Inputs in {} cycles", end - start);

    // Business Logic
    let start = env::cycle_count();
    verify_certificate(&cert, prev_cert.as_ref(), genesis_key.as_ref()).expect(&format!(
        "Failed to verify certificate, hash: '{:?}'",
        cert.hash
    ));
    let end = env::cycle_count();
    eprintln!("Verify certificates in {} cycles", end - start);
  



    let start = env::cycle_count();
    // Build custom journal format
    let mut journal = Vec::new();

    // Control flag (4 bytes, u32)
    let control_flag: u32 = if prev_cert.is_some() { 1 } else { 0 };
    journal.extend_from_slice(&control_flag.to_le_bytes());
    //eprintln!("GUEST: control_flag = {}", control_flag);

    // Previous hash if present (32 bytes)
    if let Some(pc) = &prev_cert {
        journal.extend_from_slice(&pc.hash);
        eprintln!("GUEST: wrote prev_hash, total_len = {}", journal.len());
    }

    // Current hash (32 bytes)
    journal.extend_from_slice(&cert.hash);
    ////eprintln!("GUEST: wrote current_hash, total_len = {}", journal.len());

    // Message count (4 bytes, u32)
    let msg_count = cert.protocol_message.parts.len() as u32;
    journal.extend_from_slice(&msg_count.to_le_bytes());
    ////eprintln!("GUEST: msg_count = {}, total_len = {}", msg_count, journal.len());

    // Each message (4 bytes length + data)
    for (idx, message) in cert.protocol_message.parts.iter().enumerate() {
        let len = message.1.len() as u32;
        journal.extend_from_slice(&len.to_le_bytes());
        journal.extend_from_slice(&message.1);
        //eprintln!("GUEST: message[{}] len = {}, total_len = {}", idx, len, journal.len());
    }

    ////eprintln!("GUEST: Final journal length = {}", journal.len());
    
    // Commit the journal as raw bytes
    env::commit_slice(&journal);
    
    let end = env::cycle_count();
    eprintln!("Write Outputs in {} cycles", end - start);
}


fn read_certificate() -> Vec<u8> {
    let len = env::read();
    let mut input_1 = vec![0u8; len];
    env::read_slice(&mut input_1);
    input_1
}