use mithril_dwarf::*;
use risc0_zkvm::guest::env;

fn main() {
    // read the genesis key
    let start = env::cycle_count();
    let mut genesis_key = [0u8; 32];
    env::read_slice(&mut genesis_key);
    let end = env::cycle_count();
    eprintln!("read genesis key: {}", end - start);

    // read the certificate input1
    let start = env::cycle_count();
    let len: usize = env::read();
    let mut input_1 = vec![0u8; len];
    env::read_slice(&mut input_1);
    let end = env::cycle_count();
    eprintln!("read certificate 1: {}", end - start);

    let start = env::cycle_count();
    let cert = certificate_from_bytes(&input_1).expect("Failed to parse certificate 1");
    let end = env::cycle_count();
    eprintln!("parse certificate 1: {}", end - start);

    // read the certificate input2
    let start = env::cycle_count();
    let len: usize = env::read();
    let mut input_2 = vec![0u8; len];
    env::read_slice(&mut input_2);
    let prev_cert = certificate_from_bytes(&input_2).expect("Failed to parse certificate 2");
    let end = env::cycle_count();
    eprintln!("read and parse certificate 2: {}", end - start);

    // Business Logic
    let start = env::cycle_count();
    verify_certificate(&cert, Some(&prev_cert), &genesis_key).expect(&format!(
        "Failed to verify certificate 1, hash: '{:?}' against predecessor certificate 2, hash: '{:?}'",
        cert.hash, prev_cert.hash
    ));
    let end = env::cycle_count();
    eprintln!("verify_standard_certificate: {}", end - start);

    // write public output to the journal
    env::commit(&cert.hash);
}
