// Command-line tool for parallel Mithril certificate proving
// Run with: cargo run --release --bin mithril-prover -- [options]
use anyhow::anyhow;
use anyhow::{Context, Result};
use clap::Parser;

use mithril_dwarf::ProtocolGenesisVerificationKey;
use mithril_dwarf::{Ed25519VerificationKey, MithrilCertificateVerifier};

use std::path::PathBuf;
use std::time::Instant;

// Import your modules
pub mod helpers;
pub mod parallel_prover;
use oakshield_common::ChainProofOutput;
use parallel_prover::{ParallelProver, ProvingConfig};

use crate::helpers::create_cert_receiver;
use crate::helpers::is_genesis;
use crate::helpers::{get_certificate, Network};
use log::{debug, info, trace, warn};
use methods::OAKSHIELD_ELF;
use methods_comp::OAKSHIELD_COMP_ELF;
use mithril_dwarf::{parser::certificate_to_bytes, Certificate, CertificateVerifier};

use risc0_zkvm::guest::env;

#[derive(Parser)]
#[command(name = "mithril-prover")]
#[command(version = "0.1.0")]
#[command(about = "Parallel Mithril certificate chain proving with RISC0", long_about = None)]
struct Cli {
    /// Mithril aggregator URL
    #[arg(long, default_value = "MAINNET", env = "MITHRIL_NETWORK")]
    network: String,

    /// Certificate Hash. the tip you want to proof
    #[arg(long)]
    certificate_hash: String,

    /// Max certificates to fetch
    #[arg(long, default_value = "1000")]
    max_certificates: usize,

    /// Number of parallel workers (GPUs)
    #[arg(long, short = 'w', default_value = "4")]
    workers: usize,

    /// Directory to store receipt backups
    #[arg(long, default_value = "./receipts")]
    receipt_dir: PathBuf,

    /// Disable disk backup (keep only in memory)
    #[arg(long, default_value = "true")]
    no_disk_backup: bool,

    /// Maximum retry attempts per certificate
    #[arg(long, default_value = "3")]
    max_retries: usize,

    /// Output file for final Groth16 proof
    #[arg(long, short = 'o', default_value = "./chain_proof.bin")]
    output: PathBuf,

    /// Output file for public inputs (JSON)
    #[arg(long, default_value = "./public_inputs.json")]
    public_inputs: PathBuf,

    /// Limit number of certificates to prove (for testing)
    #[arg(long)]
    limit: Option<usize>,

    /// Skip composition (only prove certificates)
    #[arg(long, default_value = "false")]
    skip_composition: bool,

    /// Verbose logging
    #[arg(long, short = 'v', default_value = "false")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    print_banner();

    let total_start = Instant::now();

    let network = Network::from_str(&cli.network);

    // Step 1: Fetch certificates
    println!("\n📥 Step 1: Fetching certificates from Mithril aggregator");
    println!("URL: {}", network.get_aggregator_url());

    let mut certificates = fetch_certificates(
        &network,
        &cli.certificate_hash,
        &cli.max_certificates,
        &cli.output,
    )
    .await
    .context("Failed to fetch certificates from Mithril aggregator")?;

    println!("✓ Fetched {} certificates", certificates.len());

    // Apply limit if specified
    if let Some(limit) = cli.limit {
        if limit < certificates.len() {
            println!("⚠ Limiting to first {} certificates (--limit)", limit);
            certificates.truncate(limit);
        }
    }

    // Step 2: Validate chain
    println!("\n🔍 Step 2: Validating certificate chain");
    validate_chain(&certificates, &cli.certificate_hash, &network).await?;
    println!("✓ Chain validation passed");

    let genesis_key = Some(Ed25519VerificationKey::from_json_hex(
        network.get_genesis_key(),
    )?);

    // Step 3: Setup proving configuration
    let config = ProvingConfig {
        genesis_key,
        num_workers: cli.workers,
        receipt_dir: cli.receipt_dir.clone(),
        enable_disk_backup: !cli.no_disk_backup,
        retry_on_failure: true,
        max_retries: cli.max_retries,
    };

    println!("\n⚙️  Configuration:");
    println!("  Workers: {}", config.num_workers);
    println!("  Disk backup: {}", config.enable_disk_backup);
    println!("  Max retries: {}", config.max_retries);

    let prover = ParallelProver::new(config).context("Failed to initialize parallel prover")?;

    // Step 4: Parallel proving
    println!("\n⚡ Step 3: Proving certificates in parallel");
    let proving_start = Instant::now();

    let receipts = prover
        .prove_chain(certificates, OAKSHIELD_ELF)
        .await
        .context("Certificate proving failed")?;

    let proving_time = proving_start.elapsed();
    println!("\n✓ Proving complete!");
    println!("  Total time: {:.2?}", proving_time);
    println!("  Certificates: {}", receipts.len());
    println!(
        "  Average: {:.2?} per certificate",
        proving_time / receipts.len() as u32
    );

    if cli.skip_composition {
        println!("\n⏭️  Skipping composition (--skip-composition)");
        println!("✓ Receipts saved to: {}", cli.receipt_dir.display());
        return Ok(());
    }

    // Step 5: Composition
    println!("\n🔗 Step 4: Composing proofs");
    let composition_start = Instant::now();

    let (groth16_receipt, chain_output) = prover
        .compose_chain(receipts, OAKSHIELD_COMP_ELF)
        .context("Proof composition failed")?;

    let composition_time = composition_start.elapsed();
    println!("✓ Composition complete: {:.2?}", composition_time);

    // Step 6: Save outputs
    println!("\n💾 Step 5: Saving outputs");

    // Save Groth16 proof (binary)
    let proof_bytes =
        bincode::serialize(&groth16_receipt).context("Failed to serialize Groth16 proof")?;
    std::fs::write(&cli.output, &proof_bytes).context("Failed to write Groth16 proof")?;

    println!(
        "✓ Groth16 proof: {} ({} bytes)",
        cli.output.display(),
        proof_bytes.len()
    );

    // Save public inputs (JSON)
    let public_inputs_json = serde_json::json!({
        "genesis_hash": format_hash(&chain_output.genesis_hash),
        "tip_hash": format_hash(&chain_output.tip_hash),
        //"tip_transaction_merkle_root": format_hash(&chain_output.tip_transaction_merkle_root),
        "certificate_count": chain_output.certificate_count,
        "proving_time_secs": proving_time.as_secs_f64(),
        "composition_time_secs": composition_time.as_secs_f64(),
        "total_time_secs": total_start.elapsed().as_secs_f64(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    std::fs::write(
        &cli.public_inputs,
        serde_json::to_string_pretty(&public_inputs_json)?,
    )
    .context("Failed to write public inputs")?;

    println!("✓ Public inputs: {}", cli.public_inputs.display());

    // Print final summary
    print_summary(
        &chain_output,
        proving_time,
        composition_time,
        total_start.elapsed(),
        proof_bytes.len(),
    );

    Ok(())
}

fn print_banner() {
    println!(
        r#"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║       RISC0 Mithril Parallel Chain Prover                ║
║       Version 1.0.0                                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    "#
    );
}

fn print_summary(
    output: &ChainProofOutput,
    proving_time: std::time::Duration,
    composition_time: std::time::Duration,
    total_time: std::time::Duration,
    proof_size: usize,
) {
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║                   PROVING COMPLETE                        ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("\n📊 Summary:");
    println!("  Certificates: {}", output.certificate_count);
    println!("  Proving time: {:.2?}", proving_time);
    println!("  Composition time: {:.2?}", composition_time);
    println!("  Total time: {:.2?}", total_time);
    println!("\n🔐 Chain Hashes:");
    println!("  Genesis: {}", format_hash(&output.genesis_hash));
    println!("  Tip: {}", format_hash(&output.tip_hash));
    println!(
        "  Tip Protocol Message: {:?}",
        &output.tip_protocol_messages
    );
    println!("\n📦 Proof:");
    println!("  Size: {} bytes", proof_size);
    println!("  Format: Groth16");
    println!("\n✅ Ready for verification!");
}

fn format_hash(hash: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3], hash[28], hash[29], hash[30], hash[31]
    )
}

/// Fetch certificates from Mithril aggregator
async fn fetch_certificates(
    network: &Network,
    certificate_hash: &str,
    max_certificates: &usize,
    output_dir: &PathBuf,
) -> Result<Vec<Certificate>> {
    info!("Connecting to aggregator...");

    let client = helpers::make_mithril_client(network)?;
    let mut certificates = Vec::<Certificate>::new();

    let mut current_hash = certificate_hash.to_string();
    let mut certificates_fetched = 0;
    let mut genesis_reached = false;

    info!("📥 Fetching certificate chain (walking backward to genesis)...\n");

    loop {
        if certificates_fetched >= *max_certificates {
            warn!(
                "⚠️  Reached maximum certificate limit ({})",
                max_certificates
            );
            warn!("   Use --max-certificates to increase the limit");
            break;
        }

        debug!("[{}] Fetching: {}", certificates_fetched + 1, current_hash);

        let cert_msg = get_certificate(&client, &current_hash)
            .await?
            .ok_or_else(|| anyhow!("Certificate not found: {}", current_hash))?;

        let cert: Certificate = cert_msg.clone().try_into()?;

        if is_genesis(&cert_msg)? {
            info!("   ✅ Genesis certificate reached!");
            certificates.push(cert);
            genesis_reached = true;
            certificates_fetched += 1;
            break;
        }

        let previous_hash = cert_msg.previous_hash.clone();

        debug!("   Certificate Hash: {}", &previous_hash);

        certificates.push(cert);
        certificates_fetched += 1;

        current_hash = previous_hash;
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Summary:");
    println!("   Certificates fetched: {}", certificates_fetched);
    println!(
        "   Genesis reached:      {}",
        if genesis_reached { "✅ Yes" } else { "❌ No" }
    );
    println!("   Output directory:     {}", output_dir.display());

    if !genesis_reached {
        warn!("\n⚠️  Warning: Genesis certificate was not reached!");
        warn!("   The chain may be incomplete.");
    }

    println!("\n✅ Certificate chain fetched successfully!");

    Ok(certificates)
}

/// Validate certificate chain locally (fast host-side check)
async fn validate_chain(
    certificates: &[Certificate],
    start_hash: &str,
    network: &Network,
) -> Result<()> {
    use anyhow::bail;

    if certificates.is_empty() {
        bail!("Empty certificate chain");
    }

    info!("Validating {} certificates...", certificates.len());

    let start_cert = certificates
        .iter()
        .find(|x| x.hash == start_hash)
        .ok_or(anyhow!("Start Certificate not found"))?;

    let genesis_key = ProtocolGenesisVerificationKey::from_json_hex(network.get_genesis_key())?;
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let retriever = std::sync::Arc::new(create_cert_receiver(certificates));
    let verifier = MithrilCertificateVerifier::new(logger, retriever);
    verifier
        .verify_certificate_chain(start_cert.clone(), &genesis_key)
        .await?;

    Ok(())
}

// Implement Certificate trait for your type
impl parallel_prover::CertificateProver for Certificate {
    fn write_to_env(&self, env: &mut risc0_zkvm::ExecutorEnvBuilder) -> Result<()> {
        let bytes = certificate_to_bytes(&self);
        let len = bytes.len();

        trace!("  HOST write_to_env: length = {}", len);
        env.write(&len)?;
        env.write_slice(&bytes);

        Ok(())
    }

    fn hash(&self) -> String {
        self.hash.clone()
    }

    fn previous_hash(&self) -> String {
        self.previous_hash.clone()
    }
}
