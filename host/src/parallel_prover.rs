// Host orchestration for parallel Mithril certificate proving
// Uses custom byte parsing for maximum efficiency (no serde)
use anyhow::anyhow;
use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, error, info};
use mithril_dwarf::Ed25519VerificationKey;
use oakshield_common::{CertificateStepOutput, ChainProofOutput};
use risc0_zkvm::{default_prover, Digest, ExecutorEnv, ProverOpts, Receipt};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::task;

use methods::{OAKSHIELD_ELF, OAKSHIELD_ID};

/// Receipt with metadata for tracking
#[derive(Debug, Clone)]
pub struct CertificateReceipt {
    pub receipt: Receipt,
    pub output: CertificateStepOutput,
    pub proving_time_secs: f64,
}

impl CertificateReceipt {
    /// Serialize to custom binary format
    /// Format: [proving_time: 8][output: 96][receipt_len: 8][receipt_bytes: var]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // Serialize receipt using RISC0's built-in serialization
        let receipt_bytes = bincode::serialize(&self.receipt)?;
        let receipt_len = receipt_bytes.len();

        let output_bytes = self.output.to_bytes();

        let mut result = Vec::new();
        result.extend_from_slice(&self.proving_time_secs.to_le_bytes());
        result.extend_from_slice(&output_bytes);
        result.extend_from_slice(&receipt_len.to_le_bytes());
        result.extend_from_slice(&receipt_bytes);

        Ok(result)
    }

    /// Deserialize from custom binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 + 96 + 8 {
            anyhow::bail!("Invalid receipt file: too short");
        }

        let mut pos = 0;

        // Parse proving_time
        let mut proving_time_bytes = [0u8; 8];
        proving_time_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        let proving_time_secs = f64::from_le_bytes(proving_time_bytes);
        pos += 8;

        // Parse output
        let output = CertificateStepOutput::from_bytes(&bytes[pos..pos + 96])?;
        pos += 96;

        // Parse receipt length
        let mut receipt_len_bytes = [0u8; 8];
        receipt_len_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        let receipt_len = u64::from_le_bytes(receipt_len_bytes) as usize;
        pos += 8;

        // Parse receipt
        if bytes.len() < pos + receipt_len {
            anyhow::bail!("Invalid receipt file: receipt data truncated");
        }
        let receipt: Receipt = bincode::deserialize(&bytes[pos..pos + receipt_len])?;

        Ok(Self {
            receipt,
            output,
            proving_time_secs,
        })
    }
}

/// Configuration for parallel proving
#[derive(Clone)]
pub struct ProvingConfig {
    pub genesis_key: Option<Ed25519VerificationKey>,
    pub num_workers: usize,
    pub receipt_dir: PathBuf,
    pub enable_disk_backup: bool,
    pub retry_on_failure: bool,
    pub max_retries: usize,
}

impl Default for ProvingConfig {
    fn default() -> Self {
        Self {
            genesis_key: None,
            num_workers: 8,
            receipt_dir: PathBuf::from("./receipts"),
            enable_disk_backup: true,
            retry_on_failure: true,
            max_retries: 3,
        }
    }
}

/// Main coordinator for parallel proving
pub struct ParallelProver {
    config: ProvingConfig,
    multi_progress: MultiProgress,
}

impl ParallelProver {
    pub fn new(config: ProvingConfig) -> Result<Self> {
        // Create receipt directory if it doesn't exist
        if config.enable_disk_backup {
            fs::create_dir_all(&config.receipt_dir)?;
        }

        Ok(Self {
            config,
            multi_progress: MultiProgress::new(),
        })
    }

    /// Prove entire certificate chain in parallel
    pub async fn prove_chain<C>(
        &self,
        certificates: Vec<C>,
        certificate_elf: &[u8],
    ) -> Result<Vec<CertificateReceipt>>
    where
        C: CertificateProver + Clone + Send + 'static,
    {
        let total_certs = certificates.len();
        info!("\n=== Starting Parallel Certificate Proving ===");
        info!("Total certificates: {}", total_certs);
        info!("Workers: {}", self.config.num_workers);
        info!("Disk backup: {}", self.config.enable_disk_backup);
        println!(); // Keep blank line for readability

        let start_time = Instant::now();

        let remaining_certs: Vec<(String, String, C)> = certificates
            .iter()
            .map(|c| (c.hash(), c.previous_hash(), c.clone()))
            .collect();

        info!("Certificates to prove: {}", remaining_certs.len());
        println!();

        let new_receipts = self
            .prove_certificates_parallel(remaining_certs, certificate_elf)
            .await?;

        let all_receipts = sort_by_hash_chain(new_receipts)?;

        let total_time = start_time.elapsed();

        info!("\n=== Proving Summary ===");
        info!("Total certificates: {}", all_receipts.len());
        info!("Total time: {:.2?}", total_time);
        info!(
            "Average per cert: {:.2?}",
            total_time / all_receipts.len() as u32
        );

        let proving_times: Vec<f64> = all_receipts.iter().map(|r| r.proving_time_secs).collect();
        let avg_time = proving_times.iter().sum::<f64>() / proving_times.len() as f64;
        let min_time = proving_times.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_time = proving_times
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        info!("Proving time stats:");
        info!("  Average: {:.2}s", avg_time);
        info!("  Min: {:.2}s", min_time);
        info!("  Max: {:.2}s", max_time);
        println!();

        Ok(all_receipts)
    }

    /// Prove certificates in parallel
    async fn prove_certificates_parallel<C>(
        &self,
        certificates: Vec<(String, String, C)>,
        certificate_elf: &[u8],
    ) -> Result<Vec<CertificateReceipt>>
    where
        C: CertificateProver + Clone + Send + 'static,
    {
        let total = certificates.len();
        let certificates_per_worker =
            (total + self.config.num_workers - 1) / self.config.num_workers;

        // Create progress bars
        let main_pb = self.multi_progress.add(ProgressBar::new(total as u64));
        main_pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▓▒░ "),
        );
        main_pb.set_message("Proving certificates");

        // Split work among workers
        let mut handles = Vec::new();

        for worker_id in 0..self.config.num_workers {
            let start_idx = worker_id * certificates_per_worker;
            let end_idx = std::cmp::min(start_idx + certificates_per_worker, total);

            if start_idx >= total {
                break;
            }

            let worker_certs: Vec<(String, String, C)> = certificates[start_idx..end_idx].to_vec();

            let mut dependencies = Vec::<(String, String, C)>::new();
            for c in &worker_certs {
                if c.1 == "" {
                    // Genesis Certificate does not store its own hash ?????
                    continue;
                }
                if let Some(_) = worker_certs.iter().find(|x| c.1 == x.0) {
                    continue;
                } else {
                    if let Some(prev_c) = certificates.iter().find(|x| c.1 == x.0) {
                        dependencies.push(prev_c.clone());
                    } else {
                        return Err(anyhow!(
                            "A previous Certificate is missing for '{}', looking for '{}'!",
                            c.0,
                            c.1
                        ));
                    }
                }
            }
            debug!(
                "Worker {}: Proving {} certs, with {} dependencies available",
                worker_id,
                worker_certs.len(),
                dependencies.len()
            );
            //let worker_certs = [worker_certs, missing].concat();
            let elf = certificate_elf.to_vec();
            let config = self.config.clone();
            let pb = main_pb.clone();

            // Create worker progress bar
            let worker_pb = self
                .multi_progress
                .add(ProgressBar::new(worker_certs.len() as u64));
            worker_pb.set_style(
                ProgressStyle::default_bar()
                    .template(&format!(
                        "Worker {} [{{elapsed_precise}}] {{bar:30.green/yellow}} {{pos}}/{{len}}",
                        worker_id
                    ))
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            let handle = task::spawn_blocking(move || {
                Self::prove_batch(
                    worker_id,
                    worker_certs,
                    dependencies,
                    &elf,
                    config,
                    pb,
                    worker_pb,
                )
            });

            handles.push(handle);
        }

        // Collect results
        let mut all_receipts = Vec::new();
        for handle in handles {
            let batch_receipts = handle.await.context("Worker task failed")??;
            all_receipts.extend(batch_receipts);
        }

        main_pb.finish_with_message("✓ All certificates proved");

        Ok(all_receipts)
    }

    /// Prove a batch of certificates (runs on single worker/GPU)
    fn prove_batch<C>(
        worker_id: usize,
        certificates: Vec<(String, String, C)>,
        dependencies: Vec<(String, String, C)>,
        elf: &[u8],
        config: ProvingConfig,
        main_pb: ProgressBar,
        worker_pb: ProgressBar,
    ) -> Result<Vec<CertificateReceipt>>
    where
        C: CertificateProver,
    {
        let mut receipts = Vec::new();

        for (current_hash, previous_hash, cert) in certificates.iter() {
            worker_pb.set_message(format!("Cert {}", worker_id));

            let (genesis_key, prev_cert) = if cert.previous_hash() == "".to_string() {
                (config.genesis_key, None)
            } else if let Some(prev_cert) = certificates.iter().find(|x| x.0 == *previous_hash) {
                (None, Some(&prev_cert.2))
            } else if let Some(prev_cert) = dependencies.iter().find(|x| x.0 == *previous_hash) {
                (None, Some(&prev_cert.2))
            } else {
                return Err(anyhow!("No previous certificate found but this is not a genesis certificate: Hash: '{}', Prev Hash: '{}'",current_hash,previous_hash));
            };

            let mut attempt = 0;
            let result = loop {
                attempt += 1;

                match Self::prove_single_certificate(genesis_key, prev_cert, cert, elf) {
                    Ok(receipt) => break Ok(receipt),
                    Err(_) if config.retry_on_failure && attempt < config.max_retries => {
                        worker_pb.set_message(format!(
                            "Cert {} (retry {}/{})",
                            current_hash, attempt, config.max_retries
                        ));
                        continue;
                    }
                    Err(e) => break Err(e),
                }
            };

            let cert_receipt =
                result.context(format!("Failed to prove certificate {}", current_hash))?;

            // Save to disk if enabled
            if config.enable_disk_backup {
                // Use first 8 bytes of hash for filename
                let hash_prefix = &cert_receipt.output.current_hash[..8];
                let filename = format!(
                    "cert_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    hash_prefix[0],
                    hash_prefix[1],
                    hash_prefix[2],
                    hash_prefix[3],
                    hash_prefix[4],
                    hash_prefix[5],
                    hash_prefix[6],
                    hash_prefix[7]
                );
                let receipt_path = config.receipt_dir.join(filename);
                Self::save_receipt(&cert_receipt, &receipt_path)?;
            }

            receipts.push(cert_receipt);
            worker_pb.inc(1);
            main_pb.inc(1);
        }

        worker_pb.finish_with_message(format!("✓ Worker {} complete", worker_id));

        Ok(receipts)
    }

    /// Prove a single certificate
    fn prove_single_certificate<C>(
        genesis: Option<Ed25519VerificationKey>,
        prev_cert: Option<&C>,
        cert: &C,
        elf: &[u8],
    ) -> Result<CertificateReceipt>
    where
        C: CertificateProver,
    {
        if let Some(pv) = prev_cert {
            if cert.previous_hash() != pv.hash() {
                error!("Hash mismatch in certificate chain!");
                panic!("Hash mismatch!")
            }
        }

        let start = Instant::now();
        let mut env_builder = ExecutorEnv::builder();

        if let Some(genessis_key) = genesis {
            env_builder.write(&0u32)?;
            debug!("HOST: Writing genesis key (32 bytes)");
            env_builder.write_slice(genessis_key.as_bytes());
        } else {
            if let Some(pcert) = prev_cert {
                env_builder.write(&1u32)?;
                debug!("HOST: Writing prev_cert");
                pcert.write_to_env(&mut env_builder)?;
            } else {
                return Err(anyhow!(
                    "Previous Certificate Missing but no genesis key given!"
                ));
            }
        }

        debug!("HOST: Writing current cert");
        cert.write_to_env(&mut env_builder)?;

        let env = env_builder.build()?;

        let prover = default_prover();
        let opts = ProverOpts::succinct();
        let prove_info = prover.prove_with_opts(env, elf, &opts)?;
        let receipt = prove_info.receipt;

        let journal_bytes = &receipt.journal.bytes;
        let output = CertificateStepOutput::from_bytes(journal_bytes)?;

        let proving_time = start.elapsed();

        Ok(CertificateReceipt {
            receipt,
            output,
            proving_time_secs: proving_time.as_secs_f64(),
        })
    }

    /// Compose all receipts into final chain proof
    pub fn compose_chain(
        &self,
        mut receipts: Vec<CertificateReceipt>,
        composition_elf: &[u8],
    ) -> Result<(Receipt, ChainProofOutput)> {
        println!("\n=== Starting Proof Composition ===");
        println!("Composing {} receipts", receipts.len());

        let start = Instant::now();

        // Reverse to backwards order: [Tip, ..., Genesis]
        receipts.reverse();

        // Validate chain linkage BEFORE composition
        validate_receipt_chain_backwards(&receipts)
            .context("Chain validation failed before composition")?;

        // Extract journals in backwards order
        let journals: Vec<Vec<u8>> = receipts
            .iter()
            .map(|r| r.receipt.journal.bytes.clone())
            .collect();

        info!("Extracted {} journals (Tip -> Genesis)", journals.len());

        // Debug: Check journal sizes
        for (idx, journal) in journals.iter().enumerate() {
            debug!("Journal {}: {} bytes", idx, journal.len());
        }

        // Create malicous / wrong ordered journals block
        //let mut mal_journals = journals.clone();
        //mal_journals[1] = journals.get(0).unwrap().clone();
        //let journals = mal_journals.clone();

        // Build composition environment
        let mut env_builder = ExecutorEnv::builder();

        // Step 1: Add all receipts as assumptions (available for env::verify)
        for cert_receipt in &receipts {
            env_builder.add_assumption(cert_receipt.receipt.clone());
        }

        // Step 2: Write journals Vec (composition guest reads this)
        env_builder.write(&journals)?;

        let env = env_builder.build()?;

        info!("Proving composition with Groth16 (this may take several minutes)...");

        // Prove composition with Groth16
        let prover = default_prover();
        let opts = ProverOpts::groth16().with_control_ids(vec![Digest::from(OAKSHIELD_ID)]);
        let prove_info = prover.prove_with_opts(env, composition_elf, &opts)?;
        let receipt = prove_info.receipt;

        let composition_time = start.elapsed();
        info!("✓ Composition complete: {:.2?}", composition_time);

        // Parse composed output
        let journal_bytes = receipt.journal.bytes.as_slice();
        let chain_output = ChainProofOutput::from_bytes(journal_bytes)?;

        info!("\n=== Composition Result ===");
        info!("Genesis hash: {:02x?}...", &chain_output.genesis_hash[..4]);
        info!("Tip hash: {:02x?}...", &chain_output.tip_hash[..4]);
        info!("Certificate count: {}", chain_output.certificate_count);
        info!(
            "Protocol messages: {}",
            chain_output.tip_protocol_messages.len()
        );

        Ok((receipt, chain_output))
    }

    /// Save receipt to disk (custom binary format)
    fn save_receipt(receipt: &CertificateReceipt, path: &Path) -> Result<()> {
        let bytes = receipt.to_bytes()?;
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    /// Load receipt from disk
    fn load_receipt(&self, path: &Path) -> Result<CertificateReceipt> {
        let mut file = File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        CertificateReceipt::from_bytes(&bytes)
    }
}

/// Trait that certificates must implement for custom serialization
pub trait CertificateProver {
    /// Write certificate data to executor environment
    fn write_to_env(&self, env: &mut risc0_zkvm::ExecutorEnvBuilder) -> Result<()>;

    /// Extracts Certificate Hash
    fn hash(&self) -> String;

    /// Extracts Previous Certificate Hash
    fn previous_hash(&self) -> String;
}

/// Sort receipts by following the hash chain
/// Returns receipts in order: genesis -> cert1 -> cert2 -> ... -> tip
fn sort_by_hash_chain(mut receipts: Vec<CertificateReceipt>) -> Result<Vec<CertificateReceipt>> {
    if receipts.is_empty() {
        return Ok(receipts);
    }

    if receipts.len() == 1 {
        return Ok(receipts);
    }

    // Build hash -> receipt lookup
    use std::collections::HashMap;
    let mut by_current_hash: HashMap<[u8; 32], CertificateReceipt> = HashMap::new();
    for receipt in receipts {
        by_current_hash.insert(receipt.output.current_hash, receipt);
    }

    // Find genesis (certificate whose previous_hash doesn't match any current_hash)
    // OR has all-zero previous_hash
    let mut genesis: Option<CertificateReceipt> = None;

    for (_, receipt) in by_current_hash.iter() {
        let is_genesis = receipt.output.previous_hash == None;

        if is_genesis {
            if genesis.is_some() {
                anyhow::bail!("Multiple genesis certificates found");
            }
            genesis = Some(receipt.clone());
        }
    }

    let genesis = genesis.context("No genesis certificate found")?;

    // Build chain by following hash links
    let mut ordered = Vec::with_capacity(by_current_hash.len());
    let mut current = genesis;

    loop {
        let current_hash = current.output.current_hash;
        ordered.push(current);

        // Find next certificate (one whose previous_hash = current_hash)
        let next = by_current_hash
            .iter()
            .find(|(_, r)| r.output.previous_hash == Some(current_hash))
            .map(|(_, r)| r.clone());

        match next {
            Some(next_cert) => {
                current = next_cert.clone();
            }
            None => {
                // Reached the end of chain
                break;
            }
        }
    }

    // Verify we got all receipts (no orphans)
    if ordered.len() != by_current_hash.len() {
        anyhow::bail!(
            "Chain incomplete: got {} receipts but only {} connected in chain. \
             Possible orphaned certificates or broken chain.",
            by_current_hash.len(),
            ordered.len()
        );
    }

    Ok(ordered)
}

/// Validate receipt chain in backwards order (Tip -> Genesis)
/// Checks that each certificate's previous_hash links to the next certificate's current_hash
fn validate_receipt_chain_backwards(receipts: &[CertificateReceipt]) -> Result<()> {
    if receipts.is_empty() {
        anyhow::bail!("Empty receipt chain");
    }

    info!(
        "Validating backwards chain linkage for {} receipts",
        receipts.len()
    );

    // receipts = [Tip, Cert_n-1, ..., Genesis]
    for i in 0..receipts.len() - 1 {
        let current = &receipts[i];
        let next = &receipts[i + 1];

        // Current cert's previous_hash should match next cert's current_hash
        match current.output.previous_hash {
            Some(prev_hash) => {
                if prev_hash != next.output.current_hash {
                    anyhow::bail!(
                        "Chain linkage broken at position {}: \
                         current.previous_hash ({:02x?}...) != next.current_hash ({:02x?}...)",
                        i,
                        &prev_hash[..4],
                        &next.output.current_hash[..4]
                    );
                }
            }
            None => {
                anyhow::bail!(
                    "Certificate at position {} has None previous_hash but is not genesis",
                    i
                );
            }
        }
    }

    // Verify genesis (last element) has None previous_hash
    let genesis = receipts.last().unwrap();
    if genesis.output.previous_hash.is_some() {
        anyhow::bail!("Genesis certificate must have None previous_hash");
    }

    info!("✓ Backwards chain validation passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
}
