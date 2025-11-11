#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use anyhow::{bail, Result};

/// Output from individual certificate proofs (variable size)
/// Layout: [control_flag: 4][previous_hash: 32 (if flag=1)][current_hash: 32][msg_count: 4][messages...]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "std", derive(PartialEq))]
pub struct CertificateStepOutput {
    pub previous_hash: Option<[u8; 32]>,
    pub current_hash: [u8; 32],
    pub protocol_messages: Vec<Vec<u8>>,
}

impl CertificateStepOutput {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0;

        // Safety check
        if bytes.len() < 4 {
            bail!("Journal too short for control flag");
        }

        // Read control flag (4 bytes, u32)
        let control_bytes: [u8; 4] = bytes[pos..pos + 4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to read control flag"))?;
        let control_flag = u32::from_le_bytes(control_bytes);
        pos += 4;

        // Read previous hash if present (64 bytes hex string -> convert to 32 bytes binary)
        let previous_hash = if control_flag == 1 {
            if pos + 64 > bytes.len() {
                bail!(
                    "Journal too short for previous_hash: need {} bytes, have {}",
                    pos + 64,
                    bytes.len()
                );
            }
            let hash_hex = &bytes[pos..pos + 64];
            let hash_binary = Self::hex_to_bytes(hash_hex)?;
            pos += 64;
            Some(hash_binary)
        } else {
            None
        };

        // Read current hash (64 bytes hex string -> convert to 32 bytes binary)
        if pos + 64 > bytes.len() {
            bail!(
                "Journal too short for current_hash: need {} bytes, have {}",
                pos + 64,
                bytes.len()
            );
        }
        let hash_hex = &bytes[pos..pos + 64];
        let current_hash = Self::hex_to_bytes(hash_hex)?;
        pos += 64;

        // Read message count (4 bytes)
        if pos + 4 > bytes.len() {
            bail!(
                "Journal too short for message count: need {} bytes, have {}",
                pos + 4,
                bytes.len()
            );
        }
        let count_bytes: [u8; 4] = bytes[pos..pos + 4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to read message count"))?;
        let message_count = u32::from_le_bytes(count_bytes) as usize;
        pos += 4;

        // Read messages
        let mut protocol_messages = Vec::new();
        for i in 0..message_count {
            if pos + 4 > bytes.len() {
                bail!(
                    "Journal too short for message[{}] length: need {} bytes, have {}",
                    i,
                    pos + 4,
                    bytes.len()
                );
            }

            let len_bytes: [u8; 4] = bytes[pos..pos + 4]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to read message[{}] length", i))?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            pos += 4;

            if pos + len > bytes.len() {
                bail!(
                "Journal too short for message[{}] data: need {} bytes (pos {} + len {}), have {} bytes total",
                i, pos + len, pos, len, bytes.len()
            );
            }

            let message = bytes[pos..pos + len].to_vec();
            pos += len;

            protocol_messages.push(message);
        }

        Ok(Self {
            previous_hash,
            current_hash,
            protocol_messages,
        })
    }

    /// Convert hex string (64 ASCII chars) to binary (32 bytes)
    fn hex_to_bytes(hex: &[u8]) -> Result<[u8; 32]> {
        if hex.len() != 64 {
            bail!("Invalid hex string length: expected 64, got {}", hex.len());
        }

        let mut result = [0u8; 32];
        for i in 0..32 {
            let high = Self::hex_char_to_nibble(hex[i * 2])?;
            let low = Self::hex_char_to_nibble(hex[i * 2 + 1])?;
            result[i] = (high << 4) | low;
        }
        Ok(result)
    }

    /// Convert hex ASCII character to nibble value (0-15)
    fn hex_char_to_nibble(c: u8) -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => bail!("Invalid hex character: {}", c as char),
        }
    }

    /// Convert to bytes (for serialization)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write control flag (4 bytes, u32)
        let control_flag: u32 = if self.previous_hash.is_some() { 1 } else { 0 };
        bytes.extend_from_slice(&control_flag.to_le_bytes());

        // Write previous hash if present (32 bytes binary)
        if let Some(prev_hash) = &self.previous_hash {
            bytes.extend_from_slice(prev_hash);
        }

        // Write current hash (32 bytes binary)
        bytes.extend_from_slice(&self.current_hash);

        // Write message count (4 bytes, u32)
        let msg_count = self.protocol_messages.len() as u32;
        bytes.extend_from_slice(&msg_count.to_le_bytes());

        // Write each message (4 bytes length + data)
        for message in &self.protocol_messages {
            let len = message.len() as u32;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(message);
        }

        bytes
    }
}

/// Final aggregated output for the entire chain
/// Layout: [genesis_hash: 32][tip_hash: 32][cert_count: 8][msg_count: 4][messages...]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "std", derive(PartialEq))]
pub struct ChainProofOutput {
    pub genesis_hash: [u8; 32],
    pub tip_hash: [u8; 32],
    pub tip_protocol_messages: Vec<Vec<u8>>,
    pub certificate_count: u64,
}

impl ChainProofOutput {
    /// Convert to bytes with variable-length protocol messages
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write fixed fields
        bytes.extend_from_slice(&self.genesis_hash);
        bytes.extend_from_slice(&self.tip_hash);
        bytes.extend_from_slice(&self.certificate_count.to_le_bytes());

        // Write protocol messages count
        let msg_count = self.tip_protocol_messages.len() as u32;
        bytes.extend_from_slice(&msg_count.to_le_bytes());

        // Write each message (length-prefixed)
        for message in &self.tip_protocol_messages {
            let len = message.len() as u32;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(message);
        }

        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 + 32 + 8 + 4 {
            bail!(
                "ChainProofOutput too short: need at least {} bytes, have {}",
                32 + 32 + 8 + 4,
                bytes.len()
            );
        }

        let mut pos = 0;

        // Read genesis_hash
        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        // Read tip_hash
        let mut tip_hash = [0u8; 32];
        tip_hash.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        // Read certificate_count
        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        let certificate_count = u64::from_le_bytes(count_bytes);
        pos += 8;

        // Read message count
        let mut msg_count_bytes = [0u8; 4];
        msg_count_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        let msg_count = u32::from_le_bytes(msg_count_bytes) as usize;
        pos += 4;

        // Read protocol messages
        let mut tip_protocol_messages = Vec::new();
        for i in 0..msg_count {
            if pos + 4 > bytes.len() {
                bail!("Message[{}] length truncated", i);
            }

            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(len_bytes) as usize;
            pos += 4;

            if pos + len > bytes.len() {
                bail!("Message[{}] data truncated", i);
            }

            let message = bytes[pos..pos + len].to_vec();
            pos += len;

            tip_protocol_messages.push(message);
        }

        Ok(Self {
            genesis_hash,
            tip_hash,
            tip_protocol_messages,
            certificate_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_output_roundtrip() {
        let output = CertificateStepOutput {
            previous_hash: Some([1u8; 32]),
            current_hash: [2u8; 32],
            protocol_messages: vec![vec![3, 4, 5], vec![6, 7]],
        };

        let bytes = output.to_bytes();
        let parsed = CertificateStepOutput::from_bytes(&bytes).unwrap();

        assert_eq!(output.previous_hash, parsed.previous_hash);
        assert_eq!(output.current_hash, parsed.current_hash);
        assert_eq!(output.protocol_messages, parsed.protocol_messages);
    }

    #[test]
    fn test_chain_output_roundtrip() {
        let output = ChainProofOutput {
            genesis_hash: [1u8; 32],
            tip_hash: [2u8; 32],
            tip_protocol_messages: vec![vec![3, 4, 5], vec![6, 7]],
            certificate_count: 42,
        };

        let bytes = output.to_bytes();
        let parsed = ChainProofOutput::from_bytes(&bytes).unwrap();

        assert_eq!(output.genesis_hash, parsed.genesis_hash);
        assert_eq!(output.tip_hash, parsed.tip_hash);
        assert_eq!(output.tip_protocol_messages, parsed.tip_protocol_messages);
        assert_eq!(output.certificate_count, parsed.certificate_count);
    }
}
