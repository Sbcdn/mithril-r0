// Helper functions
use anyhow::anyhow;
use anyhow::Error as AppError;
use async_trait::async_trait;
use mithril_dwarf::{
    CardanoTransactionsProofs, Certificate, CertificateMessage, CertificateRetriever,
    CertificateRetrieverError, Client, ClientBuilder,
};

pub(crate) fn make_mithril_client(network: &Network) -> Result<Client, AppError> {
    ClientBuilder::aggregator(network.get_aggregator_url(), network.get_genesis_key())
        .build()
        .map_err(|e| e.into())
}

/// Check if a certificate is genesis
pub(crate) fn is_genesis(cert: &CertificateMessage) -> Result<bool, AppError> {
    let c: Certificate = cert.clone().try_into()?;
    Ok(c.is_genesis())
}

pub(crate) async fn get_transaction_proof(
    client: &Client,
    tx_hash: &str,
) -> Result<CardanoTransactionsProofs, AppError> {
    client
        .cardano_transaction()
        .get_proofs(&[tx_hash])
        .await
        .map_err(|e| e.into())
}

pub(crate) async fn get_certificate(
    client: &Client,
    certificate_hash: &str,
) -> Result<Option<CertificateMessage>, AppError> {
    client
        .certificate()
        .get(certificate_hash)
        .await
        .map_err(|e| e.into())
}

#[derive(Debug)]
pub enum Network {
    Preview,
    Preprod,
    Mainnet,
}

impl Network {
    pub fn from_str(str: &str) -> Self {
        match str {
            "Preview" | "preview" => Network::Preview,
            "Preprod" | "preprod" => Network::Preprod,
            _ => Network::Mainnet,
        }
    }

    pub fn get_genesis_key(&self) -> &str {
        match self {
            Self::Preview => {
                "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d"
            }
            Self::Preprod => {
                "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d"
            }
            Self::Mainnet => {
                "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d"
            }
        }
    }

    pub fn get_aggregator_url(&self) -> &str {
        match self {
            Self::Preview => {
                "https://aggregator.pre-release-preview.api.mithril.network/aggregator"
            }
            Self::Preprod => "https://aggregator.release-preprod.api.mithril.network/aggregator",
            Self::Mainnet => "https://aggregator.release-mainnet.api.mithril.network/aggregator",
        }
    }
}

pub struct PCertificateRetriever {
    certificates: Vec<Certificate>,
}

#[async_trait]
impl CertificateRetriever for PCertificateRetriever {
    async fn get_certificate_details(
        &self,
        certificate_hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        if let Some(r) = self
            .certificates
            .iter()
            .find(|&c| c.hash == certificate_hash)
        {
            Ok(r.clone())
        } else {
            Err(CertificateRetrieverError(anyhow!("Certificate not found")))
        }
    }
}
pub fn create_cert_receiver(certificates: &[Certificate]) -> PCertificateRetriever {
    PCertificateRetriever {
        certificates: certificates.to_vec(),
    }
}
