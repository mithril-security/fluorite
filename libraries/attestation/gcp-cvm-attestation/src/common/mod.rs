/// NV Index of the GCP RSA AK certificate
pub const AKCERT_NVINDEX_RSA: u32 = 0x01c10000;

/// NV Index of the GCP RSA AK template
pub const AKTEMPLATE_NVINDEX_RSA: u32 = 0x01c10001;

/// NV Index of the GCP ECC AK certificate
pub const AKCERT_NVINDEX_ECC: u32 = 0x01c10002;

/// NV Index of the GCP ECC AK template
pub const AKTEMPLATE_NVINDEX_ECC: u32 = 0x01c10003;

use serde::{Deserialize, Serialize};

use serde_with::{serde_as, IfIsHumanReadable};
use tpm_quote::common::Quote;

pub const GCP_AK_ROOT_CA_DER: &[u8] = include_bytes!("gcp_ak_root_ca.crt");

/// Attestation document for GCP Confidential VM.
///
/// For more information about Confidential VMs, see the
/// [Google Cloud documentation](https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview).
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CvmAttestationDocument {
    pub quote: Quote,
    /// Attestation Key (AK) certificate chain of a GCE Confidential VM.
    /// DER-encoded certificates, ordered from leaf to root.
    #[serde_as(as = "Vec<IfIsHumanReadable<serde_with::base64::Base64>>")]
    pub ak_cert_chain: Vec<Vec<u8>>,
}
