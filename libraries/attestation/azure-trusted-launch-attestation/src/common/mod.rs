pub const VTPM_AK_HANDLE: u32 = 0x81000003;
pub const VTPM_AK_CERT_NVINDEX: u32 = 0x01C101D0;

use serde::{Deserialize, Serialize};

use serde_with::IfIsHumanReadable;
use serde_with::serde_as;
use tpm_quote::common::Quote;

pub const AZURE_VTPM_ROOT_CA_PEM: &[u8] =
    include_bytes!("Azure Virtual TPM Root Certificate Authority 2023.crt");
pub const AZURE_VTPM_INTERMEDIATE_CA_PEM: &[&[u8]] = &[
    include_bytes!("intermediate_ca_01.crt"),
    include_bytes!("intermediate_ca_03.crt"),
];

/// Attestation document for an Azure Trusted Launch VM.
///
/// For more information about Azure Trusted Launch VMs, please refer to
/// [Azure documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq).
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustedLaunchVmAttestationDocument {
    pub quote: Quote,
    /// Attestation Key (AK) certificate chain of an Azure Trusted Launch VM
    /// DER-encoded certificates, ordered from leaf to root.
    #[serde_as(as = "Vec<IfIsHumanReadable<serde_with::base64::Base64>>")]
    pub ak_cert_chain: Vec<Vec<u8>>,
}
