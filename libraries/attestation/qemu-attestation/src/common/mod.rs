pub const VTPM_AK_HANDLE: u32 = 0x81000003;
pub const VTPM_AK_CERT_NVINDEX: u32 = 0x01C101D0;

use serde::{Deserialize, Serialize};

use serde_with::{IfIsHumanReadable, serde_as};
use tpm_quote::common::Quote;

pub const QEMU_VTPM_ROOT_CA_PEM: &[u8] = include_bytes!("ca.cert.pem");
pub const QEMU_VTPM_INTERMEDIATE_CA_PEM: &[u8] = include_bytes!("intermediate_ca.crt");

/// Attestation document for an QEMU VM.
///
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QEMUVmAttestationDocument {
    pub quote: Quote,
    /// Attestation Key (AK) certificate chain of an QEMU VM
    /// DER-encoded certificates, ordered from leaf to root.
    #[serde_as(as = "Vec<IfIsHumanReadable<serde_with::base64::Base64>>")]
    pub ak_cert_chain: Vec<Vec<u8>>,
}
