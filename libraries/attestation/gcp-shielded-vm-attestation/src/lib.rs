#![feature(doc_notable_trait)]

//! Attestation for Google Cloud Platform (GCP) Shielded VMs
//!
//! GCP Shielded VMs have vTPMs with measured boot but their Attestation Keys (AK)
//! are not backed by an official certificate chain like CVMs. This library provides
//! attestation support by using a notarizer service (running on a CVM) to endorse
//! the Shielded VM's attestation key.
//!
//! ## Verification Chain
//!
//! 1. Verify the notarizer's CVM attestation (proves it runs on genuine CVM hardware)
//! 2. Verify the notarizer's event log to extract the signing key
//! 3. Verify the notarizer signed the Shielded VM's identity
//! 4. Extract the AK public key from the signed identity
//! 5. Verify the vTPM quote was signed by that endorsed AK
//!
//! ## Usage
//!
//! ### Verification
//!
//! ```ignore
//! use gcp_shielded_vm_attestation::ShieldedVmAttestationDocument;
//! use attestation::VerifyAttestationDocument;
//! use rustls_pki_types::UnixTime;
//!
//! let attestation_doc: ShieldedVmAttestationDocument = /* deserialize from JSON/CBOR */;
//! let pcr_data = attestation_doc.verify(UnixTime::now())?;
//! ```
//!
//! ### Generation (on a Shielded VM)
//!
//! The endorsement must be stored in instance metadata under the key `notarizer-endorsement`
//! (or a custom key). The generator fetches it from the metadata server automatically.
//!
//! ```ignore
//! use gcp_shielded_vm_attestation::ShieldedVmAttestationDocumentGenerator;
//! use attestation::AsyncGenerateAttestationDocument;
//!
//! // Use default metadata key "notarizer-endorsement"
//! let mut generator = ShieldedVmAttestationDocumentGenerator::new()?;
//!
//! // Or specify a custom metadata key
//! let mut generator = ShieldedVmAttestationDocumentGenerator::with_metadata_key(
//!     "my-custom-key".to_string()
//! )?;
//!
//! let attestation_doc = generator.generate_attestation_document(&pcr_selection_list).await?;
//! ```

mod common;
pub use common::*;

#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "generate")]
mod generate;

#[cfg(feature = "generate")]
pub use generate::*;

// Re-export useful types from dependencies
pub use gcp_cvm_attestation::CvmAttestationDocument;
pub use tpm_quote::common::Quote;

#[cfg(feature = "generate")]
pub use tss_esapi::interface_types::algorithm::HashingAlgorithm as TssHashingAlgorithm;
#[cfg(feature = "generate")]
pub use tss_esapi::structures::PcrSelectionList;
#[cfg(feature = "generate")]
pub use tss_esapi::structures::PcrSlot;
