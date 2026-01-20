#![feature(doc_notable_trait)]

//! Attestation for Google Cloud Platform (GCP) platforms

mod common;
pub use common::*;

#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "generate")]
pub(crate) mod generate;

#[cfg(feature = "generate")]
pub use generate::*;

// Re-export tss-esapi types needed for generating attestation documents
#[cfg(feature = "generate")]
pub use tss_esapi::interface_types::algorithm::HashingAlgorithm as TssHashingAlgorithm;
#[cfg(feature = "generate")]
pub use tss_esapi::structures::PcrSelectionList;
#[cfg(feature = "generate")]
pub use tss_esapi::structures::PcrSlot;
