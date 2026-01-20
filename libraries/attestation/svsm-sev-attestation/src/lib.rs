#![feature(doc_notable_trait)]

//! Attestation for AMD SEV-SNP platforms

mod common;
pub use common::*;

#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "generate")]
pub(crate) mod generate;

#[cfg(feature = "generate")]
pub use generate::*;
