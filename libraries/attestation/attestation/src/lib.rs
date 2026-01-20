#![feature(adt_const_params)]
#![feature(doc_notable_trait)]

pub mod cbor;
pub mod eventlog;
pub mod msg;

#[cfg(feature = "tss-esapi")]
pub use generate::*;

pub use verify::*;

#[cfg(feature = "tss-esapi")]
mod generate {
    use async_trait::async_trait;
    use tss_esapi::structures::PcrSelectionList;

    #[async_trait]
    #[doc(notable_trait)]
    pub trait AsyncGenerateAttestationDocument: Sized {
        type AttestationDocument;
        /// Generate an attestation document attesting to the selected PCR
        ///
        /// This function should only be run on the target platform.
        async fn generate_attestation_document(
            &mut self,
            pcr_selection_list: &PcrSelectionList,
        ) -> anyhow::Result<Self::AttestationDocument>;
    }
}

mod verify {
    use async_trait::async_trait;
    use rustls_pki_types::UnixTime;
    use tpm_quote::common::SanitizedPcrData;

    #[doc(notable_trait)]
    pub trait VerifyAttestationDocument {
        /// Verify an attestation document
        ///
        /// Returns PcrData, which represents the state of the selected PCR
        fn verify(&self, now: UnixTime) -> anyhow::Result<SanitizedPcrData>;
    }

    #[async_trait]
    #[doc(notable_trait)]
    pub trait AsyncVerifyAttestationDocument {
        /// Async verify for attestation Document
        ///
        /// Returns
        async fn verify(&self, now: UnixTime) -> anyhow::Result<SanitizedPcrData>;
    }
}
