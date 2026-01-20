//! Generate a quote.
//!
//! # Example
//! ```
//! # use tpm_quote::generate::*;
//! use tss_esapi::structures::PcrSelectionList;
//! use tss_esapi::interface_types::algorithm::HashingAlgorithm;
//! use tss_esapi::structures::PcrSlot;
//!
//!
//! # fn generate_quote_example() -> anyhow::Result<()> {
//! let mut tpm_ctx = tpm_context()?;
//!
//! let mut ak_handle = AttestationKeyHandle::create_from_template_at_nvindex(
//!     &mut tpm_ctx,
//!     0x01c10002.try_into()?,
//! )?;
//!
//! let pcr_selections = PcrSelectionList::builder()
//!     .with_selection(
//!         HashingAlgorithm::Sha256,
//!         &[PcrSlot::Slot0],
//!     )
//!     .build()?;
//!
//! let quote = ak_handle.quote(&pcr_selections)?;
//! # Ok(())
//! # }
//! ```
//!

use crate::common::Quote;
use anyhow::{bail, Context as _};
use fn_error_context::context;
use std::str::FromStr as _;
use tss_esapi::abstraction::nv;
use tss_esapi::abstraction::pcr::{self};
use tss_esapi::handles::{KeyHandle, NvIndexTpmHandle, TpmHandle};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::structures::PcrSelectionList;
use tss_esapi::structures::{Data, SignatureScheme};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};

///  Create a TPM Context (used as an interface to the TPM)
pub fn tpm_context() -> anyhow::Result<tss_esapi::Context> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?);
    let ctx = tss_esapi::Context::new(conf)?;
    Ok(ctx)
}

/// Handle to a TPM AK that can be used to sign quotes
pub struct AttestationKeyHandle<'a> {
    key_handle: tss_esapi::handles::KeyHandle,
    ctx: &'a mut tss_esapi::Context,
}

impl<'a> AttestationKeyHandle<'a> {
    /// Use an existing AK handle persisted at a Tpm Index
    #[context(move, "AttestationKeyHandle::from_tpm_handle failed")]
    pub fn from_tpm_handle(
        ctx: &'a mut tss_esapi::Context,
        tpm_handle: TpmHandle,
    ) -> anyhow::Result<Self> {
        let key_handle = KeyHandle::try_from(ctx.tr_from_tpm_public(tpm_handle)?)?;
        Ok(AttestationKeyHandle {
            key_handle: key_handle,
            ctx: ctx,
        })
    }

    /// Create an AK handle from a template stored at an NvIndex.
    #[context(move, "AttestationKeyHandle::create_from_template_at_nvindex failed")]
    pub fn create_from_template_at_nvindex(
        ctx: &'a mut tss_esapi::Context,
        nv_index: NvIndexTpmHandle,
    ) -> anyhow::Result<Self> {
        // Get AK Template from NVRAM
        let ak_template =
            ctx.execute_with_nullauth_session(|ctx| nv::read_full(ctx, NvAuth::Owner, nv_index))?;
        let ak_template_ = tss_esapi::structures::Public::unmarshall(&ak_template)?;

        // Create AK Key
        let primary_res = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ak_template_, None, None, None, None)
        })?;
        Ok(AttestationKeyHandle {
            key_handle: primary_res.key_handle,
            ctx: ctx,
        })
    }

    /// Generate a quote attesting to the selected PCR with the AK.
    #[context("AttestationKeyHandle::quote failed")]
    pub fn quote(&mut self, selection_list: &PcrSelectionList) -> anyhow::Result<Quote> {
        let ctx = &mut self.ctx;
        let key_handle: tss_esapi::handles::KeyHandle = self.key_handle;

        let pcr_data_before =
            pcr::read_all(ctx, selection_list.clone()).context("pcr::read_all failed")?;

        // Generate a quote on the selected PCR signed by the attestation key
        let (attest, signature) = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.quote(
                    key_handle,
                    Data::default(),
                    SignatureScheme::Null,
                    selection_list.clone(),
                )
            })
            .context("ctx.quote failed")?;

        let pcr_data_after =
            pcr::read_all(ctx, selection_list.clone()).context("pcr::read_all failed")?;

        if pcr_data_before != pcr_data_after {
            bail!(
                "PCR values changed during quote generation process. You can rerun the function."
            );
        }

        let quote = Quote {
            signature: signature
                .marshall()
                .context("Failed to marshall Signature")?,
            message: attest.marshall().context("Failed to marshall Attest")?,
            pcr_data: pcr_data_after.into(),
        };

        log::info!("{:?}", &quote);

        Ok(quote)
    }
}
