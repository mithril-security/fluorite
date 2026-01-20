// From <https://github.com/kinvolk/azure-cvm-tooling/tree/main>
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_cvm_vtpm::hcl::HclError;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tss_esapi::abstraction::{nv, pcr, pcr::PcrData};
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::{resource_handles::NvAuth, session_handles::AuthSession};
use tss_esapi::structures::{
    AttestInfo, Data, PcrSelectionList, PcrSlot, Signature, SignatureScheme,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
use tss_esapi::Context;

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const VTPM_AK_HANDLE: u32 = 0x81000003;

pub(crate) const ALL_8_SLOTS: &[PcrSlot; 8] = &[
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
];

pub(crate) const ALL_SLOTS: &[PcrSlot; 24] = &[
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum QuoteError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("data too large")]
    DataTooLarge,
    #[error("Not a quote, that should not occur")]
    NotAQuote,
    #[error("Wrong signature, that should not occur")]
    WrongSignature,
    #[error("PCR bank not found")]
    PcrBankNotFound,
    #[error("PCR reading error")]
    PcrRead,
}

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
}

#[derive(Debug, Clone)]
pub struct Quote {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcr_data: PcrData,
}

impl Quote {
    pub fn pcr_data(&self) -> PcrData {
        self.pcr_data.clone()
    }

    /// Extract message from a Quote
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

/// Get a signed vTPM Quote
///
/// # Arguments
///
/// * `data` - A byte slice to use as nonce
pub fn get_quote(data: &[u8], pcr_selection_list: PcrSelectionList) -> Result<Quote, QuoteError> {
    if data.len() > Data::MAX_SIZE {
        return Err(QuoteError::DataTooLarge);
    }
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;

    let quote_data: Data = data.try_into()?;
    let scheme = SignatureScheme::Null;

    let auth_session: AuthSession = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let (attest, signature) = context.quote(
        key_handle.into(),
        quote_data,
        scheme,
        pcr_selection_list.clone(),
    )?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err(QuoteError::NotAQuote);
    };
    let Signature::RsaSsa(ref rsa_sig) = signature else {
        return Err(QuoteError::WrongSignature);
    };
    let signature = rsa_sig.signature().to_vec();
    let message = attest.marshall()?;

    context.clear_sessions();
    let pcr_data = pcr::read_all(&mut context, pcr_selection_list)?;

    Ok(Quote {
        signature,
        message,
        pcr_data,
    })
}

/// Get a HCL report from an nvindex
pub fn get_report() -> Result<Vec<u8>, ReportError> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let report = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(report)
}
use serde_big_array::BigArray;

pub struct HclReport {
    bytes: Vec<u8>,
    attestation_report: AttestationReport,
    report_type: ReportType,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReportType {
    // Tdx,
    Snp,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
enum IgvmHashType {
    Invalid = 0,
    Sha256,
    Sha384,
    Sha512,
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct IgvmRequestData {
    data_size: u32,
    version: u32,
    report_type: u32,
    report_data_hash_type: IgvmHashType,
    variable_data_size: u32,
    variable_data: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct AttestationHeader {
    signature: u32,
    version: u32,
    report_size: u32,
    request_type: u32,
    status: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct AttestationReport {
    header: AttestationHeader,
    #[serde(with = "BigArray")]
    hw_report: [u8; SNP_REPORT_SIZE],
    hcl_data: IgvmRequestData,
}

use memoffset::offset_of;

use sev::firmware::guest::AttestationReport as SnpReport;

use std::mem::size_of;
use std::ops::Range;
// use thiserror::Error;

//const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
const SNP_REPORT_SIZE: usize = size_of::<SnpReport>();
//const fn max(a: usize, b: usize) -> usize {
//    if a > b {
//        return a;
//    }
//    b
//}
const SNP_REPORT_TYPE: u32 = 2;
//const TDX_REPORT_TYPE: u32 = 4;
const HW_REPORT_OFFSET: usize = offset_of!(AttestationReport, hw_report);
const fn report_range(report_size: usize) -> Range<usize> {
    HW_REPORT_OFFSET..(HW_REPORT_OFFSET + report_size)
}
// const TD_REPORT_RANGE: Range<usize> = report_range(TD_REPORT_SIZE);
const SNP_REPORT_RANGE: Range<usize> = report_range(SNP_REPORT_SIZE);

//pub enum HwReport {
//    // Tdx(TdReport),
//    Snp(SnpReport),
//}

impl HclReport {
    /// Parse a HCL report from a byte slice.
    pub fn new(bytes: Vec<u8>) -> Result<Self, HclError> {
        let attestation_report: AttestationReport = bincode::deserialize(&bytes)?;
        let report_type = match attestation_report.hcl_data.report_type {
            // TDX_REPORT_TYPE => ReportType::Tdx,
            SNP_REPORT_TYPE => ReportType::Snp,
            _ => return Err(HclError::InvalidReportType),
        };

        let report = Self {
            bytes,
            attestation_report,
            report_type,
        };
        Ok(report)
    }

    /// Get the type of the nested hardware report
    //pub fn report_type(&self) -> ReportType {
    //    self.report_type
    //}

    pub fn report_slice(&self) -> &[u8] {
        match self.report_type {
            ReportType::Snp => self.bytes[SNP_REPORT_RANGE].as_ref(),
        }
    }

    /// Get the slice of the VarData section
    pub fn var_data_slice(&self) -> &[u8] {
        let var_data_offset =
            offset_of!(AttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
        let hcl_data = &self.attestation_report.hcl_data;
        let var_data_end = var_data_offset + hcl_data.variable_data_size as usize;
        &self.bytes[var_data_offset..var_data_end]
    }
}
