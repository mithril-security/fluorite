use core::convert::TryFrom;
use core::fmt;
use digest::generic_array::{ArrayLength, GenericArray};
pub use pcr::slot::PcrSlot;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::IfIsHumanReadable;
use std::{collections::BTreeMap, ops::Deref};
use thiserror::Error;
use tpm_structs::Tpm2bDigest;

mod constants;
mod error;
pub mod pcr;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Quote {
    /// A marshalled TPMS_ATTEST
    /// The struct that is signed by the TPM AK
    #[serde_as(as = "IfIsHumanReadable<serde_with::base64::Base64>")]
    pub message: Vec<u8>,
    /// A marshalled TPMT_SIGNATURE
    #[serde_as(as = "IfIsHumanReadable<serde_with::base64::Base64>")]
    pub signature: Vec<u8>,
    /// PcrData, a struct holding the values of all selected PCRs
    /// Needed because a TPM2 Quote does not contain the values of the selected PCR
    /// It only contains a composite digest (a digest of the concatenation of the selected PCR values)
    pub pcr_data: PcrData,
}

impl Quote {
    pub fn message(self) -> Vec<u8> {
        self.message
    }

    pub fn signature(self) -> Vec<u8> {
        self.signature
    }
}

/// Struct holding pcr banks and their associated
/// hashing algorithm
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PcrData {
    pub data: Vec<(HashingAlgorithm, PcrBank)>,
}

/// PcrData where all digests have the appropriate length
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedPcrData(pub(crate) PcrData);

impl PcrData {
    pub fn is_subset(&self, other: &Self) -> bool {
        self.data.iter().all(|(alg, bank)| {
            other.pcr_bank(*alg).is_some_and(|other_bank| {
                bank.bank.iter().all(|(slot, digest)| {
                    other_bank
                        .bank
                        .get(slot)
                        .is_some_and(|other_digest| digest == other_digest)
                })
            })
        })
    }
}

impl Deref for SanitizedPcrData {
    type Target = PcrData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PcrData {
    /// Function for retrieving the first PCR values associated with hashing_algorithm.
    pub fn pcr_bank(&self, hashing_algorithm: HashingAlgorithm) -> Option<&PcrBank> {
        self.data
            .iter()
            .find(|(alg, _)| *alg == hashing_algorithm)
            .map(|(_, bank)| bank)
    }
}

#[cfg(feature = "generate")]
impl From<tss_esapi::abstraction::pcr::PcrData> for PcrData {
    fn from(item: tss_esapi::abstraction::pcr::PcrData) -> Self {
        PcrData {
            data: item
                .into_iter()
                .map(|(alg, bank)| (HashingAlgorithm::from(alg), PcrBank::from(bank)))
                .collect(),
        }
    }
}

/// Enum containing the supported hash algorithms
///
/// # Details
/// This corresponds to TPMI_ALG_HASH interface type.
// #[serde_as]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "generate", derive(o2o::o2o))]
#[cfg_attr(
    feature = "generate",
    map(tss_esapi::interface_types::algorithm::HashingAlgorithm)
)]
pub enum HashingAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Null,
}

impl From<tpm_structs::TpmiAlgHash> for HashingAlgorithm {
    fn from(value: tpm_structs::TpmiAlgHash) -> Self {
        match value {
            tpm_structs::TpmiAlgHash::Sha1 => Self::Sha1,
            tpm_structs::TpmiAlgHash::Sha256 => Self::Sha256,
            tpm_structs::TpmiAlgHash::Sha384 => Self::Sha384,
            tpm_structs::TpmiAlgHash::Sha512 => Self::Sha512,
            tpm_structs::TpmiAlgHash::Sm3_256 => Self::Sm3_256,
            tpm_structs::TpmiAlgHash::Sha3_256 => Self::Sha3_256,
            tpm_structs::TpmiAlgHash::Sha3_384 => Self::Sha3_384,
            tpm_structs::TpmiAlgHash::Sha3_512 => Self::Sha3_512,
        }
    }
}

impl HashingAlgorithm {
    /// Size in bytes of the digest of the hashing algorithm
    pub fn digest_size(self) -> u8 {
        match self {
            HashingAlgorithm::Sha1 => 20,
            HashingAlgorithm::Sha256 => 32,
            HashingAlgorithm::Sha384 => 48,
            HashingAlgorithm::Sha512 => 64,
            HashingAlgorithm::Sm3_256 => 32,
            HashingAlgorithm::Sha3_256 => 32,
            HashingAlgorithm::Sha3_384 => 48,
            HashingAlgorithm::Sha3_512 => 64,
            HashingAlgorithm::Null => 0,
        }
    }
}

/// Struct for holding PcrSlots and their
/// corresponding values.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PcrBank {
    pub bank: BTreeMap<PcrSlot, Digest>,
}

#[cfg(feature = "generate")]
impl From<tss_esapi::abstraction::pcr::PcrBank> for PcrBank {
    fn from(item: tss_esapi::abstraction::pcr::PcrBank) -> Self {
        PcrBank {
            bank: item
                .into_iter()
                .map(|(slot, digest)| (PcrSlot::from(slot), Digest(digest.to_vec())))
                .collect(),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct Digest(#[serde_as(as = "IfIsHumanReadable<serde_with::hex::Hex>")] pub Vec<u8>);

impl From<Tpm2bDigest<'_>> for Digest {
    fn from(value: Tpm2bDigest) -> Self {
        Digest(value.buffer.to_vec())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Error)]
#[error("length error")]
pub struct LengthError;

impl<U: ArrayLength<u8>> TryFrom<&Digest> for GenericArray<u8, U> {
    type Error = LengthError;

    fn try_from(value: &Digest) -> Result<Self, Self::Error> {
        let len = U::to_usize();
        if value.0.len() == len {
            let mut array = GenericArray::default();
            array.copy_from_slice(&value.0[..]);
            Ok(array)
        } else {
            Err(LengthError)
        }
    }
}

pub struct PcrIndex {
    pub bank: HashingAlgorithm,
    pub pcr_slot: PcrSlot,
}
