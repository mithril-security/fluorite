// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// use crate::{tss2_esys::TPM2_PCR_SELECT_MAX, Error, Result, WrapperErrorKind};
use crate::common::{
    constants::TPM2_PCR_SELECT_MAX,
    error::{Result, WrapperErrorKind},
};

use enumflags2::bitflags;
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Enum with the bit flag for each PCR slot.
#[bitflags]
#[repr(u32)]
#[derive(
    Serialize,
    Deserialize,
    FromPrimitive,
    ToPrimitive,
    Hash,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Clone,
    Copy,
    std::marker::ConstParamTy,
)]
#[cfg_attr(feature = "generate", derive(o2o::o2o))]
#[cfg_attr(feature = "generate", map(tss_esapi::structures::pcr_slot::PcrSlot))]
pub enum PcrSlot {
    Slot0 = 0x0000_0001,
    Slot1 = 0x0000_0002,
    Slot2 = 0x0000_0004,
    Slot3 = 0x0000_0008,
    Slot4 = 0x0000_0010,
    Slot5 = 0x0000_0020,
    Slot6 = 0x0000_0040,
    Slot7 = 0x0000_0080,
    Slot8 = 0x0000_0100,
    Slot9 = 0x0000_0200,
    Slot10 = 0x0000_0400,
    Slot11 = 0x0000_0800,
    Slot12 = 0x0000_1000,
    Slot13 = 0x0000_2000,
    Slot14 = 0x0000_4000,
    Slot15 = 0x0000_8000,
    Slot16 = 0x0001_0000,
    Slot17 = 0x0002_0000,
    Slot18 = 0x0004_0000,
    Slot19 = 0x0008_0000,
    Slot20 = 0x0010_0000,
    Slot21 = 0x0020_0000,
    Slot22 = 0x0040_0000,
    Slot23 = 0x0080_0000,
    Slot24 = 0x0100_0000,
    Slot25 = 0x0200_0000,
    Slot26 = 0x0400_0000,
    Slot27 = 0x0800_0000,
    Slot28 = 0x1000_0000,
    Slot29 = 0x2000_0000,
    Slot30 = 0x4000_0000,
    Slot31 = 0x8000_0000,
}

impl From<PcrSlot> for u32 {
    fn from(pcr_slot: PcrSlot) -> u32 {
        pcr_slot.to_u32().unwrap()
    }
}

impl TryFrom<u32> for PcrSlot {
    type Error = WrapperErrorKind;

    fn try_from(value: u32) -> Result<PcrSlot> {
        PcrSlot::from_u32(value).ok_or_else(|| {
            error!("{} is not valid PcrSlot value", value);
            WrapperErrorKind::InvalidParam
        })
    }
}

impl From<PcrSlot> for [u8; TPM2_PCR_SELECT_MAX as usize] {
    fn from(pcr_slot: PcrSlot) -> [u8; TPM2_PCR_SELECT_MAX as usize] {
        u32::from(pcr_slot).to_le_bytes()
    }
}

impl TryFrom<[u8; TPM2_PCR_SELECT_MAX as usize]> for PcrSlot {
    type Error = WrapperErrorKind;

    fn try_from(tss_pcr_slot: [u8; TPM2_PCR_SELECT_MAX as usize]) -> Result<PcrSlot> {
        PcrSlot::try_from(u32::from_le_bytes(tss_pcr_slot))
    }
}

#[cfg(feature = "generate")]
impl From<PcrSlot> for tss_esapi::handles::PcrHandle {
    fn from(value: PcrSlot) -> Self {
        use tss_esapi::handles::PcrHandle;

        match value {
            PcrSlot::Slot0 => PcrHandle::Pcr0,
            PcrSlot::Slot1 => PcrHandle::Pcr1,
            PcrSlot::Slot2 => PcrHandle::Pcr2,
            PcrSlot::Slot3 => PcrHandle::Pcr3,
            PcrSlot::Slot4 => PcrHandle::Pcr4,
            PcrSlot::Slot5 => PcrHandle::Pcr5,
            PcrSlot::Slot6 => PcrHandle::Pcr6,
            PcrSlot::Slot7 => PcrHandle::Pcr7,
            PcrSlot::Slot8 => PcrHandle::Pcr8,
            PcrSlot::Slot9 => PcrHandle::Pcr9,
            PcrSlot::Slot10 => PcrHandle::Pcr10,
            PcrSlot::Slot11 => PcrHandle::Pcr11,
            PcrSlot::Slot12 => PcrHandle::Pcr12,
            PcrSlot::Slot13 => PcrHandle::Pcr13,
            PcrSlot::Slot14 => PcrHandle::Pcr14,
            PcrSlot::Slot15 => PcrHandle::Pcr15,
            PcrSlot::Slot16 => PcrHandle::Pcr16,
            PcrSlot::Slot17 => PcrHandle::Pcr17,
            PcrSlot::Slot18 => PcrHandle::Pcr18,
            PcrSlot::Slot19 => PcrHandle::Pcr19,
            PcrSlot::Slot20 => PcrHandle::Pcr20,
            PcrSlot::Slot21 => PcrHandle::Pcr21,
            PcrSlot::Slot22 => PcrHandle::Pcr22,
            PcrSlot::Slot23 => PcrHandle::Pcr23,
            PcrSlot::Slot24 => PcrHandle::Pcr24,
            PcrSlot::Slot25 => PcrHandle::Pcr25,
            PcrSlot::Slot26 => PcrHandle::Pcr26,
            PcrSlot::Slot27 => PcrHandle::Pcr27,
            PcrSlot::Slot28 => PcrHandle::Pcr28,
            PcrSlot::Slot29 => PcrHandle::Pcr29,
            PcrSlot::Slot30 => PcrHandle::Pcr30,
            PcrSlot::Slot31 => PcrHandle::Pcr31,
        }
    }
}
