//
// SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

use anyhow::{ensure, Context};
use byte_string::{ByteStr, ByteString};
use hex::{self};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::utils::SIGNATURE_LENGTH;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct DmtfMeasurement {
    /*  The class to represent the DMTF Measurement.
    The structure of the Measurement when MeasurementSpecification field is bit 0 = DMTF in DMTF's SPDM 1.1 spec.
    OFFSET - FIELD                        - SIZE(in bytes)
    0      - DMTFSpecMeasurementValueType - 1
    1      - DMTFSpecMeasurementValueSize - 2
    3      - DMTFSpecMeasurementValue     - DMTFSpecMeasurementValueSize
    */
    dmtfspec_measurement_value_type: Option<u8>,
    dmtfspec_measurement_value_size: Option<usize>,
    dmtfspec_measurement_value: Option<Vec<u8>>,
    field_size: HashMap<String, usize>,
}

impl Default for DmtfMeasurement {
    fn default() -> Self {
        DmtfMeasurement {
            dmtfspec_measurement_value_type: None,
            dmtfspec_measurement_value_size: None,
            dmtfspec_measurement_value: None,
            field_size: HashMap::from([
                ("DMTFSpecMeasurementValueType".to_string(), 1),
                ("DMTFSpecMeasurementValueSize".to_string(), 2),
            ]),
        }
    }
}

impl DmtfMeasurement {
    fn get_measurement_value(self) -> anyhow::Result<Vec<u8>> {
        // Fetches the measurement value.

        self.dmtfspec_measurement_value.ok_or(anyhow::format_err!(
            "Error getting the dmtfspec_measurement_value"
        ))
    }

    fn get_measurement_value_size(self) -> anyhow::Result<usize> {
        //Fetches the measurement value size in bytes.

        self.dmtfspec_measurement_value_size
            .ok_or(anyhow::format_err!(
                "Error getting the dmtfspec_measurement_value_size"
            ))
    }

    // THE TYPES USED FOR THIS STRUCT ARE ALMOST CERTAINLY INCORRECT
    fn parse(mut self, measurement_data: Vec<u8>) -> anyhow::Result<Self> {
        // Parses the raw DMTF Measurement data and sets the various field values of the Measurement.

        let mut byte_index = 0;

        // Get DMTFSpecMeasurementValueType size
        let value_type_size =
            self.field_size
                .get("DMTFSpecMeasurementValueType")
                .ok_or(anyhow::format_err!(
                    "Error getting DMTFSpecMeasurementValueType size"
                ))?;
        let x = measurement_data[byte_index..(byte_index + value_type_size)].to_vec();

        let value = u8::from_str_radix(&hex::encode(x), 16)?;
        self.dmtfspec_measurement_value_type = Some(value);
        byte_index += value_type_size;

        // Get DMTFSpecMeasurementValueSize size
        let value_size_field_size =
            self.field_size
                .get("DMTFSpecMeasurementValueSize")
                .ok_or(anyhow::format_err!(
                    "Error getting DMTFSpecMeasurementValueSize field size"
                ))?;
        let x = &measurement_data[byte_index..(byte_index + value_size_field_size)];
        let value = usize::from_str_radix(&read_field_as_little_endian(ByteStr::new(x)), 16)?;
        self.dmtfspec_measurement_value_size = Some(value);
        byte_index += value_size_field_size;

        let measurement_value_size = self
            .dmtfspec_measurement_value_size
            .expect("invalid value size"); // The logic here still uses expect; typically you'd replace this with ok_or/map_err if it needs to return an anyhow::Error, but keeping the original logic flow for now.

        let value = measurement_data[byte_index..(byte_index + measurement_value_size)].to_vec();
        self.dmtfspec_measurement_value = Some(value);

        Ok(self)
    }

    fn __init__(mut self, measurement_data: Vec<u8>) -> anyhow::Result<Self> {
        // The constructor method for the DmtfMeasurement class representing the DMTF Measurement.

        self.dmtfspec_measurement_value_type = None;
        self.dmtfspec_measurement_value_size = None;
        self.dmtfspec_measurement_value = None;
        self = self.parse(measurement_data)?;
        Ok(self)
    }
}

pub fn read_field_as_little_endian(binary_data: &ByteStr) -> String {
    // Reads a multi-byte field in little endian form and return the read
    //field as a hexadecimal string.

    let mut x = String::from("");

    for i in 0..binary_data.len() {
        let temp = &binary_data[i..(i + 1)];
        let mut hex_str = hex::encode(temp);
        hex_str.push_str(&x);
        x = hex_str;
    }
    x
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct MeasurementRecord {
    // Class to represent the Measurement block.
    //The structure of each of the Measurement block in DMTF's SPDM 1.1 spec is as follows:
    //OFFSET - FIELD                    - SIZE(in bytes)
    //0      - Index                    - 1
    //1      - MeasurementSpecification - 1
    //2      - MeasurementSize          - 2
    //4      - Measurement              - MeasurementSize
    //
    field_size: HashMap<String, usize>,
    measurement_blocks: HashMap<u32, DmtfMeasurement>,
    number_of_blocks: u32,
    dmtf_measurement_specification_value: u8, // = 1
}

impl Default for MeasurementRecord {
    fn default() -> Self {
        MeasurementRecord {
            measurement_blocks: HashMap::new(),
            field_size: HashMap::from([
                ("Index".to_string(), 1),
                ("MeasurementSpecification".to_string(), 1),
                ("MeasurementSize".to_string(), 2),
            ]),
            dmtf_measurement_specification_value: 1,
            number_of_blocks: 0,
        }
    }
}

impl MeasurementRecord {
    pub fn get_measurements(self) -> anyhow::Result<Vec<String>> {
        // Fetches all the measurement value and then returns them as a list.
        let mut measurement_list: Vec<String> = vec!["".to_string(); self.measurement_blocks.len()];

        for (index, dmtf) in self.measurement_blocks {
            let thing = dmtf.get_measurement_value()?;
            measurement_list[index as usize - 1] = hex::encode(thing);
        }
        Ok(measurement_list)
    }

    fn parse(mut self, binary_data: Vec<u8>) -> anyhow::Result<Self> {
        // Parses the raw measurement record data and sets the fields of the class MeasurementRecord object
        //representing the Measurement Record.

        ensure!(
            self.number_of_blocks > 0,
            "There are no measurement blocks in the respone message."
        );

        let mut byte_index: usize = 0;

        for _ in 0..self.number_of_blocks {
            // Get Index size
            let index_size = self
                .field_size
                .get("Index")
                .ok_or(anyhow::format_err!("Error getting Index size"))?;
            let x = binary_data[byte_index..(byte_index + index_size)].to_vec();
            let index = u32::from_str_radix(&hex::encode(x), 16)?;
            byte_index += index_size;

            // Get MeasurementSpecification size
            let measurement_specification_size = self
                .field_size
                .get("MeasurementSpecification")
                .ok_or(anyhow::format_err!(
                    "Error getting MeasurementSpecification size"
                ))?;
            let x = binary_data[byte_index..(byte_index + measurement_specification_size)].to_vec();
            let measurement_specification = u8::from_str_radix(&hex::encode(x), 16)?;
            ensure!(
                measurement_specification == self.dmtf_measurement_specification_value,
                "Measurement block not following DMTF specification. Quitting now."
            );

            byte_index += measurement_specification_size;

            // Get MeasurementSize size
            let measurement_size_field_size =
                self.field_size
                    .get("MeasurementSize")
                    .ok_or(anyhow::format_err!(
                        "Error getting MeasurementSize field size"
                    ))?;
            let x = &binary_data[byte_index..(byte_index + measurement_size_field_size)];

            let measurement_size =
                usize::from_str_radix(&read_field_as_little_endian(ByteStr::new(x)), 16)?;
            byte_index += measurement_size_field_size;

            let measurement_data =
                binary_data[byte_index..(byte_index + measurement_size)].to_vec();
            let dmtf_measurement = DmtfMeasurement::default();
            let dmtf_measurement = dmtf_measurement.__init__(measurement_data)?;
            self.measurement_blocks.insert(index, dmtf_measurement);
            byte_index += measurement_size;
        }

        ensure!(
            byte_index == binary_data.len(),
            "Something went wrong while parsing the MeasurementRecord. Quitting now."
        );
        // Count is unusted, but it's part of the original implementation.
        let mut _count = 0;
        for i in 1..self.number_of_blocks + 1 {
            if let Some(x) = self.measurement_blocks.get(&i) {
                if x.clone().get_measurement_value()?.len()
                    == x.clone().get_measurement_value_size()?
                {
                    _count += 1;
                }
            }
        }

        Ok(self)
    }

    fn __init__(
        mut self,
        measurement_record_data: Vec<u8>,
        number_of_blocks: u32,
    ) -> anyhow::Result<Self> {
        // The constructor method for the class MeasurementRecord to represent the measurement records.

        self.measurement_blocks = HashMap::new();
        self.number_of_blocks = number_of_blocks;
        self = self.parse(measurement_record_data)?;
        Ok(self)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct OpaqueData {
    // This is a class to represent the OpaqueData field in the SPDM GET_MEASUREMENT response message.
    //The structure of the data in this field is as follows:
    //[DataType(2 bytes)|DataSize(2 bytes)|Data(DataSize bytes)][DataType(2 bytes)|DataSize(2 bytes)|Data(DataSize bytes)]...
    //
    opaque_data_types: HashMap<u8, String>,
    msr_count_size: usize, // = 4
    field_size: HashMap<String, usize>,
    opaque_data_field: HashMap<String, Vec<u8>>,
}

impl Default for OpaqueData {
    fn default() -> Self {
        OpaqueData {
            opaque_data_types: HashMap::from([
                (1, "OPAQUE_FIELD_ID_CERT_ISSUER_NAME".to_string()),
                (
                    2,
                    "OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER".to_string(),
                ),
                (3, "OPAQUE_FIELD_ID_DRIVER_VERSION".to_string()),
                (4, "OPAQUE_FIELD_ID_GPU_INFO".to_string()),
                (5, "OPAQUE_FIELD_ID_SKU".to_string()),
                (6, "OPAQUE_FIELD_ID_VBIOS_VERSION".to_string()),
                (7, "OPAQUE_FIELD_ID_MANUFACTURER_ID".to_string()),
                (8, "OPAQUE_FIELD_ID_TAMPER_DETECTION".to_string()),
                (9, "OPAQUE_FIELD_ID_SMC".to_string()),
                (10, "OPAQUE_FIELD_ID_VPR".to_string()),
                (11, "OPAQUE_FIELD_ID_NVDEC0_STATUS".to_string()),
                (12, "OPAQUE_FIELD_ID_MSRSCNT".to_string()),
                (13, "OPAQUE_FIELD_ID_CPRINFO".to_string()),
                (14, "OPAQUE_FIELD_ID_BOARD_ID".to_string()),
                (15, "OPAQUE_FIELD_ID_CHIP_SKU".to_string()),
                (16, "OPAQUE_FIELD_ID_CHIP_SKU_MOD".to_string()),
                (17, "OPAQUE_FIELD_ID_PROJECT".to_string()),
                (18, "OPAQUE_FIELD_ID_PROJECT_SKU".to_string()),
                (19, "OPAQUE_FIELD_ID_PROJECT_SKU_MOD".to_string()),
                (20, "OPAQUE_FIELD_ID_FWID".to_string()),
                (21, "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS".to_string()),
                (22, "OPAQUE_FIELD_ID_SWITCH_PDI".to_string()),
                (23, "OPAQUE_FIELD_ID_FLOORSWEPT_PORTS".to_string()),
                (24, "OPAQUE_FIELD_ID_POSITION_ID".to_string()),
                (25, "OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS".to_string()),
                (32, "OPAQUE_FIELD_ID_GPU_LINK_CONN".to_string()),
                (33, "OPAQUE_FIELD_ID_SYS_ENABLE_STATUS".to_string()),
                (34, "OPAQUE_FIELD_ID_OPAQUE_DATA_VERSION".to_string()),
                (35, "OPAQUE_FIELD_ID_CHIP_INFO".to_string()),
                (36, "OPAQUE_FIELD_ID_FEATURE_FLAG".to_string()),
                (255, "OPAQUE_FIELD_ID_INVALID".to_string()),
            ]),
            msr_count_size: 4,
            field_size: HashMap::from([
                ("DataType".to_string(), 2),
                ("DataSize".to_string(), 2),
                ("PdiDataSize".to_string(), 8),
            ]),
            opaque_data_field: HashMap::new(),
        }
    }
}

impl OpaqueData {
    pub fn get_data(&self, field_name: &str) -> anyhow::Result<Vec<u8>> {
        // Fetches the field value of the given field name.

        self.opaque_data_field
            .get(field_name)
            .cloned()
            .ok_or(anyhow::format_err!(
                "Error getting field {} from opaque data",
                field_name
            ))
    }

    fn parse_measurement_count(self, data: &ByteStr) -> anyhow::Result<Vec<u8>> {
        // Parses and creates a list of measurement count values from the OpaqueData field.

        if !data.len().is_multiple_of(self.msr_count_size) {
            panic!("{}", "Invalid size of measurement count field data.");
        }

        let mut msr_cnt = Vec::new();
        let number_of_elements = data.len() / self.msr_count_size;

        for i in 0..number_of_elements {
            let start = i * self.msr_count_size;
            let end = start + self.msr_count_size;
            let element = &data[start..end];

            let element =
                u8::from_str_radix(&read_field_as_little_endian(ByteStr::new(element)), 16)?;
            msr_cnt.push(element);
        }

        Ok(msr_cnt)
    }

    fn parse(mut self, binary_data: Vec<u8>) -> anyhow::Result<Self> {
        // Parses the raw OpaqueData field of the SPDM GET_MEASUREMENT response message.

        let mut byte_index = 0;

        let mut opaque_data_hashmap: HashMap<String, Vec<u8>> = HashMap::new();
        let data_type_size = self
            .field_size
            .get("DataType")
            .ok_or(anyhow::format_err!("Error getting DataType"))?;
        let data_size = self
            .field_size
            .get("DataSize")
            .ok_or(anyhow::format_err!("Error getting DataSize"))?;
        let opaque_data_types = self.clone().opaque_data_types;
        while byte_index < binary_data.len() {
            let x = &binary_data[byte_index..(byte_index + data_type_size)];

            let value = u8::from_str_radix(&read_field_as_little_endian(ByteStr::new(x)), 16)?;

            let data_type = opaque_data_types.get(&value).ok_or(anyhow::format_err!(
                "Error getting value out of opaque_data_types: {}",
                value
            ))?;

            byte_index += data_type_size;

            let x = &binary_data[byte_index..byte_index + data_size];
            let data_size_val =
                usize::from_str_radix(&read_field_as_little_endian(ByteStr::new(x)), 16)?;
            byte_index += data_size;

            let value = binary_data[byte_index..(byte_index + data_size_val)].to_vec();

            if data_type == "OPAQUE_FIELD_ID_MSRSCNT" {
                let msr_cnt: Vec<u8> =
                    self.clone().parse_measurement_count(ByteStr::new(&value))?;
                opaque_data_hashmap.insert("OPAQUE_FIELD_ID_MSRSCNT".to_string(), msr_cnt.to_vec());
            } else {
                opaque_data_hashmap.insert(data_type.to_string(), value.to_vec());
            }
            byte_index += data_size_val;
        }
        self.opaque_data_field = opaque_data_hashmap;
        Ok(self)
    }

    fn __init__(mut self, binary_data: Vec<u8>) -> anyhow::Result<Self> {
        // The constructor method for the class representing the OpaqueData.

        self.opaque_data_field = HashMap::new();
        self.parse(binary_data)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct SpdmMeasurementResponseMessage {
    // Class to represent the SPDM GET_MEASUREMENT response message.
    //Following is the expected structure of the Successful MEASUREMENTS response message in DMTF's SPDM 1.1 spec.
    //OFFSET   - FIELD                   - SIZE(in bytes)
    //0        - SPDMVersion             - 1
    //1        - RequestResponseCode     - 1
    //2        - Param1                  - 1
    //3        - Param2                  - 1
    //4        - NumberOfBlocks          - 1
    //5        - MeasurementRecordLength - 3
    //8        - MeasurementRecord       - L1 = MeasurementRecordLength
    //8+L1     - Nonce                   - 32
    //40+L1    - OpaqueLength            - 2
    //42+L1    - OpaqueData              - L2 = OpaqueLength
    //42+L1+L2 - Signature               - 64
    //
    field_size: HashMap<String, usize>,
    pub spdmversion: Vec<u8>,
    pub request_response_code: Vec<u8>,
    pub param1: Vec<u8>,
    pub param2: Vec<u8>,
    pub number_of_blocks: u32,
    pub measurement_record_length: usize,
    pub nonce: Vec<u8>,
    pub opaque_length: usize,
    pub measurement_record: MeasurementRecord,
    pub opaque_data: OpaqueData,
    pub signature: Vec<u8>,
}

impl Default for SpdmMeasurementResponseMessage {
    fn default() -> Self {
        SpdmMeasurementResponseMessage {
            field_size: HashMap::from([
                ("SPDMVersion".to_string(), 1),
                ("RequestResponseCode".to_string(), 1),
                ("Param1".to_string(), 1),
                ("Param2".to_string(), 1),
                ("NumberOfBlocks".to_string(), 1),
                ("MeasurementRecordLength".to_string(), 3),
                ("Nonce".to_string(), 32),
                ("OpaqueLength".to_string(), 2),
            ]),
            spdmversion: Vec::new(),
            request_response_code: Vec::new(),
            param1: Vec::new(),
            param2: Vec::new(),
            number_of_blocks: 0,
            measurement_record_length: 0,
            nonce: Vec::new(),
            opaque_length: 0,
            measurement_record: MeasurementRecord::default(),
            signature: Vec::new(),
            opaque_data: OpaqueData::default(),
        }
    }
}

impl SpdmMeasurementResponseMessage {
    pub fn get_measurement_record(self) -> MeasurementRecord {
        // Fetches the MeasurementRecord object representing the measurement record of the SPDM GET_MEASUREMENT response.

        self.measurement_record
    }

    pub fn get_nonce(self) -> Vec<u8> {
        // Fetches the Nonce field of the object representing the SPDM GET_MEASUREMENT response.

        self.nonce
    }

    pub fn get_opaque_data_length(self) -> usize {
        // Fetches the length of OpaqueData field of the object representing the SPDM GET_MEASUREMENT response.

        self.opaque_length
    }

    pub fn get_opaque_data(self) -> OpaqueData {
        // Fetches the OpaqueData class object representing the Opaque data in the SPDM GET_MEASUREMENT response.

        self.opaque_data
    }

    pub fn get_signature(self) -> Vec<u8> {
        // Fetches the signature field content of the SpdmMeasurementResponseMessage class object.

        self.signature
    }

    fn parse(mut self, response: Vec<u8>) -> anyhow::Result<Self> {
        // Parses the raw SPDM GET_MEASUREMENT response message and sets the various fields of the SpdmMeasurementResponseMessage class object.

        let mut byte_index = 0;
        let response = ByteString::new(response);

        let spdm_version = self
            .field_size
            .get("SPDMVersion")
            .ok_or(anyhow::format_err!("Error getting SPDMVersion"))?;
        let value = response[byte_index..(byte_index + spdm_version)].to_vec();
        self.spdmversion = value;
        byte_index += spdm_version;

        let request_response_code_size = self
            .field_size
            .get("RequestResponseCode")
            .ok_or(anyhow::format_err!("Error getting RequestResponseCode"))?;
        let value = response[byte_index..(byte_index + request_response_code_size)].to_vec();
        self.request_response_code = value;
        byte_index += request_response_code_size;

        let param1_size = self
            .field_size
            .get("Param1")
            .ok_or(anyhow::format_err!("Error getting Param1"))?;
        let value = response[byte_index..(byte_index + param1_size)].to_vec();
        self.param1 = value;
        byte_index += param1_size;

        let param2_size = self
            .field_size
            .get("Param2")
            .ok_or(anyhow::format_err!("Error getting Param2"))?;
        let value = response[byte_index..(byte_index + param2_size)].to_vec();
        self.param2 = value;
        byte_index += param2_size;

        let number_of_blocks_size = self
            .field_size
            .get("NumberOfBlocks")
            .ok_or(anyhow::format_err!("Error getting NumberOfBlocks"))?;
        let x = response[byte_index..(byte_index + number_of_blocks_size)].to_vec();
        let value = u32::from_str_radix(&hex::encode(x), 16)?;
        self.number_of_blocks = value;
        byte_index += number_of_blocks_size;

        let measurement_record_length_size = self
            .field_size
            .get("MeasurementRecordLength")
            .ok_or(anyhow::format_err!("Error getting MeasurementRecordLength"))?;
        let x = &response[byte_index..(byte_index + measurement_record_length_size)];
        let value = usize::from_str_radix(&read_field_as_little_endian(ByteStr::new(x)), 16)?;
        self.measurement_record_length = value;
        byte_index += measurement_record_length_size;

        let measurement_record_data =
            response[byte_index..(byte_index + self.measurement_record_length)].to_vec();
        let mut measurement_record = MeasurementRecord::default();
        measurement_record =
            measurement_record.__init__(measurement_record_data, self.number_of_blocks)?;
        self.measurement_record = measurement_record;
        byte_index += self.measurement_record_length;

        let nonce_size = self
            .field_size
            .get("Nonce")
            .ok_or(anyhow::format_err!("Error getting Nonce"))?;
        let value = response[byte_index..(byte_index + nonce_size)].to_vec();
        self.nonce = value;
        byte_index += nonce_size;

        let opaque_length_size = self
            .field_size
            .get("OpaqueLength")
            .ok_or(anyhow::format_err!("Error getting OpaqueLength"))?;
        let x = &response[byte_index..(byte_index + opaque_length_size)];
        let value = usize::from_str_radix(&read_field_as_little_endian(ByteStr::new(x)), 16)?;
        self.opaque_length = value;
        byte_index += opaque_length_size;

        let opaque_data_content = response[byte_index..(byte_index + self.opaque_length)].to_vec();
        self.opaque_data = OpaqueData::default();
        self.opaque_data = self.opaque_data.__init__(opaque_data_content)?;
        byte_index += self.opaque_length;

        let signature_size = self
            .field_size
            .get("Signature")
            .ok_or(anyhow::format_err!("Error getting Signature"))?;
        let value = response[byte_index..(byte_index + signature_size)].to_vec();
        self.signature = value;
        // byte_index = byte_index + signature_size;

        Ok(self)
    }

    pub fn __init__(mut self, response: Vec<u8>) -> anyhow::Result<Self> {
        // The constructor method for the class SpdmMeasurementResponseMessage representing the SPDM GET_MEASUREMENT response message.

        self.spdmversion = Vec::new();
        self.request_response_code = Vec::new();
        self.param1 = Vec::new();
        self.param2 = Vec::new();
        self.number_of_blocks = 0;
        self.measurement_record_length = 0;
        self.measurement_record = MeasurementRecord::default();
        self.nonce = Vec::new();
        self.opaque_length = 0;
        self.opaque_data = OpaqueData::default();
        self.signature = Vec::new();
        self.field_size
            .insert("Signature".to_string(), SIGNATURE_LENGTH);

        self.parse(response)
            .context("SpdmMeasurementResponseMessage __init__ error parsing the response")
    }
}
