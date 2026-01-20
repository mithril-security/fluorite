//
// SPDX-FileCopyrightText{ Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier{ BSD-3-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met{
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

use anyhow::Context;
use byte_string::ByteString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct SpdmMeasurementRequestMessage {
    /*  Class representing the SPDM GET_MEASUREMENT request message.
    Following is the expected structure of the MEASUREMENTS request message in DMTF's SPDM 1.1 spec.
    OFFSET   - FIELD                   - SIZE(in bytes)
    0        - SPDMVersion             - 1
    1        - RequestResponseCode     - 1
    2        - Param1                  - 1
    3        - Param2                  - 1
    4        - Nonce                   - 32
    36       - SlotIDParam             - 1
     */
    field_size: HashMap<String, usize>,
    spdmversion: Option<Vec<u8>>,
    request_response_code: Option<Vec<u8>>,
    param1: Option<Vec<u8>>,
    param2: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    slot_idparam: Option<Vec<u8>>,
}

impl Default for SpdmMeasurementRequestMessage {
    fn default() -> Self {
        SpdmMeasurementRequestMessage {
            field_size: HashMap::from([
                ("SPDMVersion".to_string(), 1),
                ("RequestResponseCode".to_string(), 1),
                ("Param1".to_string(), 1),
                ("Param2".to_string(), 1),
                ("Nonce".to_string(), 32),
                ("SlotIDParam".to_string(), 1),
            ]),
            spdmversion: Some(Vec::new()),
            request_response_code: Some(Vec::new()),
            param1: Some(Vec::new()),
            param2: Some(Vec::new()),
            nonce: Some(Vec::new()),
            slot_idparam: Some(Vec::new()),
        }
    }
}

impl SpdmMeasurementRequestMessage {
    pub fn get_nonce(self) -> Option<Vec<u8>> {
        // Fetches the Nonce field of the object representing the SPDM GET_MEASUREMENT request.

        self.nonce
    }

    fn parse(mut self, request_data: Vec<u8>) -> Option<Self> {
        //  Parses the raw SPDM GET_MEASUREMENT request message.

        let mut byte_index = 0;
        let request_data = ByteString::new(request_data);

        let value =
            request_data[byte_index..(byte_index + self.field_size.get("SPDMVersion")?)].to_vec();
        self.spdmversion = Some(value);
        byte_index += self.field_size.get("SPDMVersion")?;

        let value = request_data
            [byte_index..byte_index + self.field_size.get("RequestResponseCode")?]
            .to_vec();
        self.request_response_code = Some(value);
        byte_index += self.field_size.get("RequestResponseCode")?;

        let value = request_data[byte_index..byte_index + self.field_size.get("Param1")?].to_vec();
        self.param1 = Some(value);
        byte_index += self.field_size.get("Param1")?;

        let value = request_data[byte_index..byte_index + self.field_size.get("Param2")?].to_vec();
        self.param2 = Some(value);
        byte_index += self.field_size.get("Param2")?;

        let value = request_data[byte_index..byte_index + self.field_size.get("Nonce")?].to_vec();
        self.nonce = Some(value);
        byte_index += self.field_size.get("Nonce")?;

        let value =
            request_data[byte_index..byte_index + self.field_size.get("SlotIDParam")?].to_vec();
        self.slot_idparam = Some(value);
        byte_index += self.field_size.get("SlotIDParam")?;

        if byte_index != request_data.len() {
            let err_msg =
                "Something went wrong during parsing the SPDM GET MEASUREMENT request message.";
            panic!("{}", err_msg);
        }
        Some(self)
    }

    pub fn __init__(mut self, request_data: Vec<u8>) -> anyhow::Result<Self> {
        // The constructor method for the SpdmMeasurementRequestMessage class representing the SPDM GET_MEASUREMENT
        // request message.

        self.spdmversion = None;
        self.request_response_code = None;
        self.param1 = None;
        self.param2 = None;
        self.nonce = None;
        self.slot_idparam = None;
        self.parse(request_data)
            .context("Error parsing request data")
    }
}
