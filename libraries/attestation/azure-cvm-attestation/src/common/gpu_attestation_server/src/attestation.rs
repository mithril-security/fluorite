//
// SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::spdm_msrt_req_msg::SpdmMeasurementRequestMessage;
use crate::spdm_msrt_resp_msg::SpdmMeasurementResponseMessage;
use anyhow::{ensure, Context};
use p384::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use spki::DecodePublicKey;
use x509_parser::prelude::X509Certificate;

const LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE: usize = 37;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct AttestationReport {
    pub request_data: Vec<u8>,
    pub response_data: Vec<u8>,
}

impl AttestationReport {
    // A class to represent the attestation report coming from the GPU driver.
    //The class to encapsulate the Attestation report which comprises of the
    //SPDM GET MEASUREMENT request message and the SPDM GET MEASUREMENT response
    //message.
    //

    fn concatenate(self, signature_length: usize) -> anyhow::Result<Vec<u8>> {
        // Computes the binary data over which the signature verification is to be done.

        ensure!(self.response_data.len() > signature_length, "The the length of the SPDM GET_MEASUREMENT response message is less than or equal to the length of the signature field, which is not correct.");
        let mut res = Vec::new();
        res.extend_from_slice(&self.request_data);
        res.extend_from_slice(&self.response_data[..(self.response_data.len() - signature_length)]);

        Ok(res)
    }

    pub fn verify_signature(
        self,
        certificate: X509Certificate,
        signature_length: usize,
    ) -> anyhow::Result<()> {
        // Performs the signature verification of the attestation report.
        let pub_key = certificate.public_key();
        let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(pub_key.raw)
            .context("Error creating VerifyingKey")?;
        let signature = p384::ecdsa::Signature::from_slice(&self.get_response_message()?.signature)
            .context("Error creating p384 Signature")?;
        let data = self
            .concatenate(signature_length)
            .context("Error concatenating attestation data")?;

        verifying_key
            .verify(&data, &signature)
            .context("Error verifying attestation report signature")
    }

    pub fn get_measurements(self) -> anyhow::Result<Vec<String>> {
        // Fetches the runtime measurements from the attestation report.

        let measurement_list = self
            .get_response_message()?
            .get_measurement_record()
            .get_measurements()
            .context("Error getting the measurement")?;

        if measurement_list.is_empty() {
            Err(anyhow::format_err!("The measurement_list is empty"))
        } else {
            Ok(measurement_list)
        }
    }

    pub fn get_request_message(&self) -> anyhow::Result<SpdmMeasurementRequestMessage> {
        // Fetches the SPDM GET MEASUREMENT request message represented as an object of class SpdmMeasurementRequestMessage.

        let mut request_message = SpdmMeasurementRequestMessage::default();
        request_message = request_message.__init__(self.request_data.clone())?;

        Ok(request_message)
    }

    pub fn get_response_message(&self) -> anyhow::Result<SpdmMeasurementResponseMessage> {
        // Fetches the SPDM GET MEASUREMENT response message represented as an object of class SpdmMeasurementResponseMessage.
        let mut response_message = SpdmMeasurementResponseMessage::default();
        response_message = response_message.__init__(self.response_data.clone())?;

        Ok(response_message)
    }

    pub fn new(data: Vec<u8>) -> AttestationReport {
        // The constructor for the attestation report class.

        let mut request_data = data;
        let response_data = request_data.split_off(LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE);

        AttestationReport {
            request_data,
            response_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::{ensure, Context};
    use log::info;
    use nvml_wrapper::structs::device::ConfidentialComputeGpuCertificate;
    use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

    use crate::{
        attestation::AttestationReport,
        parse_certificate_chain_pem,
        utils::{init_logger_tests, SIGNATURE_LENGTH},
    };

    #[test]
    fn test_attestation_report_verification() -> anyhow::Result<()> {
        init_logger_tests();
        let attestation_report: AttestationReport = serde_json::from_slice(
            &fs::read("./test_data/attestation_report.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let cert_der = fs::read("./test_data/attestation_report_leaf_cert.crt")
            .context("Error reading certificate test file")?;
        let (_, leaf_cert) = parse_x509_certificate(&cert_der)?;

        attestation_report.verify_signature(leaf_cert, SIGNATURE_LENGTH)?;

        Ok(())
    }

    #[test]
    fn test_attestation_report_verification_with_certificate_from_chain() -> anyhow::Result<()> {
        init_logger_tests();

        let attestation_report: AttestationReport = serde_json::from_slice(
            &fs::read("./test_data/attestation_report.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let certificate_chain: ConfidentialComputeGpuCertificate = serde_json::from_slice(
            &fs::read("./test_data/certificate_chain.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let attestation_report_cert_chain_pem =
            parse_certificate_chain_pem(&certificate_chain.attestation_cert_chain)
                .context("Error parsing pem chain")?;

        let attestation_report_cert_chain: Vec<X509Certificate<'_>> =
            attestation_report_cert_chain_pem
                .iter()
                .map(|pem| pem.parse_x509())
                .collect::<Result<Vec<_>, _>>()?;

        let leaf_cert = attestation_report_cert_chain[0].clone();

        attestation_report.verify_signature(leaf_cert, SIGNATURE_LENGTH)?;
        Ok(())
    }

    #[test]
    fn test_attestation_report_verification_with_wrong_certificate_from_chain() -> anyhow::Result<()>
    {
        init_logger_tests();

        let attestation_report: AttestationReport = serde_json::from_slice(
            &fs::read("./test_data/attestation_report.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let certificate_chain: ConfidentialComputeGpuCertificate = serde_json::from_slice(
            &fs::read("./test_data/certificate_chain.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let attestation_report_cert_chain_pem =
            parse_certificate_chain_pem(&certificate_chain.attestation_cert_chain)
                .context("Error parsing pem chain")?;

        let attestation_report_cert_chain: Vec<X509Certificate<'_>> =
            attestation_report_cert_chain_pem
                .iter()
                .map(|pem| pem.parse_x509())
                .collect::<Result<Vec<_>, _>>()?;

        // Not the leaf cert. The last certificate in the certificate chain is the root ca cert. Verification should fail.
        let not_the_leaf_cert =
            attestation_report_cert_chain[attestation_report_cert_chain.len() - 1].clone();

        let verification_result =
            attestation_report.verify_signature(not_the_leaf_cert, SIGNATURE_LENGTH);

        ensure!(
            verification_result.is_err(),
            "Verification should have failed because the certificate is wrong!"
        );

        let err_msg = verification_result
            .err()
            .ok_or(anyhow::anyhow!("Failed getting the error in negative test"))?;
        info!("Test failed with: {}", err_msg.root_cause());

        Ok(())
    }
}
