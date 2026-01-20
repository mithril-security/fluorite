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
use crate::utils::{
    ocsp_certificate_chain_validation, parse_xml_document, verify_certificate_chain,
    CertChainVerificationMode, GoldenMeasurement, RimName,
};
use anyhow::{anyhow, bail, ensure, Context};
use base64::prelude::*;
use libxml::schemas::{SchemaParserContext, SchemaValidationContext};
use log::info;
use std::collections::HashMap;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::X509Certificate;
use xmltree::Element;

const RIM_ROOT_CERT: &[u8; 809] = include_bytes!("../certs/verifier_RIM_root.pem");
const SWID_SCHEMA: &[u8; 47689] = include_bytes!("../swidSchema2015.xsd");

fn parse_measurements(
    payload: Element,
    rim_name: RimName,
) -> anyhow::Result<HashMap<usize, GoldenMeasurement>> {
    // Lists the measurements of the Resource tags in the base RIM.

    let mut measurements_obj: HashMap<usize, GoldenMeasurement> = HashMap::new();

    for child in payload.children {
        let child_elem = child
            .as_element()
            .ok_or(anyhow!("Error converting payload child to element"))?;

        let index = child_elem
            .attributes
            .get("index")
            .ok_or(anyhow!("Could not get 'index' property"))?
            .parse::<usize>()?;
        let alternatives = child_elem
            .attributes
            .get("alternatives")
            .ok_or(anyhow!("Could not get 'alternatives' property"))?
            .parse::<usize>()?;

        let active = match child_elem
            .attributes
            .get("active")
            .ok_or(anyhow!("Could not get 'active' property"))?
            .as_str()
        {
            "True" => Ok(true),
            "False" => Ok(false),
            _ => Err(anyhow!("Error parsing 'active' property")),
        }?;

        let name = child_elem
            .attributes
            .get("name")
            .ok_or(anyhow!("Could not get 'name' property"))?
            .to_string();
        let size = child_elem
            .attributes
            .get("size")
            .ok_or(anyhow!("Could not get 'size' property"))?
            .parse::<usize>()?;

        let mut measurements_values = Vec::new();
        for i in 0..alternatives {
            let name = format!("Hash{}", i);
            let hash = child_elem
                .attributes
                .get(&name)
                .ok_or(anyhow!("Could not get '{}' property", name))?
                .to_string();
            measurements_values.push(hash);
        }
        let golden_measurement = GoldenMeasurement {
            rim_name,
            name,
            values: measurements_values,
            size,
            alternatives,
            active,
        };

        if let std::collections::hash_map::Entry::Vacant(e) = measurements_obj.entry(index) {
            e.insert(golden_measurement);
        } else {
            bail!(
                "Multiple measurement are assigned same index in {} rim. Index: {}",
                rim_name,
                index
            );
        }
    }

    ensure!(
        !measurements_obj.is_empty(),
        "No golden measurements found in {}. Quitting now.",
        rim_name
    );

    Ok(measurements_obj)
}

fn extract_certificates(xml_root_element: &Element) -> anyhow::Result<Vec<Vec<u8>>> {
    let signature = xml_root_element
        .get_child("Signature")
        .ok_or(anyhow!("Could not get `Signature` element"))?;

    let keyinfo = signature
        .get_child("KeyInfo")
        .ok_or(anyhow!("Could not get `KeyInfo` element"))?;

    let x509_data = keyinfo
        .get_child("X509Data")
        .ok_or(anyhow!("Could not get `X509Data` element"))?;

    let decoded_certs = x509_data
        .children
        .clone()
        .iter()
        .map(|xml_node| {
            let element = xml_node
                .as_element()
                .ok_or(anyhow!("Error getting converting xml_node to Element"))?;

            if element.name == "X509Certificate" {
                let text = element
                    .get_text()
                    .ok_or(anyhow!("Error getting text from X509Certificate Element"))?
                    .into_owned();
                let encoded = text.lines().collect::<String>();
                BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|err| anyhow!("Error base64 decoding the certificate data: {}", err))
            } else {
                Err(anyhow!(
                    "There should only be X509Certificate children elements"
                ))
            }
        })
        .collect::<anyhow::Result<Vec<Vec<u8>>>>()?;

    // let decoded_certs: Vec<Vec<u8>> = get_element(&x509_data, "X509Certificate".to_string())
    //     .iter()
    //     .map(|pem_contents| {
    //         let encoded = pem_contents.get_content().lines().collect::<String>();
    //         BASE64_STANDARD
    //             .decode(encoded)
    //             .map_err(|err| anyhow!("Error base64 decoding the certificate data: {}", err))
    //     })
    //     .collect::<anyhow::Result<Vec<Vec<u8>>>>()?;

    // let decoded_certs = Vec::new();

    Ok(decoded_certs)
}

pub fn create_rim(rim_name: RimName, content: String) -> anyhow::Result<RIM> {
    // The constructor method for the RIM class handling all the RIM file processing.
    ensure!(
        !content.is_empty(),
        "Can't create a RIM with an empty content"
    );

    let xml_root_element = parse_xml_document(&content)?;

    let meta = xml_root_element
        .get_child("Meta")
        .ok_or(anyhow!("Could not get `Meta` element"))?;

    let colloquial_version = meta
        .attributes
        .get("colloquialVersion")
        .ok_or(anyhow!("Driver version not found in the RIM."))?
        .to_string();

    info!(
        "The driver version in the RIM file is {}",
        colloquial_version
    );

    let payload = xml_root_element
        .get_child("Payload")
        .ok_or(anyhow!("Could not get `Payload` element"))?;
    let measurements_obj = parse_measurements(payload.clone(), rim_name)?;

    let rim = RIM {
        rim_name,
        colloquial_version,
        measurements_obj,
        xml_root_element,
        original_xml_str: content,
    };
    Ok(rim)
}

#[derive(Clone)]
pub struct RIM {
    rim_name: RimName,
    colloquial_version: String,
    measurements_obj: HashMap<usize, GoldenMeasurement>,
    xml_root_element: Element,
    original_xml_str: String,
}

impl RIM {
    // The signature verification is sensible to how the formatter outputs the xml,
    // And i can't obtain the original xml string that created the xml_root_element
    // Because I can't properly setup the writer.

    // fn root_element_to_string(&self) -> anyhow::Result<String>{
    //     let mut vec = Vec::new();
    //     self.xml_root_element.write(&mut vec).context("Error writing root element to string")?;
    //     let res = String::from_utf8(vec)?;
    //     Ok(res)
    // }

    // A class to process and manage all the processing of the RIM files.
    //RIM module Trusted Computing Group Reference Integrity Manifest of the
    //Verifier is used to perform the authentication and access of the golden
    //measurements.
    //
    fn validate_schema(&self) -> anyhow::Result<()> {
        // Performs the schema validation of the base RIM against a given schema.

        let parser = libxml::parser::Parser::default();
        let parse_options = libxml::parser::ParserOptions {
            no_net: true,
            no_def_dtd: true,
            ..Default::default()
        };
        let xml_root_element = parser
            .parse_string_with_options(self.original_xml_str.clone(), parse_options)
            .map_err(|e| anyhow!("Error parsing xml document: {:?}", e))?;

        let mut xsdparser = SchemaParserContext::from_buffer(SWID_SCHEMA);
        let mut xsd = SchemaValidationContext::from_parser(&mut xsdparser)
            .map_err(|e| anyhow!("Err: {:?}", e))
            .context("Failed to parse schema")?;

        xsd.validate_document(&xml_root_element)
            .map_err(|e| anyhow!("Err: {:?}", e))
            .context("Invalid XML accoding to XSD schema")
    }

    fn verify_signature(&self, cert: X509Certificate) -> anyhow::Result<()> {
        // Verifies the signature of the base RIM.
        samael::crypto::verify_signed_xml(self.original_xml_str.clone(), cert.as_raw(), None)
            .context("RIM signature verification failed.")
    }

    pub fn get_measurements(self) -> HashMap<usize, GoldenMeasurement> {
        // Returns the hashmap object that contains the golden measurement.

        self.measurements_obj
    }

    pub async fn verify(&self, version: String) -> anyhow::Result<()> {
        // Performs the schema validation if it is successful then signature verification is done.
        // If both tests passed then returns True, otherwise returns False.

        self.validate_schema().context(anyhow!(
            "Schema validation of {} RIM failed.",
            self.rim_name
        ))?;

        info!("RIM Schema validation passed.");

        ensure!(version == self.colloquial_version.to_lowercase(), anyhow!("The {} version in the RIM file is not matching with the installed {} version. {} != {}", self.rim_name, self.rim_name, version, self.colloquial_version.to_lowercase()));

        info!(
            "The {} version in the RIM file is matching with the installed {} version",
            self.rim_name, self.rim_name
        );

        let decoded_certs = extract_certificates(&self.xml_root_element)?;

        let rim_cert_chain: Vec<X509Certificate<'_>> = decoded_certs
            .iter()
            .map(|cert_der| {
                let (_, parsed_cert) = parse_x509_certificate(cert_der)?;
                Ok(parsed_cert)
            })
            .collect::<anyhow::Result<_>>()
            .context("Error parsing certificates")?;

        let (_, root_certificate_pem) =
            parse_x509_pem(RIM_ROOT_CERT).context("Error parsing the RIM_ROOT_CERT")?;
        let root_certificate = root_certificate_pem
            .parse_x509()
            .context("Error decodin the PEM contents of the RIM_ROOT_CERT")?;

        ensure!(
            root_certificate == rim_cert_chain[rim_cert_chain.len() - 1],
            "RIM_ROOT_CERT does not match the expected RIM ROOT CERT contained in the RIM"
        );

        let mode = match self.rim_name {
            RimName::Driver => CertChainVerificationMode::DriverRimCert,
            RimName::VBios => CertChainVerificationMode::VbiosRimCert,
        };

        verify_certificate_chain(&rim_cert_chain, mode).context(anyhow!(
            "{} RIM cert chain verification failed",
            self.rim_name
        ))?;

        info!(
            "{} RIM certificate chain verification successful.",
            self.rim_name
        );

        ocsp_certificate_chain_validation(&rim_cert_chain, mode)
            .await
            .context(anyhow!(
                "{} RIM cert chain ocsp status verification failed.",
                self.rim_name
            ))?;

        info!(
            "{} RIM certificate chain ocsp status verification successful.",
            self.rim_name
        );

        self.verify_signature(rim_cert_chain[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::{ensure, Context};
    use log::info;

    use crate::{
        rim::{create_rim, RIM},
        utils::{
            self, fetch_rim_file, get_driver_rim_file_id, get_vbios_rim_file_id, init_logger_tests,
            RimName,
        },
    };

    #[tokio::test]
    async fn test_local_driver_rim_parsing_and_verification() -> anyhow::Result<()> {
        init_logger_tests();
        let version = "580.95.05".to_string();
        let rim_name = RimName::Driver;
        let file_name = get_driver_rim_file_id(&version);

        let driver_rim_content =
            String::from_utf8(fs::read(format!("./test_data/{}.xml", file_name))?)?;

        let driver_rim =
            create_rim(rim_name, driver_rim_content).context("Error creating driver RIM.")?;

        driver_rim.verify(version).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_remote_driver_rim_parsing_and_verification() -> anyhow::Result<()> {
        init_logger_tests();
        let version = "580.95.05".to_string();

        let driver_rim_file_id = get_driver_rim_file_id(&version);
        let driver_rim_content = fetch_rim_file(driver_rim_file_id).await?;

        let driver_rim = create_rim(RimName::Driver, driver_rim_content)
            .context("Error creating driver RIM.")?;

        driver_rim.verify(version).await?;

        Ok(())
    }

    async fn get_vbios_rim(remote: bool) -> anyhow::Result<(RIM, String)> {
        init_logger_tests();
        let rim_name = RimName::VBios;
        let project_str = "1010";
        let project_sku_str = "0210";
        let chip_sku_str = "886";
        let vbios_version_for_id = "96009F0004";
        let vbios_version = "96.00.9f.00.04".to_string();

        let vbios_rim_file_id = get_vbios_rim_file_id(
            &project_str,
            &project_sku_str,
            &chip_sku_str,
            &vbios_version_for_id,
        );

        let vbios_rim_content = if remote {
            utils::fetch_rim_file(vbios_rim_file_id).await?
        } else {
            String::from_utf8(fs::read(format!("./test_data/{}.xml", vbios_rim_file_id))?)?
        };

        let vbios_rim =
            create_rim(rim_name, vbios_rim_content).context("Error creating vbios RIM.")?;

        Ok((vbios_rim, vbios_version))
    }

    #[tokio::test]
    async fn test_local_vbios_rim_parsing_and_verification() -> anyhow::Result<()> {
        init_logger_tests();
        let (vbios_rim, vbios_version) = get_vbios_rim(false).await?;

        vbios_rim
            .verify(vbios_version)
            .await
            .context("VBIOS RIM verification failed. Quitting now.")?;

        Ok(())
    }

    #[tokio::test]
    async fn test_remote_vbios_rim_parsing_and_verification() -> anyhow::Result<()> {
        init_logger_tests();
        let (vbios_rim, vbios_version) = get_vbios_rim(true).await?;

        vbios_rim
            .verify(vbios_version)
            .await
            .context("VBIOS RIM verification failed. Quitting now.")?;

        Ok(())
    }

    #[tokio::test]
    async fn test_vbios_rim_broken_signature() -> anyhow::Result<()> {
        init_logger_tests();
        let rim_name = RimName::VBios;
        let project_str = "1010";
        let project_sku_str = "0210";
        let chip_sku_str = "886";
        let vbios_version_for_id = "96009F0004";
        let vbios_version = "96.00.9f.00.04".to_string();

        let vbios_rim_file_id = get_vbios_rim_file_id(
            &project_str,
            &project_sku_str,
            &chip_sku_str,
            &vbios_version_for_id,
        );

        // HashedMeasurement_1_FSP is an active measuremenet and is zeroed out
        let vbios_rim_content = String::from_utf8(fs::read(format!(
            "./test_data/{}_broken.xml",
            vbios_rim_file_id
        ))?)?;
        let vbios_rim =
            create_rim(rim_name, vbios_rim_content).context("Error creating vbios RIM.")?;

        let verification_result = vbios_rim
            .verify(vbios_version)
            .await
            .context("VBIOS RIM verification failed. Quitting now.");

        ensure!(verification_result.is_err(), "Verification should have failed because I modified the rim without updating the signature, so the verification step should fail.");

        let err_msg = verification_result
            .err()
            .ok_or(anyhow::anyhow!("Failed getting the error in negative test"))?;
        info!("Test failed with: {}", err_msg.root_cause());

        Ok(())
    }
}
