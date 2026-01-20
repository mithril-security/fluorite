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

use anyhow::{anyhow, ensure, Context};

use crate::{attestation::AttestationReport, rim::RIM, utils::GoldenMeasurement};
use log::info;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Verifier {
    // A class to match the runtime GPU measurements against the golden
    //measurements.
    pub is_msr_35_valid: bool,
    pub runtime_measurements: Vec<String>,
    pub golden_measurements: HashMap<usize, GoldenMeasurement>,
}

impl Verifier {
    pub fn new(
        attestation_report: AttestationReport,
        driver_rim: RIM,
        vbios_rim: RIM,
    ) -> anyhow::Result<Self> {
        let golden_measurements = Self::generate_golden_measurement_list(
            driver_rim.get_measurements(),
            vbios_rim.get_measurements(),
        )
        .context("Error generating golden measurement list")?;
        let runtime_measurements = attestation_report.get_measurements()?;

        let verifier = Verifier {
            is_msr_35_valid: true,
            runtime_measurements,
            golden_measurements,
        };

        Ok(verifier)
    }
    pub fn verify(&self) -> anyhow::Result<()> {
        info!("Comparing measurements (runtime vs golden)");

        ensure!(
            !self.runtime_measurements.is_empty(),
            "Warning : no measurements from attestation report received."
        );

        ensure!(
            !self.golden_measurements.is_empty(),
            "Warning : no golden measurements from RIMs received."
        );

        // Make sure that active golden measurement are always less than or equal to run time measurement
        ensure!(
            (self.golden_measurements.len() <= self.runtime_measurements.len()),
            "Warning : Golden measurement are more than measurements in Attestation report."
        );

        let mut mismached_measurements = Vec::new();

        for (idx, golden_measurement) in &self.golden_measurements {
            if *idx == 35 && !self.is_msr_35_valid {
                continue;
            }

            let mut is_matching = false;
            for j in 0..golden_measurement.alternatives {
                if golden_measurement.values[j] == self.runtime_measurements[*idx]
                    && golden_measurement.size == (self.runtime_measurements[*idx].len()) / 2
                {
                    is_matching = true;
                }
            }

            if !is_matching {
                mismached_measurements.push(idx);
            }
        }

        ensure!(mismached_measurements.is_empty(), format!("The runtime measurements are not matching with the golden measurements at the following index: {:?}", mismached_measurements));

        info!("The runtime measurements are matching with the golden measurements. GPU is in expected state.");
        Ok(())
    }

    fn generate_golden_measurement_list(
        driver_golden_measurements: HashMap<usize, GoldenMeasurement>,
        vbios_golden_measurements: HashMap<usize, GoldenMeasurement>,
    ) -> anyhow::Result<HashMap<usize, GoldenMeasurement>> {
        // This method takes the driver and vbios golden measurements and
        //combines them into a single dictionary with the measurement index as
        //the key and the golden measurement object as the value.

        let mut verifier_golden_measurement = driver_golden_measurements
            .into_iter()
            .filter(|(_, golden_measurement)| golden_measurement.active)
            .collect::<HashMap<usize, GoldenMeasurement>>();

        for (idx, golden_measurement) in vbios_golden_measurements {
            if golden_measurement.active {
                ensure!(
                    !verifier_golden_measurement.contains_key(&idx),
                    anyhow!(
                        "The driver and vbios RIM have measurement at the same index : {}",
                        idx
                    )
                );
                verifier_golden_measurement.insert(idx, golden_measurement.clone());
            }
        }

        Ok(verifier_golden_measurement)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::{ensure, Context};
    use log::info;

    use crate::{
        attestation::AttestationReport,
        rim::{create_rim, RIM},
        utils::{get_driver_rim_file_id, get_vbios_rim_file_id, init_logger_tests, RimName},
        verifier::Verifier,
    };

    async fn get_rims() -> anyhow::Result<(RIM, RIM)> {
        let version = "580.95.05".to_string();
        let rim_name = RimName::Driver;
        let file_name = get_driver_rim_file_id(&version);

        let driver_rim_content =
            String::from_utf8(fs::read(format!("./test_data/{}.xml", file_name))?)?;

        let driver_rim =
            create_rim(rim_name, driver_rim_content).context("Error creating driver RIM.")?;

        driver_rim.verify(version).await?;

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
        let vbios_rim_content =
            String::from_utf8(fs::read(format!("./test_data/{}.xml", vbios_rim_file_id))?)?;
        let vbios_rim =
            create_rim(rim_name, vbios_rim_content).context("Error creating vbios RIM.")?;

        vbios_rim
            .verify(vbios_version)
            .await
            .context("VBIOS RIM verification failed. Quitting now.")?;

        Ok((driver_rim, vbios_rim))
    }

    #[tokio::test]
    async fn test_verify() -> anyhow::Result<()> {
        init_logger_tests();

        let (driver_rim, vbios_rim) = get_rims().await?;

        let attestation_report: AttestationReport = serde_json::from_slice(
            &fs::read("./test_data/attestation_report.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let verifier_obj = Verifier::new(attestation_report, driver_rim, vbios_rim)?;
        verifier_obj.verify()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_with_duplicate_rim_golden_measurements() -> anyhow::Result<()> {
        init_logger_tests();

        let (driver_rim, _vbios_rim) = get_rims().await?;

        let attestation_report: AttestationReport = serde_json::from_slice(
            &fs::read("./test_data/attestation_report.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let verifier_creation_result =
            Verifier::new(attestation_report, driver_rim.clone(), driver_rim);

        ensure!(verifier_creation_result.is_err(), "Verifier creation should have failed because I passed the same rim twice. The step for generating golden measurement list should have failed bacuse of duplicate measurement.");

        let err_msg = verifier_creation_result
            .err()
            .ok_or(anyhow::anyhow!("Failed getting the error in negative test"))?;
        info!("Test failed with: {}", err_msg.root_cause());

        Ok(())
    }

    #[tokio::test]
    async fn test_verify_with_broken_runtime_measurement() -> anyhow::Result<()> {
        init_logger_tests();

        let (driver_rim, vbios_rim) = get_rims().await?;

        // Replaced the runtime measurement at index 31 from [128, 251, 25, 81, 242, 229, 105, 93, 226, 164, 126, 40, 117, 199, 188, 215, 99, 121, 69, 129, 19, 25, 230, 192, 104, 147, 251, 72, 158, 29, 79, 52, 217, 42, 158, 179, 140, 181, 246, 236, 164, 42, 203, 103, 11, 101, 138, 234]
        // to: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

        let attestation_report: AttestationReport = serde_json::from_slice(
            &fs::read("./test_data/attestation_report_broken.json")
                .context("Error reading attestation report test file")?,
        )
        .context("Error parsing file to AttestationReport")?;

        let verifier_obj = Verifier::new(attestation_report, driver_rim, vbios_rim)?;
        let verification_result = verifier_obj.verify();

        ensure!(verification_result.is_err(), "Verification should have failed because the runtime measurement at index 32 does not match the golden measurement contained in the RIMs.");

        let err_msg = verification_result
            .err()
            .ok_or(anyhow::anyhow!("Failed getting the error in negative test"))?;
        info!("Test failed with: {}", err_msg.root_cause());

        Ok(())
    }
}
