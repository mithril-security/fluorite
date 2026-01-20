use anyhow::{ensure, Context};
use base64::prelude::*;
use log::{debug, info};
use nvml_wrapper::enums::device::DeviceArchitecture;
use nvml_wrapper_sys::bindings::NVML_CC_GPU_CEC_NONCE_SIZE;
use x509_parser::prelude::*;
mod spdm_msrt_req_msg;
mod spdm_msrt_resp_msg;
mod verifier;
use serde::{Deserialize, Serialize};
mod rim;
use crate::utils::{c_str_to_string, format_vbios_version, get_vbios_rim_file_id, RimName};
use crate::{attestation::AttestationReport, nvml::MyNvmlHandler, utils::generate_nonce};
mod attestation;
mod nvml;
mod utils;
use crate::rim::create_rim;
use crate::verifier::Verifier;

const DEVICE_ROOT_CERT: &[u8; 768] = include_bytes!("../certs/verifier_device_root.pem");

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationResult {
    pub gpu_infos: Vec<GpuInfoObj>,
    pub nonce: [u8; NVML_CC_GPU_CEC_NONCE_SIZE as usize],
    pub driver_version: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GpuInfoObj {
    pub attestation_report: AttestationReport,
    pub uuid: String,
    pub architecture: DeviceArchitecture,
    pub vbios_version: String,
    pub info_rom_image_version: String,
    pub attestation_cert_chain: Vec<u8>,
}

pub fn serialize_attestation(attestations: AttestationResult) -> anyhow::Result<String> {
    let serialized_binary_attestation = bincode::serialize(&attestations)?;

    Ok(BASE64_STANDARD.encode(serialized_binary_attestation))
}

pub fn deserialize_attestation(attestations_b64: String) -> anyhow::Result<AttestationResult> {
    let decoded = BASE64_STANDARD.decode(attestations_b64)?;

    let deserialized_binary_attestation: AttestationResult = bincode::deserialize(&decoded)?;

    Ok(deserialized_binary_attestation)
}

pub async fn attest() -> anyhow::Result<AttestationResult> {
    //  Method to perform GPU Attestation and return an Attestation Response.
    let nvmlhandler = MyNvmlHandler::new()?;
    let number_of_available_gpus = nvmlhandler.get_device_count()?;

    ensure!(number_of_available_gpus > 0, "No GPU found");

    let nonce = generate_nonce()?;
    let gpu_infos = utils::get_gpus_infos(&nvmlhandler, nonce)?;
    let sys_driver_version = nvmlhandler.get_sys_driver_version()?;

    Ok(AttestationResult {
        gpu_infos,
        nonce,
        driver_version: sys_driver_version,
    })
}

pub fn parse_certificate_chain_pem(data: &[u8]) -> anyhow::Result<Vec<Pem>> {
    Ok(Pem::iter_from_buffer(data).collect::<Result<Vec<Pem>, PEMError>>()?)
}

pub async fn verify_gpu_evidence(attestation_result: AttestationResult) -> anyhow::Result<()> {
    //  Method to verify GPU Attestation reports
    // Run attestation verification for each GPU
    for (idx, gpu_info_obj) in attestation_result.gpu_infos.iter().enumerate() {
        info!("Verifying GPU: {}", idx);
        ensure!(
            gpu_info_obj.architecture == DeviceArchitecture::Hopper,
            "The architecture of the device is not Hopper"
        );
        let attestation_report_cert_chain_pem =
            parse_certificate_chain_pem(&gpu_info_obj.attestation_cert_chain)
                .context("Error parsing pem chain")?;

        let attestation_report_cert_chain: Vec<X509Certificate<'_>> =
            attestation_report_cert_chain_pem
                .iter()
                .map(|pem| pem.parse_x509())
                .collect::<Result<Vec<_>, _>>()?;

        debug!(
            "Attestation report chain: {:?}",
            attestation_report_cert_chain
        );

        let (_, root_cert_pem) = parse_x509_pem(DEVICE_ROOT_CERT)?;
        let root_cert = root_cert_pem
            .parse_x509()
            .context("Error parsing x509 root cert")?;

        ensure!(
            attestation_report_cert_chain.len() > 1,
            "The attestation_cert_chain has a contains less than two certificates"
        );

        ensure!(
            root_cert == attestation_report_cert_chain[attestation_report_cert_chain.len() - 1],
            "Root certificate received from server does not match expected Nvidia root certificate"
        );

        let attestation_report = gpu_info_obj.attestation_report.clone();
        let opaque_data = attestation_report.get_response_message()?.get_opaque_data();

        let fwid = hex::encode(
            opaque_data
                .get_data("OPAQUE_FIELD_ID_FWID")
                .context("Error getting OPAQUE_FIELD_ID_FWID")?,
        );

        utils::verify_gpu_certificate_chain(&attestation_report_cert_chain, fwid)
            .context("GPU attestation report certificate chain validation failed.")?;

        info!("GPU attestation report certificate chain validation successful.");

        utils::ocsp_certificate_chain_validation(
            &attestation_report_cert_chain,
            utils::CertChainVerificationMode::GpuAttestation,
        )
        .await
        .context("ocsp_certificate_chain_validation failed")?;

        info!("Authenticating attestation report");

        let attestation_report_leaf_cert = attestation_report_cert_chain[0].clone();

        utils::verify_attestation_report(
            gpu_info_obj.clone(),
            attestation_result.nonce,
            attestation_result.driver_version.clone(),
            attestation_report_leaf_cert,
        )
        .context("Error verifying attestation report")?;

        info!("Authenticating the RIMs.");
        info!("Authenticating Driver RIM.");

        // Given there is just one driever version for all devices, get the RIM just once and validate it later.
        let driver_rim_file_id = utils::get_driver_rim_file_id(&attestation_result.driver_version);
        let driver_rim_content = utils::fetch_rim_file(driver_rim_file_id).await?;

        let driver_rim = create_rim(RimName::Driver, driver_rim_content)
            .context("Error creating driver RIM.")?;

        driver_rim
            .verify(attestation_result.driver_version.clone())
            .await
            .context("Driver RIM verification failed. Quitting now.")?;

        info!("Driver RIM verification successful");
        info!("Authenticating VBIOS RIM.");

        let project = opaque_data
            .get_data("OPAQUE_FIELD_ID_PROJECT")
            .context("Error getting OPAQUE_FIELD_ID_PROJECT")?;
        let project_str = c_str_to_string(project)?;

        let project_sku = opaque_data
            .get_data("OPAQUE_FIELD_ID_PROJECT_SKU")
            .context("Error getting OPAQUE_FIELD_ID_PROJECT_SKU")?;
        let project_sku_str = c_str_to_string(project_sku)?;

        let chip_sku = opaque_data
            .get_data("OPAQUE_FIELD_ID_CHIP_SKU")
            .context("Error getting OPAQUE_FIELD_ID_CHIP_SKU")?;
        let chip_sku_str = c_str_to_string(chip_sku)?;

        let vbios_version = opaque_data
            .get_data("OPAQUE_FIELD_ID_VBIOS_VERSION")
            .context("Error getting OPAQUE_FIELD_ID_VBIOS_VERSION")?;
        let vbios_version_str = format_vbios_version(&vbios_version);

        let vbios_version_for_id = vbios_version_str.replace(".", "").to_uppercase();
        let vbios_version = vbios_version_str.to_lowercase();

        let vbios_rim_file_id = get_vbios_rim_file_id(
            &project_str,
            &project_sku_str,
            &chip_sku_str,
            &vbios_version_for_id,
        );

        let vbios_rim_content = utils::fetch_rim_file(vbios_rim_file_id).await?;
        let vbios_rim =
            create_rim(RimName::VBios, vbios_rim_content).context("Error creating VBIOS RIM.")?;

        vbios_rim
            .verify(vbios_version)
            .await
            .context("VBIOS RIM verification failed. Quitting now.")?;

        info!("VBIOS RIM verification successful");

        let verifier_obj = Verifier::new(attestation_report, driver_rim, vbios_rim)?;
        verifier_obj.verify().context(format!(
            "The verification of GPU {} with UUID {} resulted in failure.",
            idx, gpu_info_obj.uuid
        ))?;

        info!(
            "GPU {} with UUID {} verified successfully.",
            idx, gpu_info_obj.uuid
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        parse_certificate_chain_pem,
        utils::{init_logger_tests, verify_gpu_certificate_chain},
    };
    use anyhow::Context;
    use nvml_wrapper::structs::device::ConfidentialComputeGpuCertificate;
    use x509_parser::prelude::X509Certificate;

    #[test]
    fn test_parse_and_verify_certificate_chain() -> anyhow::Result<()> {
        init_logger_tests();
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

        let attestation_report_fwid = "f1ae7d0093a3f5689cced58045c9744f94eb2aa4ddca88135197fb41a7be45576c2881cf920e2cbcc090b1cb921f7b2d".to_string();
        verify_gpu_certificate_chain(&attestation_report_cert_chain, attestation_report_fwid)
            .context("GPU attestation report certificate chain validation failed.")
    }
}
