// use crate::attestation::extract_public_key;
use crate::attestation::AttestationReport;
use crate::nvml::MyNvmlHandler;
use crate::spdm_msrt_resp_msg;
use crate::GpuInfoObj;
use anyhow::bail;
use anyhow::{anyhow, ensure};
use asn1_rs::FromDer;
use base64::prelude::*;
use der::Decode;
use der::Encode;
use ecdsa::signature::Verifier;
use log::info;
use log::warn;
use pki::CertificateVerifier;
use reqwest::Url;

use spki::DecodePublicKey;
use x509_parser::der_parser::oid;

use anyhow::Context;
use reqwest::{self, Method};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha384;
use spdm_msrt_resp_msg::read_field_as_little_endian;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_ocsp::CertStatus;
use x509_ocsp::Request;
use x509_ocsp::{
    builder::OcspRequestBuilder, BasicOcspResponse, OcspRequest, OcspResponse, OcspResponseStatus,
};
use x509_parser::prelude::X509Certificate;
use xmltree::Element;

const OCSP_RETRY_COUNT: usize = 3;
const RIM_SERVICE_RETRY_COUNT: usize = 3;
const MAX_CERT_CHAIN_LENGTH: i32 = 5;

// NOTE: As of Jan 19 2026, the OCSP_URL and RIM_SERVICE_BASE_URL timeout.
// These URLs used to work in the past, but now they don't anymore.
// We'll keep both the Azure URL and Nvidia URL as fallback, hoping in the future the Azure URL will
// work again.
const OCSP_URL_NVIDIA: &str = "https://ocsp.ndis.nvidia.com/";
const OCSP_URL: &str = "https://useast2.thim.azure.net/nvidia/ocsp/";
const OCSP_VALIDITY_EXTENSION_HRS: usize = 336;
const OCSP_CERT_REVOCATION_EXTENSION_HRS: usize = 336;
const OCSP_CERT_REVOCATION_DRIVER_RIM_EXTENSION_HRS: usize = 336;
const OCSP_CERT_REVOCATION_VBIOS_RIM_EXTENSION_HRS: usize = 2160;
const RIM_SERVICE_BASE_URL_NVIDIA: &str = "https://rim.attestation.nvidia.com/v1/rim/";
const RIM_SERVICE_BASE_URL: &str = "https://useast2.thim.azure.net/nvidia/v1/rim/";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

// Public because needed in test
pub(crate) const SIGNATURE_LENGTH: usize = 96;

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum CertChainVerificationMode {
    GpuAttestation,
    OcspResponse,
    DriverRimCert,
    VbiosRimCert,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RimName {
    Driver,
    VBios,
}

impl fmt::Display for RimName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            RimName::Driver => write!(f, "driver"),
            RimName::VBios => write!(f, "vbios"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GoldenMeasurement {
    //A class to represent the individual golden measurement values from the RIM files.
    #[allow(unused)]
    pub rim_name: RimName,
    pub values: Vec<String>,
    #[allow(unused)]
    pub name: String,
    pub size: usize,
    pub alternatives: usize,
    pub active: bool,
}

use nvml_wrapper_sys::bindings::NVML_CC_GPU_CEC_NONCE_SIZE;

pub fn generate_nonce() -> anyhow::Result<[u8; NVML_CC_GPU_CEC_NONCE_SIZE as usize]> {
    // Generates cryptographically strong nonce to be sent to the SPDM requester via the nvml api for the attestation report.
    let mut random_bytes = [0u8; NVML_CC_GPU_CEC_NONCE_SIZE as usize];
    let sys_random = SystemRandom::new();
    sys_random
        .fill(&mut random_bytes)
        .map_err(|e| anyhow::format_err!("Error filling buffer with random bytes: {:?}", e))?;

    Ok(random_bytes)
}

fn extract_fwid(cert: X509Certificate) -> anyhow::Result<String> {
    // A static function to extract the FWID data from the given certificate.

    // The OID for the FWID extension.
    let tcg_dice_fwid_oid = oid!(2.23.133 .5 .4 .1);

    let value = cert
        .get_extension_unique(&tcg_dice_fwid_oid)?
        .ok_or_else(|| anyhow::format_err!("Error getting tcg_dice_fwid_oid"))?
        .value;

    let value = value.get((value.len() - 48)..).ok_or(anyhow!(
        "tcg_dice_fwid_oid extension is shorter than 48 bytes"
    ))?;

    Ok(hex::encode(value))
}

pub fn verify_gpu_certificate_chain(
    cert_chain: &Vec<X509Certificate>,
    attestation_report_fwid: String,
) -> anyhow::Result<()> {
    // A static function to perform the GPU device certificate chain verification.

    // Skipping the comparision of FWID in the attestation certificate if the Attestation report does not contains the FWID.
    if !attestation_report_fwid.is_empty() {
        let expected_fwid = extract_fwid(cert_chain[0].clone())?;

        ensure!(attestation_report_fwid == expected_fwid, format!("The firmware ID in the device certificate chain is not matching with the one in the attestation report. Expected: {}, Got: {}. ", expected_fwid, attestation_report_fwid));
        info!("The firmware ID in the device certificate chain is matching with the one in the attestation report.");
    }

    verify_certificate_chain(cert_chain, CertChainVerificationMode::GpuAttestation)
}

pub fn verify_certificate_chain(
    cert_chain: &Vec<X509Certificate<'_>>,
    mode: CertChainVerificationMode,
) -> anyhow::Result<()> {
    ensure!(
        !cert_chain.is_empty(),
        "No certificates found in certificate chain."
    );

    if mode == CertChainVerificationMode::GpuAttestation
        && cert_chain.len() != MAX_CERT_CHAIN_LENGTH as usize
    {
        return Err(anyhow::format_err!(
            "The number of certificates fetched from the GPU is unexpected. The chain length is {}",
            cert_chain.len()
        ));
    }

    let vec_of_certs: Vec<pki::Certificate> = cert_chain
        .iter()
        .map(|cert| {
            pki::Certificate::from_der(cert.as_raw())
                .map_err(|err| anyhow::format_err!("Error: {:?}", err))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut chain_verifier = CertificateVerifier::new();
    chain_verifier.ca_root(&vec_of_certs[vec_of_certs.len() - 1]);
    chain_verifier.default_paths(false);

    chain_verifier
        .verify(&vec_of_certs)
        .context("Error verifying the certificate chain")?;

    Ok(())
}

fn build_ocsp_request(
    cert: X509Certificate,
    issuer: X509Certificate,
) -> anyhow::Result<OcspRequest> {
    // A static method to build the ocsp request message.

    let cert = Certificate::from_der(cert.as_raw()).context("Error loading from_der cert")?;
    let issuer = Certificate::from_der(issuer.as_raw()).context("Error loading from_der issuer")?;

    let req = Request::from_cert::<Sha384>(&issuer, &cert)
        .map_err(|err| anyhow::format_err!("Error creating request: {}", err))?;

    let req_builder = OcspRequestBuilder::default().with_request(req);

    Ok(req_builder.build())
}

pub(crate) fn parse_xml_document(doc: &str) -> anyhow::Result<Element> {
    Element::parse(doc.as_bytes()).map_err(|err| anyhow!("Error parsing xml document: {}", err))
}

pub(crate) async fn ocsp_certificate_chain_validation(
    cert_chain: &Vec<X509Certificate<'_>>,
    mode: CertChainVerificationMode,
    // url: Url,
) -> anyhow::Result<()> {
    //Result<(bool,BaseSettings), Box<dyn std::error::Error>> {
    // A static method to perform the ocsp status check of the input certificate chain along with the
    let start_index = if mode == CertChainVerificationMode::GpuAttestation {
        1
    } else {
        0
    };

    let end_index = cert_chain.len() - 1;

    let ocsp_url = Url::parse(OCSP_URL_NVIDIA)?;
    ensure!(
        ocsp_url.scheme() == "https",
        anyhow::format_err!("OCSP_URL_NVIDIA does not start with https: {}", ocsp_url)
    );

    let ocsp_url_fallback = Url::parse(OCSP_URL)?;
    ensure!(
        ocsp_url_fallback.scheme() == "https",
        anyhow::format_err!("OCSP_URL does not start with https: {}", ocsp_url_fallback)
    );

    for i in start_index..end_index {
        let ocsp_request = build_ocsp_request(cert_chain[i].clone(), cert_chain[i + 1].clone())?;

        let ocsp_request_data: Vec<u8> = ocsp_request
            .to_der()
            .context("Error DER encoding ocsp_request")?;

        let ocsp_response = match fetch_ocsp_response_from_url(
            ocsp_request_data.clone(),
            ocsp_url.clone(),
        )
        .await
        {
            Ok(ocsp_response) => Ok(ocsp_response),
            Err(err) => {
                // Fallback to Nvidia OCSP Service if the fetch fails
                warn!("Error fetching OCSP Response from {}: {:?}", ocsp_url, err);
                warn!("Using fallback url: {}", ocsp_url_fallback);
                match fetch_ocsp_response_from_url(ocsp_request_data, ocsp_url_fallback.clone())
                    .await
                {
                    Ok(ocsp_response) => Ok(ocsp_response),
                    Err(err) => {
                        warn!(
                            "Error fetching OCSP Response from {}: {:?}",
                            ocsp_url_fallback, err
                        );
                        Err(anyhow::format_err!("Failed to fetch the ocsp response for certificate from both OCSP services."))
                    }
                }
            }
        }?;

        ensure!(
            ocsp_response.response_status == OcspResponseStatus::Successful,
            anyhow::format_err!(
                "Couldn't receive a proper response from the OCSP server. Response: {:?}",
                ocsp_response
            )
        );

        // Verify the Nonce in the OCSP response
        let basic_ocsp_resp = BasicOcspResponse::from_der(
            ocsp_response
                .response_bytes
                .ok_or(anyhow!("Error getting ocsp response bytes"))?
                .response
                .as_bytes(),
        )
        .context("Error creating BasicOcspResponse")?;

        let single_response_vec = basic_ocsp_resp.clone().tbs_response_data.responses;

        ensure!(
            single_response_vec.len() == 1,
            "The OCSP Single Response Vec should contain just one SingleResponse"
        );

        let single_response = single_response_vec[0].clone();

        // Verify the OCSP response is within the validity period
        let this_update = single_response.this_update.0.to_unix_duration();
        let next_update = single_response
            .next_update
            .ok_or(anyhow!("next_update field missing"))?
            .0
            .to_unix_duration();
        let next_update_extended =
            next_update + Duration::from_hours(OCSP_VALIDITY_EXTENSION_HRS as u64);
        let utc_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Error getting the current time")?;

        // Outside validity period, print warning
        if !((this_update <= utc_now) && (utc_now <= next_update)) {
            warn!("WARNING: OCSP FOR IS EXPIRED AFTER {:?}.", next_update);
        }

        // Outside extended validity period
        if !((this_update <= utc_now) && (utc_now <= next_update_extended)) {
            bail!(anyhow::format_err!("OCSP IS EXPIRED AND NO LONGER GOOD FOR ATTESTATION AFTER {:?} WITH {} HOURS EXTENSION PERIOD.", next_update_extended, OCSP_VALIDITY_EXTENSION_HRS));
        }

        // Verifying the ocsp response certificate chain.
        let ocsp_resp_certificates = basic_ocsp_resp
            .clone()
            .certs
            .ok_or(anyhow!("Error getting certs from basic ocps_response"))?;

        ensure!(
            !ocsp_resp_certificates.is_empty(),
            "The ocsp_resp_certificates is empty and it should contain at least one certificate"
        );

        let ocsp_response_leaf_cert = (ocsp_resp_certificates)[0]
            .to_der()
            .context("Error converting ocsp_resp_certificates to der")?;

        let (_, ocsp_response_leaf_cert) = X509Certificate::from_der(&ocsp_response_leaf_cert)
            .context("Error parsing x509 ocsp_response_leaf_cert")?;

        let mut ocsp_cert_chain = [ocsp_response_leaf_cert.clone()].to_vec();

        ocsp_cert_chain.extend_from_slice(&cert_chain[i..]);

        verify_certificate_chain(&ocsp_cert_chain, CertChainVerificationMode::OcspResponse)
            .context("Error verifying ocsp cert chain")?;

        info!("OCSP chain verification successful");

        // Verifying the signature of the ocsp response message.
        verify_ocsp_signature(ocsp_response_leaf_cert, basic_ocsp_resp).context("The ocsp response response for certificate {cert_common_name} failed due to signature verification failure.")?;

        info!("OCSP response signature verification successful");

        match single_response.cert_status {
            CertStatus::Good(_) => {}
            CertStatus::Revoked(revoked_info) => {
                // Get cert revoke timestamp
                let cert_revocation_time = revoked_info.revocation_time.0.to_unix_duration();

                let cert_revocation_reason = revoked_info
                    .revocation_reason
                    .ok_or(anyhow!("Error getting the cert revocation reason"))?;

                let cert_revocation_extension_hrs = match mode {
                    CertChainVerificationMode::GpuAttestation => OCSP_CERT_REVOCATION_EXTENSION_HRS,
                    CertChainVerificationMode::OcspResponse => OCSP_CERT_REVOCATION_EXTENSION_HRS,
                    CertChainVerificationMode::DriverRimCert => {
                        OCSP_CERT_REVOCATION_DRIVER_RIM_EXTENSION_HRS
                    }
                    CertChainVerificationMode::VbiosRimCert => {
                        OCSP_CERT_REVOCATION_VBIOS_RIM_EXTENSION_HRS
                    }
                };
                let cert_revocation_time_extended = cert_revocation_time
                    + Duration::from_hours(cert_revocation_extension_hrs as u64);

                // Cert is revoked, print warning
                warn!(
                    "WARNING: THE CERTIFICATE IS REVOKED FOR {:?}",
                    cert_revocation_reason
                );

                // Allow hold cert, or cert is revoked but within the extension period
                if utc_now <= cert_revocation_time_extended {
                    warn!("WARNING: THE CERTIFICATE IS REVOKED FOR {:?} BUT STILL GOOD FOR ATTESTATION UNTIL {:?} WITH {} HOURS OF GRACE PERIOD", cert_revocation_reason, cert_revocation_time_extended, cert_revocation_extension_hrs);
                } else {
                    bail!("WARNING: THE CERTIFICATE IS REVOKED FOR {:?} AND NO LONGER GOOD FOR ATTESTATION AFTER {:?}", cert_revocation_reason, cert_revocation_time_extended);
                }
            }
            CertStatus::Unknown(_) => {
                bail!("The single_response.cert_status is CertStatus::Unknown")
            }
        }
    }

    info!("The certificate chain revocation status verification successful.");

    Ok(())
}

async fn fetch_ocsp_response_from_url(
    ocsp_request_data: Vec<u8>,
    url: Url,
) -> anyhow::Result<OcspResponse> {
    // A static method to prepare http request and send it to the ocsp server
    let client = reqwest::Client::new();

    // Sending the ocsp request to the given url
    let mut retries = 0;

    let ocsp_response_data = loop {
        let response = client
            .request(Method::POST, url.clone())
            .timeout(REQUEST_TIMEOUT)
            .header("Content-Type", "application/ocsp-request")
            .body(ocsp_request_data.clone())
            .send()
            .await;
        match response {
            Ok(response) => break Ok(response.bytes().await?),
            Err(err) => {
                retries += 1;
                warn!(
                    "[{}/{}] Error while trying to get the OCSP response from: {}.",
                    retries, OCSP_RETRY_COUNT, url
                );

                if retries == OCSP_RETRY_COUNT {
                    break Err(anyhow::format_err!("Reached OCSP_RETRY_COUNT: {}", err));
                }
            }
        }
    }?;

    let ocsp_response = OcspResponse::from_der(&ocsp_response_data)
        .context("Error converting Nvidia OCSP response")?;

    Ok(ocsp_response)
}

fn verify_ocsp_signature(
    leaf_certificate: X509Certificate,
    ocsp_response: BasicOcspResponse,
) -> anyhow::Result<()> {
    // A static method to perform the signature verification of the ocsp response message.
    let signature = ocsp_response
        .signature
        .as_bytes()
        .ok_or(anyhow!("Error converting ocsp signature as bytes"))?;
    let data_vec = &ocsp_response
        .tbs_response_data
        .to_der()
        .context("Error converting tbs_response_data to_der")?;
    let pub_key = leaf_certificate.public_key();

    let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(pub_key.raw)
        .context("Error creating VerifyingKey")?;
    let signature =
        p384::ecdsa::Signature::from_der(signature).context("Error creating p384 Signature")?;
    verifying_key
        .verify(data_vec, &signature)
        .context("Error verifying ocsp signature")
}

pub async fn fetch_rim_file_from_url(url: Url) -> anyhow::Result<String> {
    // A static method to fetch the RIM file with the given file id from the given url.
    //    If the fetch fails, it retries for the maximum number of times specified by the max_retries parameter.
    //    If the max_retries is set to 0, it does not retry on failure and return None.
    let mut retries = 0;
    let client = reqwest::Client::new();

    let json_object: serde_json::Value = loop {
        let response = client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .context("Error making the request to the RIM service");

        match response {
            Ok(response) => break Ok(response.json().await?),
            Err(err) => {
                retries += 1;
                warn!(
                    "[{}/{}] Error while trying to get the RIM file from: {}",
                    retries, RIM_SERVICE_RETRY_COUNT, url
                );
                if retries == RIM_SERVICE_RETRY_COUNT {
                    break Err(anyhow::format_err!(
                        "Reached RIM_SERVICE_RETRY_COUNT {}",
                        err
                    ));
                }
            }
        }
    }?;

    let rim = json_object
        .get("rim")
        .ok_or(anyhow!("Could not get `rim` field"))?
        .as_str()
        .ok_or(anyhow!("Could not convert `rim` field to string"))?;

    let decoded_rim = BASE64_STANDARD
        .decode(rim)
        .context("Error base64 decoding `rim`")?;

    String::from_utf8(decoded_rim).context("Found invalid UTF-8")
}

fn check_https_and_join(url: Url, join_str: String) -> anyhow::Result<Url> {
    let mut url = url;
    ensure!(
        url.scheme() == "https",
        anyhow::format_err!(
            "The URL used to fetch the RIM field does not start with https: {}",
            url
        )
    );

    url =
        url.join(&join_str)
            .context(format!("Error joining {} with {}", url.as_str(), join_str))?;

    Ok(url)
}

pub async fn fetch_rim_file(rim_id: String) -> anyhow::Result<String> {
    // RIM service URL should start with https
    let base_url = check_https_and_join(Url::parse(RIM_SERVICE_BASE_URL_NVIDIA)?, rim_id.clone())?;
    let base_url_fallback = check_https_and_join(Url::parse(RIM_SERVICE_BASE_URL)?, rim_id)?;

    let rim_result = match fetch_rim_file_from_url(base_url.clone()).await {
        Ok(rim_result) => Ok(rim_result),
        Err(err) => {
            warn!("Error fetching RIM from {}: {:?}", base_url, err);
            warn!("Using fallback url: {}", base_url_fallback);
            match fetch_rim_file_from_url(base_url_fallback.clone()).await {
                Ok(rim_result) => Ok(rim_result),
                Err(err) => {
                    warn!("Error fetching RIM from {}: {:?}", base_url_fallback, err);
                    Err(anyhow::format_err!(
                        "Could not fetch the required RIM file from both RIM services: {},",
                        err
                    ))
                }
            }
        }
    }?;

    ensure!(!rim_result.is_empty(), "The fetched rim is empty!");

    Ok(rim_result)
}

pub fn get_vbios_rim_file_id(
    project: &str,
    project_sku: &str,
    chip_sku: &str,
    vbios_version: &str,
) -> String {
    // A static method to generate the required VBIOS RIM file id which needs to be fetched from the RIM service
    //    according to the vbios flashed onto the system.

    format!(
        "NV_GPU_VBIOS_{}_{}_{}_{}",
        project, project_sku, chip_sku, vbios_version
    )
}

pub fn get_driver_rim_file_id(driver_version: &str) -> String {
    // A static method to generate the driver RIM file id to be fetched from the RIM service corresponding to
    //    the driver installed onto the system.
    format!("NV_GPU_DRIVER_GH100_{}", driver_version)
}

pub fn format_vbios_version(version: &[u8]) -> String {
    // Converts the input VBIOS version to xx.xx.xx.xx.xx format.
    let value = read_field_as_little_endian(byte_string::ByteStr::new(version));
    let temp =
        value[value.len() / 2..].to_string() + &value[(value.len() / 2 - 2)..(value.len() / 2)];

    let mut idx = 0;
    let mut result = String::from("");
    for i in (0..temp.len() - 2).step_by(2) {
        result = result + &temp[i..i + 2] + ".";
        idx = i + 2;
    }
    result += &temp[idx..idx + 2];

    result
}

pub fn verify_attestation_report(
    gpu_info_obj: GpuInfoObj,
    nonce: [u8; NVML_CC_GPU_CEC_NONCE_SIZE as usize],
    sys_driver_version: String,
    attestation_report_leaf_cert: X509Certificate,
) -> anyhow::Result<()> {
    // Performs the verification of the attestation report. This contains matching the nonce in the attestation report with
    //the one generated by the cc admin, matching the driver version and vbios version in the attestation report with the one
    //fetched from the driver. And then performing the signature verification of the attestation report.

    // Here the attestation report is the concatenated SPDM GET_MEASUREMENTS request with the SPDM GET_MEASUREMENT response message.
    let request_nonce = gpu_info_obj
        .attestation_report
        .clone()
        .get_request_message()?
        .get_nonce()
        .ok_or(anyhow!("Error getting the nonce from request message"))?;

    ensure!(
        request_nonce.len() == NVML_CC_GPU_CEC_NONCE_SIZE as usize,
        format!(
            "The nonce contained in the request does not have the correct size. Size: {}",
            request_nonce.len()
        )
    );

    ensure!(request_nonce == nonce, "The nonce in the SPDM GET MEASUREMENT request message is not matching with the generated nonce.");

    info!("The nonce in the SPDM GET MEASUREMENT request message is matching with the generated nonce.");

    let opaque_data = gpu_info_obj
        .attestation_report
        .get_response_message()?
        .get_opaque_data();

    let driver_version_from_attestation_report = opaque_data
        .get_data("OPAQUE_FIELD_ID_DRIVER_VERSION")
        .context("Error getting OPAQUE_FIELD_ID_DRIVER_VERSION")?;
    let driver_version_from_attestation_report_str =
        c_str_to_string(driver_version_from_attestation_report)?;

    info!(
        "Driver version fetched from the attestation report : {:?}",
        driver_version_from_attestation_report_str
    );
    ensure!(driver_version_from_attestation_report_str == sys_driver_version, "The driver version in attestation report is not matching with the driver version fetched from the driver.");

    info!("Driver version in attestation report is matching.");

    let vbios_version_from_attestation_report = opaque_data
        .get_data("OPAQUE_FIELD_ID_VBIOS_VERSION")
        .context("Error getting OPAQUE_FIELD_ID_VBIOS_VERSION")?;

    let vbios_version_from_attestation_report_str =
        format_vbios_version(&vbios_version_from_attestation_report).to_uppercase();

    info!(
        "VBIOS version fetched from the attestation : {:?}",
        vbios_version_from_attestation_report_str
    );

    ensure!(vbios_version_from_attestation_report_str == gpu_info_obj.vbios_version, "The vbios version in attestation report is not matching with the vbios verison fetched from the driver.");

    info!("VBIOS version in attestation report is matching.");

    gpu_info_obj
        .attestation_report
        .verify_signature(attestation_report_leaf_cert, SIGNATURE_LENGTH)
        .context("Attestation report signature verification failed.")?;

    info!("Attestation report signature verification successful");
    Ok(())
}

pub(crate) fn get_gpus_infos(
    nvmlhandler: &MyNvmlHandler,
    nonce: [u8; NVML_CC_GPU_CEC_NONCE_SIZE as usize],
) -> anyhow::Result<Vec<GpuInfoObj>> {
    let num_gpus = nvmlhandler.get_device_count()?;
    let mut gpu_infos = Vec::with_capacity(num_gpus as usize);

    for idx in 0..num_gpus {
        let nvml_attestation_report = nvmlhandler.get_gpu_attestation_report(idx, nonce)?;

        let attestation_report = AttestationReport::new(nvml_attestation_report.attestation_report);

        let uuid = nvmlhandler.get_gpu_uuid(idx)?;
        let architecture = nvmlhandler.get_gpu_architecture(idx)?;
        let vbios_version = nvmlhandler.get_gpu_vbios_version(idx)?;
        let info_rom_image_version = nvmlhandler.get_gpu_info_rom_image_version(idx)?;
        let certificate_chain = nvmlhandler.get_gpu_certificate_chain(idx)?;

        // We ignore the certificate_chain.cert_chain as is not checked and include just the attestation_cert_chain.
        let attestation_cert_chain = certificate_chain.attestation_cert_chain;

        gpu_infos.push(GpuInfoObj {
            attestation_report,
            uuid,
            architecture,
            vbios_version,
            info_rom_image_version,
            attestation_cert_chain,
        });
    }

    Ok(gpu_infos)
}

pub(crate) fn c_str_to_string(vec: Vec<u8>) -> anyhow::Result<String> {
    Ok(String::from_utf8(vec)?.trim_end_matches('\0').to_string())
}

#[cfg(test)]
pub(crate) fn init_logger_tests() {
    use env_logger::Env;
    // Will fail if called more than once, but I don't care about that type of error so i can just discard it.
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();
}
