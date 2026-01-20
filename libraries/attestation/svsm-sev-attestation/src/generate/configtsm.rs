use anyhow::{Context, Result};
use sev::firmware::guest::AttestationReport;
use std::fs;
use std::path::Path;

/// Fetches the AttestationReport from the configtsm and generate a random nonce
/// that is used with the Attestation report.
///
pub(crate) fn get_attestion_report(nonce: &[u8; 64]) -> Result<(AttestationReport, Vec<u8>)> {
    let configtsm = String::from("/sys/kernel/config/tsm/report/");

    let path_configtsm = Path::new(&configtsm);
    // Creating report directory
    fs::create_dir_all(path_configtsm.join("report1"))?;

    // The GUID corresponds to the GUID specified for the single attest for vTPM
    // see https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/58019.pdf page 35
    let attest_vtpm_guid = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3";
    fs::write(
        path_configtsm.join("report1/service_guid"),
        attest_vtpm_guid,
    )
    .expect("Failed to write to service_guid file");

    // Service provider must be changed to svsm
    let service_provider = "svsm";
    fs::write(
        path_configtsm.join("report1/service_provider"),
        service_provider,
    )
    .expect("Failed to add service provider ");

    fs::write(path_configtsm.join("report1/inblob"), nonce)
        .expect("Failed to write to inblob file");

    //read outblob file
    let outblob =
        fs::read(path_configtsm.join("report1/outblob")).expect("Failed to read outblob file");

    //write outblob to file
    //fs::write("attestation_report.bin", &outblob).expect("Failed to write outblob to file");
    let manifest = fs::read(path_configtsm.join("report1/manifestblob"))
        .expect("Failed to read manifest file");

    let report = AttestationReport::from_bytes(&outblob)
        .context("Could not deserialize the binary outblob")?;

    Ok((report, manifest))
}
