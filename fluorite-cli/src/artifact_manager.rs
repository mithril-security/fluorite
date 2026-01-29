use anyhow::{Context, anyhow};
use inquire::{Text, validator::Validation};
use reqwest::Url;
use std::path::{Path, PathBuf};

use crate::utils::get_and_verify_artifact;

pub fn get_artifacts(
    release_version: String,
    provenance_path: Option<PathBuf>,
    insecure_skip_verify: bool,
) -> anyhow::Result<()> {
    let source_uri = "github.com/mithril-security/fluorite";

    let path = "fluorite-os/baremetal-amd-sev/";
    let bucket_base_url = Url::parse("https://storage.googleapis.com/fluorite/")?
        .join(format!("{}/{}", release_version, path).as_str())?;

    log::info!(
        "You selected to use remote artifacts. Artifacts will be downloaded from the Google bucket ({})",
        bucket_base_url
    );

    let mut slsa_verifier_path: Option<PathBuf> = None;
    if !insecure_skip_verify {
        log::info!(
            "Artifacts will be checked with slsa-verifier (https://github.com/slsa-framework/slsa-verifier)"
        );

        let provenance_path = provenance_path.clone().ok_or(anyhow!(
            "The provenance path is empty! Add it with --provenance-path."
        ))?;

        if !provenance_path.is_file() {
            return Err(anyhow::format_err!(
                "Could not find provenance file at: {}. Exiting...",
                provenance_path.display()
            ));
        }

        let home = std::env::home_dir().context("Error getting home directory")?;

        let mut slsa_verifier = home.join("go/bin/slsa-verifier");

        if !slsa_verifier.is_file() {
            log::info!(
                "slsa-verifier was not found at standard path {}.",
                slsa_verifier.display()
            );
            let validator = |input: &str| {
                let path = Path::new(input);
                // Second check: Ensure the file/directory exists
                if path.is_file() {
                    Ok(Validation::Valid)
                } else {
                    // Validation failed: path does not exist
                    Ok(Validation::Invalid(
                        "Could not find slsa-verifier binary. ".into(),
                    ))
                }
            };

            let slsa_verifier_path_str = Text::new("Input the absolute path to the slsa-verifier executable")
                .with_help_message("Install with `go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest`")
                .with_validator(validator)
                .prompt()?;

            slsa_verifier = PathBuf::from(slsa_verifier_path_str);

            slsa_verifier_path = Some(slsa_verifier)
        } else {
            slsa_verifier_path = Some(slsa_verifier)
        }
    }

    let url = bucket_base_url
        .join("svsm.tar.gz")
        .context("Error joining bucket_base_url with the svsm_package")?;

    let svsm_package = PathBuf::from("./svsm.tar.gz");

    get_and_verify_artifact(
        url,
        &svsm_package,
        slsa_verifier_path.clone(),
        provenance_path.clone(),
        source_uri,
        insecure_skip_verify,
    )?;

    let url = bucket_base_url
        .join("disk.raw")
        .context("Error joining bucket_base_url with the image path")?;

    let os_disk = PathBuf::from("./fluorite-os/baremetal-amd-sev/disk.raw");

    get_and_verify_artifact(
        url,
        &os_disk,
        slsa_verifier_path.clone(),
        provenance_path.clone(),
        source_uri,
        insecure_skip_verify,
    )?;

    let measurement_file = PathBuf::from("./fluorite-os/baremetal-amd-sev/os-measurement.json");
    let url = bucket_base_url
        .join("os-measurement.json")
        .context("Error joining bucket_base_url with the image path")?;

    get_and_verify_artifact(
        url,
        &measurement_file,
        slsa_verifier_path,
        provenance_path,
        source_uri,
        insecure_skip_verify,
    )?;

    Ok(())
}
