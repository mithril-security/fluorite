use anyhow::{Context, anyhow, ensure};
use inquire::Confirm;
use reqwest::Url;
use sev::Generation;
use std::{
    fs::{self, File},
    io::{self, Cursor},
    path::PathBuf,
    process::Command,
    time::Duration,
};
use sysinfo::System;

pub fn check_host_configuration() -> anyhow::Result<()> {
    let name = System::name().ok_or(anyhow!("Error getting system name"))?;

    let version = System::os_version().ok_or(anyhow!("Error getting os version"))?;

    let full_name = format!("{} {}", name, version);

    log::info!("Detected OS Release: {}", full_name);
    if full_name != "Ubuntu 25.04" {
        log::warn!(
            "Compatibility with your OS was not tested, and launching guests might not work."
        );

        let confirm = Confirm::new("Do you wish to continue?")
            .with_default(false)
            .with_help_message("Launching guests has been tested only on Ubuntu:25.04 systems.")
            .prompt()
            .context(format!("Error. Exiting...",))?;

        if !confirm {
            return Err(anyhow::format_err!("Confirmation failed. Exiting..."));
        }
    }

    let host_generation = Generation::identify_host_generation()?;
    log::info!(
        "Detected host CPU generation: {}",
        host_generation.titlecase()
    );

    let files = [
        "/sys/module/kvm_amd/parameters/sev",
        "/sys/module/kvm_amd/parameters/sev_es",
        "/sys/module/kvm_amd/parameters/sev_snp",
    ];
    for file_name in files {
        let contents =
            fs::read_to_string(file_name).context(format!("Error reading {}.", file_name))?;
        ensure!(
            contents == "Y\n",
            anyhow::format_err!(
                "{} is not equal to Y, therefore is not enabled. Check system log `dmesg`.",
                file_name
            )
        );
    }

    // TODO: Check presence of GPU?

    Ok(())
}

pub fn get_and_verify_artifact(
    url: Url,
    destination: &PathBuf,
    slsa_verifier_path: Option<PathBuf>,
    provenance_path: Option<PathBuf>,
    source_uri: &str,
    insecure_skip_verify: bool,
) -> anyhow::Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).context("Failed to create directory structure")?;
    }

    log::info!("Getting {} and saving it to {}", url, destination.display());

    let client = reqwest::blocking::Client::new();

    let resp = client
        .get(url.clone())
        .timeout(Duration::from_mins(2))
        .send()?;

    let body = resp.bytes().context("Error getting svsm_package bytes")?;
    let mut content = Cursor::new(body);

    let mut out = File::create(destination).expect("Failed creating svsm.tar.gz");
    io::copy(&mut content, &mut out).expect("Failed copying downloaded content to svsm.tar.gz");

    if !insecure_skip_verify {
        log::info!("Done getting {}. Verifying the artifact...", url);

        let provenance_path = provenance_path.clone().ok_or(anyhow!(
            "The provenance path is empty! Add it with --provenance-path."
        ))?;
        let slsa_verifier_path = slsa_verifier_path
            .clone()
            .ok_or(anyhow!("The slsa verifier path is empty!"))?;

        let child = Command::new(slsa_verifier_path)
            .args([
                "verify-artifact",
                "--provenance-path",
                &provenance_path.display().to_string(),
                "--source-uri",
                source_uri,
                &destination.display().to_string(),
            ])
            .output()
            .context("Error executing slsa-verifier")?;

        if !child.status.success() {
            return Err(anyhow::format_err!(
                "{}\nVerification failed. Exiting...",
                String::from_utf8(child.stderr)?,
            ));
        }
        log::info!("The artifact has been successfully verified.");
    } else {
        log::info!("Done getting {}.", url);
        log::warn!("Skipping verification of the artifact because --insecure-skip-verify was used");
    }

    Ok(())
}
