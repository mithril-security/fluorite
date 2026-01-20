use anyhow::{Context, anyhow};
use inquire::{Text, validator::Validation};
use reqwest::Url;
use std::{
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use crate::utils::get_and_verify_artifact;

pub fn get_artifacts(local: bool, provenance_path: PathBuf) -> anyhow::Result<()> {
    if local {
        log::info!("You selected to use local artifacts.");

        let mut earthly_path = PathBuf::from("/usr/local/bin/earthly");
        if !earthly_path.is_file() {
            log::info!(
                "Earthly was not found at standard path {}.",
                earthly_path.display()
            );
            let validator = |input: &str| {
                let path = Path::new(input);
                // Second check: Ensure the file/directory exists
                if path.is_file() {
                    Ok(Validation::Valid)
                } else {
                    // Validation failed: path does not exist
                    Ok(Validation::Invalid(
                        "Could not find earthly binary. ".into(),
                    ))
                }
            };

            let earthly_path_str = Text::new("Input the absolute path to the earthly executable")
                .with_help_message("Install instructions: https://earthly.dev/get-earthly")
                .with_validator(validator)
                .prompt()?;

            earthly_path = PathBuf::from(earthly_path_str);
        }

        log::info!("Checking if in the current directory there is an Earthfile.");
        let earthfile_path = Path::new("./Earthfile");
        if !earthfile_path.is_file() {
            return Err(anyhow!(
                "Could not find ./Earthfile in the current working directory. Exiting..."
            ));
        }

        // TODO: Handle different platforms

        log::info!("Building the artifacts necessary for the AMD SEV-SNP platform");

        let targets = ["build-host-kernel-svsm", "svsm-setup"];
        for target in targets {
            let arg = format!("+{}", target);
            log::info!("Running: {} {}", earthly_path.display(), arg);

            let child = Command::new(earthly_path.clone())
                .arg(format!("+{}", target))
                .output()
                .context("Error executing earthly")?;

            if !child.status.success() {
                return Err(anyhow::format_err!(
                    "{}\nCould not build successfully earthly target {}. Exiting...",
                    String::from_utf8(child.stderr)?,
                    target
                ));
            }

            // Avoid earthly error: fatal error: concurrent map writes
            thread::sleep(Duration::from_millis(200));
        }

        log::info!("Building the os for the AMD SEV-SNP platform");
        let target = "mithril-os-svsm";
        let args = [
            "-P".to_string(), // Needs the privileged flag
            format!("+{}", target),
            "--OS_CONFIG=config-snp-baremetal.yaml".to_string(),
        ];

        log::info!("Running: {} {}", earthly_path.display(), args.join(" "));
        let child = Command::new(earthly_path)
            .args(args)
            .output()
            .context("Error executing earthly")?;

        if !child.status.success() {
            return Err(anyhow::format_err!(
                "{}\nCould not build successfully earthly target {}. Exiting...",
                String::from_utf8(child.stderr)?,
                target
            ));
        }
    } else {
        let source_uri = "github.com/mithril-security/fluorite";

        let bucket_base_url = Url::parse("https://storage.googleapis.com/fluorite/")?;

        log::info!(
            "You selected to use remote artifacts. Artifacts will be downloaded from the Google bucket ({}) and checked with slsa-verifier (https://github.com/slsa-framework/slsa-verifier)",
            bucket_base_url
        );

        if !provenance_path.is_file() {
            return Err(anyhow::format_err!(
                "Could not find provenance file at: {}. Exiting...",
                provenance_path.display()
            ));
        }

        let home = std::env::home_dir().context("Error getting home directory")?;

        let mut slsa_verifier_path = home.join("go/bin/slsa-verifier");

        if !slsa_verifier_path.is_file() {
            log::info!(
                "slsa-verifier was not found at standard path {}.",
                slsa_verifier_path.display()
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

            slsa_verifier_path = PathBuf::from(slsa_verifier_path_str);
        }

        let url = bucket_base_url
            .join("svsm.tar.gz")
            .context("Error joining bucket_base_url with the svsm_package")?;

        let svsm_package = PathBuf::from("./svsm.tar.gz");

        get_and_verify_artifact(
            url,
            &svsm_package,
            &slsa_verifier_path,
            &provenance_path,
            source_uri,
        )?;

        let url = bucket_base_url
            .join("platform/baremetal-amd-sev/local-svsm/image.raw")
            .context("Error joining bucket_base_url with the image path")?;

        let os_disk = PathBuf::from("./platform/baremetal-amd-sev/local-svsm/image.raw");

        get_and_verify_artifact(
            url,
            &os_disk,
            &slsa_verifier_path,
            &provenance_path,
            source_uri,
        )?;
    }

    Ok(())
}
