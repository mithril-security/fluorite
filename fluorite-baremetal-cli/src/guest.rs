use anyhow::Context;
use std::ffi::OsString;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::utils::check_host_configuration;

#[allow(clippy::too_many_arguments)]
pub fn launch_guest(
    launch_vm_script_path: PathBuf,
    user_data_path: PathBuf,
    meta_data_path: PathBuf,
    ovmf_path: PathBuf,
    coconut_igvm_path: PathBuf,
    qemu_bin_path: PathBuf,
    qemu_lib_dir_path: PathBuf,
    disk_path: PathBuf,
    confidential: bool,
    virtualization_type: Option<String>,
    mem: u32,
    smp: u32,
    cpu: String,
    network: String,
    gpu_setup: bool,
) -> anyhow::Result<()> {
    check_host_configuration()?;

    // Preliminary checks
    if !user_data_path.is_file() {
        return Err(anyhow::format_err!(
            "Could not find the user data file needed to initialize the instance with cloud-init: {}. Exiting...",
            user_data_path.display()
        ));
    }

    if !meta_data_path.is_file() {
        return Err(anyhow::format_err!(
            "Could not find the meta data file needed to initialize the instance with cloud-init: {}. Exiting...",
            meta_data_path.display()
        ));
    }

    if !ovmf_path.is_file() {
        return Err(anyhow::format_err!(
            "The provided path for the ovmf file is not valid: {}. Exiting...",
            ovmf_path.display()
        ));
    }

    if !coconut_igvm_path.is_file() {
        return Err(anyhow::format_err!(
            "The provided path for the coconut igvm file is not valid: {}. Exiting...",
            coconut_igvm_path.display()
        ));
    }

    if !qemu_bin_path.is_file() {
        return Err(anyhow::format_err!(
            "The provided path for the qemu binary file is not valid: {}. Exiting...",
            qemu_bin_path.display()
        ));
    }

    if !qemu_lib_dir_path.is_dir() {
        return Err(anyhow::format_err!(
            "The provided path for the qemu libary directory is not valid: {}. Exiting...",
            qemu_lib_dir_path.display()
        ));
    }

    if !disk_path.is_file() {
        return Err(anyhow::format_err!(
            "The provided path for the os disk file is not valid: {}. Exiting...",
            disk_path.display()
        ));
    }

    log::info!("Creating seed image for cloud init");
    let cloud_localds_path = "/usr/bin/cloud-localds";
    let seed_img_path = Path::new("seed.img");

    let child = Command::new(cloud_localds_path)
        .arg(seed_img_path)
        .arg(user_data_path)
        .arg(meta_data_path)
        .output()
        .context(format!("Error executing {}. Install it with `sudo apt install cloud-image-utils`. See https://documentation.ubuntu.com/public-images/public-images-how-to/use-local-cloud-init-ds/.", cloud_localds_path))?;

    if !child.status.success() {
        return Err(anyhow::format_err!(
            "{}\nError generating cloud init file with {}. Exiting...",
            String::from_utf8(child.stderr)?,
            cloud_localds_path
        ));
    }

    let mut cmd = Command::new(&launch_vm_script_path);
    let mut cmd = cmd.args([
        "--mem",
        &mem.to_string(),
        "--smp",
        &smp.to_string(),
        "--cpu",
        &cpu,
        "--qemu-bin-path",
        &qemu_bin_path.display().to_string(),
        "--qemu-lib-dir-path",
        &qemu_lib_dir_path.display().to_string(),
        "--ovmf_path",
        &ovmf_path.display().to_string(),
        "--coconut_igvm_path",
        &coconut_igvm_path.display().to_string(),
        "--seed_img_path",
        &seed_img_path.display().to_string(),
        "--disk_path",
        &disk_path.display().to_string(),
        "--network",
        &network,
    ]);

    if confidential {
        cmd = cmd.args([
            "--confidential",
            "--virtualization_type",
            &virtualization_type.unwrap_or_default(),
        ]);
    }

    if gpu_setup {
        cmd = cmd.arg("--gpu_setup");
    }

    log::info!(
        "This program will invoke: {} {}",
        launch_vm_script_path.display(),
        cmd.get_args()
            .collect::<Vec<_>>()
            .join(&OsString::from(" "))
            .display()
    );

    // Inherit stdout to display output of subcommand.
    // Inherit stdin to be able to send kill signal to qemu

    let child = cmd
        .stdout(Stdio::inherit())
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .context(format!(
            "Error executing {}.",
            launch_vm_script_path.display()
        ))?;

    if !child.status.success() {
        return Err(anyhow::format_err!(
            "{}\nError running {}. Exiting...",
            String::from_utf8(child.stderr)?,
            launch_vm_script_path.display()
        ));
    }

    Ok(())
}
