use anyhow::{Context, anyhow};
use glob::glob;
use inquire::{Confirm, Select};
use regex::Regex;
use std::{path::Path, process::Command};

pub fn setup_host() -> anyhow::Result<()> {
    let host_kernel_dir = Path::new("svsm-linux-host");

    if !host_kernel_dir.is_dir() {
        return Err(anyhow!(
            "Could not find ./svsm-linux-host/ directory. Make sure to run fluorite-baremetal get-artifacts first. Exiting..."
        ));
    }

    let path = host_kernel_dir
        .join("*.deb")
        .to_str()
        .unwrap_or("")
        .to_owned();
    let entries: Vec<String> = glob(&path)?
        .map(|path| path.ok().unwrap().display().to_string())
        .collect();

    let dpkg = Path::new("/usr/bin/dpkg");

    log::info!(
        "This program will invoke: {} -i {}",
        dpkg.display(),
        entries.join(" ")
    );
    let confirm = Confirm::new("Do you wish to continue?")
        .with_default(false)
        .with_help_message(
            "This will install the necessary custom kernel to use the COCONUT-SVSM on your HOST system",
        )
        .prompt()
        .context(format!(
            "Error. You will have to install the custom kernel yourself by running {} -i {}. Exiting...",
            dpkg.display(),
            entries.join(" ")
        ))?;

    if !confirm {
        return Err(anyhow::format_err!(
            "Confirmation failed. You will have to install the custom kernel yourself by running {} -i {}. Exiting...",
            dpkg.display(),
            entries.join(" ")
        ));
    }

    let child = Command::new(dpkg)
        .arg("-i")
        .args(entries)
        .output()
        .context(format!("Error executing {}", dpkg.display()))?;

    if !child.status.success() {
        return Err(anyhow::format_err!(
            "{}\n{} did not exit with a successful exit status. Are you running as root? Exiting...",
            String::from_utf8(child.stderr)?,
            dpkg.display().to_string()
        ));
    };

    log::info!(
        "This program will now modify the Grub boot options in order to boot the kernel just installed"
    );
    log::info!("Getting Grub entries");

    let grub_mkconfig = "/usr/sbin/grub-mkconfig";

    let child = Command::new(grub_mkconfig)
        .output()
        .context(format!("Error executing {}", grub_mkconfig))?;

    if !child.status.success() {
        return Err(anyhow::format_err!(
            "{}\n{} did not exit with a successful exit status. Are you running as root? Exiting...",
            String::from_utf8(child.stderr)?,
            grub_mkconfig
        ));
    };

    let mkconfig_output = String::from_utf8(child.stdout)?;

    let re = Regex::new(r"menuentry 'Ubuntu, with Linux").unwrap();
    let options: Vec<String> = mkconfig_output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if re.is_match(line) {
                // Maybe check length, I think it could panic
                let line_split: Vec<&str> = line.split("'").collect();
                if line_split.len() > 1 {
                    Some(line_split[1].to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let option = Select::new("Select the kernel to boot", options).raw_prompt()?;

    let re = Regex::new(r#"GRUB_DEFAULT=(.+)"#).unwrap();

    let default_grub_path = "/etc/default/grub";
    let default_grub = std::fs::read_to_string(default_grub_path)
        .context(format!("Error reading {}. Exiting...", default_grub_path))?;

    if let Some(m) = re.find(&default_grub) {
        let repl = format!("GRUB_DEFAULT=\"1>{}\"", option.index);
        log::info!(
            "The script will modify {}. It will replace: {} with {}",
            default_grub_path,
            m.as_str(),
            repl
        );

        let confirm = Confirm::new("Proceed?")
            .with_default(false)
            .prompt()
            .context(format!(
                "Error. You will have to modify {} yourself. Exiting...",
                default_grub_path
            ))?;

        if !confirm {
            return Err(anyhow::format_err!(
                "Confirmation failed. You will have to modify {} yourself. Exiting...",
                default_grub_path
            ));
        }

        let modified_default_grub = re
            .replace(
                &default_grub,
                format!("GRUB_DEFAULT=\"1>{}\"", option.index),
            )
            .to_string();

        std::fs::write(default_grub_path, modified_default_grub).context(format!(
            "Error writing {}. Are you running as root? Exiting...",
            default_grub_path
        ))?;
    } else {
        return Err(anyhow::format_err!(
            "Error. Could not match GRUB_DEFAULT=\"(.+)\") in {}. Exiting...",
            default_grub_path
        ));
    }
    log::info!("Updating grub");
    let update_grub = Path::new("/usr/sbin/update-grub");

    Command::new(update_grub)
        .output()
        .context(format!("Error executing {}", update_grub.display()))?;

    log::info!("In order to boot the new kernel you will have to perform a reboot");

    let reboot_path = Path::new("/usr/sbin/reboot");

    let confirm = Confirm::new("Proceed?")
        .with_default(false)
        .prompt()
        .context("Error. You will have to reboot the system youself. Exiting...")?;

    if !confirm {
        return Err(anyhow::format_err!(
            "Confirmation failed. You will have to reboot yourself. Exiting..."
        ));
    }

    log::info!("Rebooting...");
    Command::new(reboot_path)
        .output()
        .context(format!("Error executing {}", reboot_path.display()))?;

    Ok(())
}
