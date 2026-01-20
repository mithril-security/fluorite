#![feature(impl_trait_in_bindings)]
#![feature(duration_constructors)]

use anyhow::ensure;
use clap::Parser;
use provisioning_structs::structs::{AttestationBackend, parse_cli_measurements};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod client_tls_config;
mod deploy;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the zarf package used to provision the cluster
    #[arg(long)]
    zarf_package_path: PathBuf,

    /// Hex encoded string of the Golden PCR4 of FluoriteOS
    #[arg(long)]
    os_measurement: String,

    /// Path to the file containing the golden platform measurements
    #[arg(long)]
    platform_measurements_path: PathBuf,

    /// Path to the operator PEM encoded public certificate
    #[arg(long)]
    operator_cert_path: PathBuf,

    /// Path to the PKCS #8 PEM encoded operator private key
    #[arg(long)]
    operator_private_key_path: PathBuf,

    /// Path to the cluster.json file containing the cluster configuration
    #[arg(long)]
    cluster_file_path: PathBuf,

    /// Optional path to the file containing the variables used during deployment. Example: https://docs.zarf.dev/ref/config-files/#config-file-examples
    #[arg(long)]
    deployment_config_path: Option<PathBuf>,

    /// The attestation backend to use to verify the attestation received from the enclave
    #[arg(long)]
    attestation_backend: AttestationBackend,

    /// The size of the deployment, it defaults to 100GB. It's how much disk space the deployment needs.
    #[arg(long, default_value_t = 107374182400)]
    deployment_size_bytes: u64
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "operator=debug,attested_server_verifier=debug,provisioning_structs=debug,attestation=debug,attestation=debug,azure_cvm_attestation=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    ensure!(
        args.operator_cert_path.is_file(),
        "The path to the Operator certificate is not valid"
    );

    ensure!(
        args.operator_private_key_path.is_file(),
        "The path to the Operator private key is not valid"
    );

    ensure!(
        args.zarf_package_path.is_file(),
        "The path to the Zarf package is not valid"
    );

    ensure!(
        args.cluster_file_path.is_file(),
        "The path to the cluster file is not valid"
    );

    let (platform_measurements, os_measurement_vec) =
        parse_cli_measurements(args.platform_measurements_path, args.os_measurement)?;

    if let Some(path) = &args.deployment_config_path {
        ensure!(path.is_file(), "The path to the deployment config file is not valid");
    }

    deploy::provision_cluster(
        args.cluster_file_path,
        args.zarf_package_path,
        args.deployment_config_path,
        args.operator_cert_path,
        args.operator_private_key_path,
        os_measurement_vec,
        platform_measurements,
        args.attestation_backend,
        args.deployment_size_bytes,
    )
    .await?;

    Ok(())
}
