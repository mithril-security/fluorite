#![feature(impl_trait_in_bindings)]

use anyhow::{Context, ensure};
use attested_server_verifier::verifier::{
    AttestedTlsServerVerifier, make_cluster_policy, make_node_policy,
    make_webserver_attestation_validator_for_cluster,
};
use clap::Parser;
use log::info;
use provisioning_structs::structs::{AttestationBackend, parse_cli_measurements};
use rustls::ClientConfig;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The URL of the master node. (ex: https://vm.net-safe.dedyn.io)
    #[arg(long)]
    master_url: String,

    /// Path to the operator certificate
    #[arg(long)]
    operator_certificate_path: String,

    /// SHA256 hash of the package the cluster was provisioned with
    #[arg(long)]
    bundle_hash: String,

    /// Hex encoded string of the Golden PCR4 of FluoriteOS
    #[arg(long)]
    os_measurement: String,

    /// Path to the file containing the golden platform measurements
    #[arg(long)]
    platform_measurements_path: PathBuf,

    /// Optional URL to the Blob Storage containing the proof with attestation document (e.g. https://proofs.demo.mithrilsecurity.io)
    #[arg(long)]
    blob_storage_url: Option<String>,

    /// The attestation backend to use to verify the attestation received from the enclave
    #[arg(long)]
    attestation_backend: AttestationBackend,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "client=debug,attested_server_verifier=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let operator_certificate_path = Path::new(args.operator_certificate_path.as_str());

    ensure!(
        operator_certificate_path.is_file(),
        "The path to the operator certificate is not valid."
    );

    let operator_certificate = fs::read_to_string(operator_certificate_path)
        .context("Unable to read operator certificate")?;

    info!("Connecting to cluster");

    let (platform_measurements, os_measurement_vec) =
        parse_cli_measurements(args.platform_measurements_path, args.os_measurement)?;

    let node_policy = make_node_policy(
        platform_measurements,
        os_measurement_vec,
        args.attestation_backend,
    );

    // Cluster policy:
    // - The cluster operator has OPERATOR_CERTIFICATE
    // - The provisioning bundle hash of the cluster is BUNDLE_HASH
    let cluster_policy = make_cluster_policy(&operator_certificate, &args.bundle_hash);

    let server_verifier = AttestedTlsServerVerifier::new(
        make_webserver_attestation_validator_for_cluster(
            Arc::new(cluster_policy),
            Arc::new(node_policy),
        ),
        args.blob_storage_url,
    )?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(server_verifier))
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .use_preconfigured_tls(config)
        .build()
        .context("Error when creating reqwest client")?;

    info!("Requesting the homepage on {}", args.master_url);
    let response = client
        .get(args.master_url)
        .send()
        .await
        .context("Error while making a request to the app running in Kubernetes")?;

    let status = response.status();
    let response_string = response.text().await?;
    info!("Status: {status}");
    info!("Body: {response_string}");

    Ok(())
}
