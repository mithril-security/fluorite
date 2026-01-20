#![feature(impl_trait_in_bindings)]

use anyhow::{Context, ensure};
use api::MyState;
use axum::{Router, routing::post};
use base64::prelude::*;
use cloud_helpers::azure_helper::AzureHelper;
use log::info;
use provisioning_structs::structs::{AttestationBackend, parse_cli_measurements};
use reqwest::Url;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, process::Command};
use tower_http::trace::TraceLayer;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api::wrapper_verify_csr;

mod api;
mod web_error;

#[derive(Deserialize, Debug)]
struct Args {
    /// Port on which to listen on
    port: u16,

    /// The base64 encoded operator certificate
    operator_certificate_b64: String,

    /// SHA256 hash of the package the cluster was provisioned with
    bundle_hash: String,

    /// Hex encoded string of the Golden PCR4 of FluoriteOS
    os_measurement: String,

    /// Path to the file containing the golden platform measurements
    platform_measurements_path: PathBuf,

    /// The attestation backend to use to verify the attestation received from the enclave
    attestation_backend: AttestationBackend,

    /// Name of the resource group where the Azure resources will be created
    resource_group_name: String,

    /// Storage account where to store the verified CSR
    attestation_storage_account_name: String,

    /// Storage URL
    storage_url: Url,

    /// Azure Subscription ID
    azure_subscription_id: String,

    /// HTTP Password
    password: String,

    /// Identity Resource ID
    identity_resource_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "attestation_transparency_service=debug,tower_http=debug,axum::rejection=trace,cloud_helpers=debug,provisioning_structs=debug" // azure_core=debug
                    .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = envy::from_env::<Args>().context("Error parsing environment variables")?;

    // Login using the user-assigned managed identities
    Command::new("/usr/bin/az")
        .args([
            "login",
            "--identity",
            "--resource-id",
            &args.identity_resource_id,
        ])
        .output()
        .context("Failed to execute 'az login' command. Is Azure CLI installed and in PATH?")?;

    ensure!(
        !args.operator_certificate_b64.is_empty(),
        "The base64 encoded operator certificate is empty."
    );

    let operator_certificate = String::from_utf8(
        BASE64_STANDARD
            .decode(args.operator_certificate_b64.clone())
            .context("Failed decoding the operator certificate from base64")?,
    )
    .context("Failed converting decoded operator certificate to string")?;

    let resource_group_name = args.resource_group_name;
    let storage_account_name = args.attestation_storage_account_name;

    let azure_helper = AzureHelper::new(args.azure_subscription_id).await?;

    let storage_client = azure_helper.get_azure_mgmt_storage_client()?;

    let container_name = "$web".to_string();
    let container_client = azure_helper
        .get_container_client(
            storage_client,
            resource_group_name,
            storage_account_name,
            container_name,
        )
        .await?;

    let (platform_measurements, os_measurement_vec) =
        parse_cli_measurements(args.platform_measurements_path, args.os_measurement)?;

    ensure!(!args.bundle_hash.is_empty(), "The bundle_hash is empty.");

    let state = MyState {
        operator_certificate: operator_certificate,
        bundle_hash: args.bundle_hash,
        os_measurement_vec: os_measurement_vec,
        platform_measurements: platform_measurements,
        container_client: container_client,
        storage_url: args.storage_url,
        attestation_backend: args.attestation_backend,
    };

    let app = Router::new()
        .route("/verify_csr", post(wrapper_verify_csr))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(ValidateRequestHeaderLayer::bearer(&args.password));

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));

    info!("listening on {addr}");

    let server = axum_server::bind(addr);

    server.serve(app.into_make_service()).await.unwrap();
    Ok(())
}
