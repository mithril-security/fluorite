#![feature(impl_trait_in_bindings)]

use anyhow::Context;
use anyhow::ensure;
use axum::{Router, routing::get};
use log::info;

use base64::prelude::*;
use provisioning_structs::structs::AttestationBackend;
use provisioning_structs::structs::parse_cli_measurements;
use reqwest::Url;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api::MyState;
use crate::api::wrapper_get_entries;

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

    /// Storage URL
    storage_url: Url,

    /// OS Disk URL
    os_disk_url: Url,

    /// Provisioning package URL
    provisioning_package_url: Url,
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
                "domain_monitor=debug,tower_http=debug,axum::rejection=trace,cloud_helpers=debug,provisioning_structs=debug,attestation=debug,attested_server_verifier=debug,azure_cvm_attestation=debug"
                    .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = envy::from_env::<Args>().context("Error parsing environment variables")?;

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

    let (platform_measurements, os_measurement_vec) =
        parse_cli_measurements(args.platform_measurements_path, args.os_measurement)?;

    ensure!(!args.bundle_hash.is_empty(), "The bundle_hash is empty.");

    let client = reqwest::Client::new();
    let state = MyState {
        client: client,
        os_measurement_vec: os_measurement_vec,
        operator_certificate: operator_certificate,
        bundle_hash: args.bundle_hash,
        attestation_backend: args.attestation_backend,
        platform_measurements: platform_measurements,
        storage_url: args.storage_url,
        os_disk_url: args.os_disk_url,
        provisioning_package_url: args.provisioning_package_url,
    };

    let compression_layer: CompressionLayer = CompressionLayer::new().deflate(true).gzip(true);
    let app = Router::new()
        .fallback_service(ServeDir::new("./static/"))
        .route("/api/get_entries", get(wrapper_get_entries))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(compression_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));

    info!("listening on {addr}");

    let server = axum_server::bind(addr);

    server.serve(app.into_make_service()).await.unwrap();

    Ok(())
}
