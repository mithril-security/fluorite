//! GCP Shielded VM Notarizer Service
//!
//! This service runs on a GCP Confidential VM (CVM with AMD SEV) and provides
//! notarization (signing) of `getShieldedVmIdentity` API responses for GCE Shielded VMs.
//!
//! GCE Shielded VMs have vTPMs with measured boot but their Attestation Keys (AK)
//! are not backed by an EK certificate chain. This service fills that gap by:
//!
//! 1. Running on a GCP CVM that has a proper AK certificate chain
//! 2. Generating a signing key at startup and logging it to the TPM event log
//! 3. Using that key to sign/notarize the identity of Shielded VMs
//!
//! Authentication is performed via TLS client certificates. Only clients presenting
//! the creator certificate (provided via instance metadata) are allowed.
//!
//! Verifiers can validate:
//! - The notarizer's CVM attestation (proving the signing key was generated in a CVM)
//! - The signature on the Shielded VM identity data

use anyhow::{Context, anyhow};
use api::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use log::info;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api::{get_notarizer_attestation, health_check, notarize_shielded_vm};
use crate::attestation::NotarizerState;
use crate::server_tls_config::CreatorCertificateVerifier;

mod api;
mod attestation;
mod gcp_api;
mod server_tls_config;
mod web_error;

/// GCP metadata server URL
const METADATA_SERVER_URL: &str = "http://metadata.google.internal/computeMetadata/v1";

/// GCP Shielded VM Notarizer Service
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Socket address to listen on (e.g., "0.0.0.0:8443" or "[::]:8443")
    #[arg(short, long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// GCP project ID where this notarizer can query Shielded VM identities
    /// If not set, the notarizer will use the project from the request
    #[arg(short, long)]
    allowed_project: Option<String>,
}

/// Fetch an attribute from GCP instance metadata
async fn fetch_metadata_attribute(key: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let url = format!("{}/instance/attributes/{}", METADATA_SERVER_URL, key);

    let response = client
        .get(&url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .context("Failed to fetch from metadata server")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Metadata server returned error {} for key '{}': {}",
            status,
            key,
            body
        );
    }

    response
        .text()
        .await
        .context("Failed to read metadata response body")
}

/// Convert PEM-encoded certificate to DER
fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let cert = CertificateDer::from_pem_slice(pem.as_bytes())
        .context("Failed to parse PEM certificate")?;
    Ok(cert.to_vec())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "gcp_shielded_vm_notarizer=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("GCP Shielded VM Notarizer starting...");

    // Fetch creator certificate from instance metadata
    info!("Fetching creator certificate from instance metadata...");
    let creator_cert_pem = fetch_metadata_attribute("creator-certificate")
        .await
        .context("Failed to fetch creator certificate from metadata. Make sure 'creator-certificate' attribute is set.")?;

    let creator_cert_der =
        pem_to_der(&creator_cert_pem).context("Failed to parse creator certificate")?;

    info!("Creator certificate loaded successfully");

    // Initialize the notarizer state (creates TPM context, generates signing key)
    let mut notarizer_state =
        NotarizerState::new().context("Failed to initialize notarizer state")?;

    info!("Notarizer state initialized");
    info!("Signing public key: {:?}", notarizer_state.verifying_key());

    // Log startup event and generate initial attestation
    info!("Generating initial CVM attestation...");
    let initial_attestation = notarizer_state
        .initialize_and_attest()
        .await
        .context("Failed to generate initial attestation")?;

    info!("CVM attestation obtained successfully");

    // Create application state with the attestation generated at startup
    let state = AppState {
        notarizer_state: Arc::new(notarizer_state),
        notarizer_attestation: initial_attestation,
        allowed_project: args.allowed_project,
    };

    // Build the router (no bearer token auth - using TLS client certs instead)
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/attestation", get(get_notarizer_attestation))
        .route("/notarize", post(notarize_shielded_vm))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    // Generate a self-signed certificate for the server
    let subject_alt_names = vec!["gcp-shielded-vm-notarizer".to_string()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("Error while generating self-signed ephemeral cert")?;

    // Create client certificate verifier that requires the creator certificate
    let client_cert_verifier =
        CreatorCertificateVerifier::new(creator_cert_der, rustls::crypto::ring::default_provider());

    // Create TLS config with client cert verification
    let tls_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(Arc::new(client_cert_verifier))
        .with_single_cert(
            vec![certified_key.cert.der().clone()],
            certified_key
                .signing_key
                .serialize_der()
                .try_into()
                .map_err(|e| anyhow!("{:?}", e))
                .context("Error converting private key")?,
        )
        .context("Error while creating the rustls ServerConfig")?;

    let rustls_config = RustlsConfig::from_config(Arc::new(tls_config));

    info!(
        "Listening on {} (TLS with client certificate authentication)",
        args.listen
    );

    let server = axum_server::bind_rustls(args.listen, rustls_config);
    server.serve(app.into_make_service()).await?;

    Ok(())
}
