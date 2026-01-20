use anyhow::{Context, anyhow, ensure};
use api::pem_to_der;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use base64::prelude::*;
use clap::Parser;
use log::info;
use provisioning_structs::structs::{AttestationBackend, ProvisioningState};
use rustls::ServerConfig;
use std::{
    fs::{self, read_to_string},
    net::SocketAddr,
    path::Path,
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    api::{
        MyState, Status, cluster_attestation, cluster_status, get_instance_identity_document,
        handler, init_as_master, init_as_slave, master_provision_cluster,
        slave_get_attestation_document, slave_join_cluster,
    },
    server_tls_acceptor::CustomAcceptor,
    server_tls_config::CertificateBearingClientAuth,
};

mod api;
mod client_tls_config;
mod server_tls_acceptor;
mod server_tls_config;
mod tpm;
mod web_error;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    port: u16,
    #[arg(long)]
    debug: bool,
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
                "provisioning=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    let subject_alt_names = vec!["MITHRILOS K3S BOOTSTRAP SERVICE CERT".to_string()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("Error while generating self signed ephemeral cert")?;

    // Fetch userdata once and extract configuration
    let userdata = get_userdata()
        .await
        .context("Could not get userdata from IMDS or filesystem")?;

    let creator_cert_pem = get_creator_cert_from_userdata(&userdata)
        .context("Could not get creator certificate from userdata")?;

    let attestation_backend = get_attestation_backend_from_userdata(&userdata)
        .context("Could not get attestation backend from userdata")?;

    info!("Attestation backend: {}", attestation_backend);

    let client_cert_verifier =
        CertificateBearingClientAuth::new(rustls::crypto::ring::default_provider());

    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(Arc::new(client_cert_verifier))
        .with_single_cert(
            vec![certified_key.cert.der().clone()],
            certified_key
                .signing_key
                .serialize_der()
                .try_into()
                .map_err(|e| anyhow!("{:?}", e))
                .context("Error bad private key")?,
        )
        .context("Error while creating the rustls ServerConfig")?;

    let state = MyState {
        status: Arc::from(Mutex::new(Status::Initial)),
        certified_key: Arc::from(certified_key),
        creator_cert: pem_to_der(&creator_cert_pem)?,
        provisioning_state: Arc::from(Mutex::new(ProvisioningState::NotStarted)),
        attestation_backend,
    };

    let app = Router::new()
        .route("/", get(handler))
        .route("/init_as_slave", post(init_as_slave))
        .route("/init_as_master", post(init_as_master))
        .route(
            "/slave/get_attestation_document",
            get(slave_get_attestation_document),
        )
        .route("/master/provision_cluster", post(master_provision_cluster))
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024 * 1024)) // Limit to 20GB
        .route("/master/cluster_attestation", get(cluster_attestation))
        .route("/cluster_status", get(cluster_status))
        .route("/slave/join_cluster", post(slave_join_cluster))
        .route(
            "/get_instance_identity_document",
            get(get_instance_identity_document),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));

    info!("listening on {}", addr);

    let acceptor = CustomAcceptor::new(RustlsAcceptor::new(RustlsConfig::from_config(Arc::from(
        config,
    ))));
    let server = axum_server::bind(addr).acceptor(acceptor);

    server.serve(app.into_make_service()).await.unwrap();
    Ok(())
}

/// Fetches the userdata from the filesystem, QEMU seed ISO, Azure IMDS, or GCP IMDS
async fn get_userdata() -> anyhow::Result<serde_json::Value> {
    // 1. Try QEMU seed ISO at /dev/vda (cloud-init seed image)
    // where the cloud-init seed image gets mounted by QEMU in bare metal vm.
    let mount_path = "/tmp/seed";
    let disk_path = "/dev/vda";

    if Path::new(disk_path).exists() {
        if !Path::new(mount_path).exists() {
            fs::create_dir_all(mount_path)?;
        }

        let output = Command::new("/usr/bin/mount")
            .args(["-t", "iso9660", disk_path, mount_path])
            .output()?;

        log::info!("{:?}", output);
        ensure!(output.status.success(), "Mount failed");

        let data_path = Path::new(mount_path).join("meta-data");
        let data = read_to_string(data_path).context("Error reading data_path")?;

        return serde_yaml::from_str(&data).context("Error interpreting data_path as yaml");
    }

    // 2. Try Azure IMDS
    let client = reqwest::Client::new();

    let azure_url = "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text";
    let azure_req = client
        .get(azure_url)
        .header("Metadata", "true")
        .timeout(Duration::from_secs(5))
        .build()?;

    let azure_resp = client.execute(azure_req).await;

    if let Ok(resp) = azure_resp {
        if resp.status().is_success() {
            let body = resp.text().await?;
            // Azure gives base64 encoded user-data
            return serde_json::from_slice::<serde_json::Value>(&BASE64_STANDARD.decode(body)?[..])
                .context("Failed converting to json the user-data got from Azure IMDS");
        }
    }

    // 3. Try GCP IMDS
    let gcp_url = "http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data";
    let gcp_req = client
        .get(gcp_url)
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(5))
        .build()?;

    let gcp_resp = client.execute(gcp_req).await;

    if let Ok(resp) = gcp_resp {
        if resp.status().is_success() {
            let body = resp.text().await?;
            // GCP gives raw JSON string user-data
            return serde_json::from_str(&body)
                .context("Failed converting to json the user-data got from GCP IMDS");
        }
    }

    Err(anyhow::anyhow!(
        "Failed to get user-data from /etc/user-data.json, /dev/vda, Azure IMDS, or GCP IMDS"
    ))
}

fn get_creator_cert_from_userdata(userdata: &serde_json::Value) -> anyhow::Result<String> {
    let creator_cert_pem: &str = userdata
        .get("creator_certificate_pem")
        .context("Could not find key `creator_certificate_pem` in data")?
        .as_str()
        .context("`creator_certificate_pem` must be a string")?;
    Ok(creator_cert_pem.to_string())
}

fn get_attestation_backend_from_userdata(
    userdata: &serde_json::Value,
) -> anyhow::Result<AttestationBackend> {
    let attestation_backend_str: &str = userdata
        .get("attestation_backend")
        .context("Could not find key `attestation_backend` in userdata")?
        .as_str()
        .context("`attestation_backend` must be a string")?;

    attestation_backend_str
        .parse::<AttestationBackend>()
        .context("Failed to parse attestation_backend")
}
