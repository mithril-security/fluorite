use crate::web_error::AppError;
use anyhow::{Context, ensure};
use axum::{Json, extract::State, response::IntoResponse};
use azure_storage_blobs::prelude::ContainerClient;
use base64::prelude::*;
use dryoc::sign::PublicKey;
use log::info;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use x509_parser::{
    pem::parse_x509_pem,
    prelude::{FromDer, GeneralName, ParsedExtension, X509CertificationRequest},
};

use attestation::cbor;

use attested_server_verifier::verifier::{
    attestation_validator_after_provisioning, get_signing_public_key_from_eventlog,
    make_cluster_policy, make_node_policy,
};
use provisioning_structs::structs::{
    AttestationBackend, ClusterAttestation, PlatformMeasurements, Proof, verify_csr_signature,
};

#[derive(Clone)]
pub struct MyState {
    pub operator_certificate: String,
    pub bundle_hash: String,
    pub os_measurement_vec: Vec<u8>,
    pub platform_measurements: PlatformMeasurements,
    pub container_client: ContainerClient,
    pub storage_url: Url,
    pub attestation_backend: AttestationBackend,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MyRequestType {
    signed_csr_b64: String,
    attestation_b64: String,
    domain: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MyResponseType {
    pub success: bool,
}

// #[post("/verify_csr")]
pub(crate) async fn wrapper_verify_csr(
    State(mystate): State<MyState>,
    Json(args): Json<MyRequestType>,
) -> Result<impl IntoResponse, AppError> {
    let result = tokio::spawn(async move { mystate.verify_csr(args).await }).await??;
    Ok(Json(result))
}

impl MyState {
    async fn verify_csr(self, req: MyRequestType) -> anyhow::Result<MyResponseType> {
        info!("Verifying the CSR for domain {}", req.domain);

        info!("Received the request: {}", serde_json::to_string(&req)?);

        let attestation_bytes = BASE64_STANDARD
            .decode(req.attestation_b64.clone())
            .context("Failed decoding the base64 encoded CSR")?;

        let cluster_attestation: ClusterAttestation = cbor::from_slice(&attestation_bytes)?;

        // Cluster attestation validation
        let cluster_info = attestation_validator_after_provisioning(
            Arc::new(make_cluster_policy(
                &self.operator_certificate,
                self.bundle_hash.as_str(),
            )),
            Arc::new(make_node_policy(
                self.platform_measurements,
                self.os_measurement_vec,
                self.attestation_backend,
            )),
            &cluster_attestation,
        )
        .context("Error verifying the cluster attestation after provisioning")?;

        // Get the public key from the cluster_info
        let signing_public_key: PublicKey =
            get_signing_public_key_from_eventlog(&cluster_info.eventlog)?;
        let signed_csr_bytes = BASE64_STANDARD
            .decode(req.signed_csr_b64.clone())
            .context("Failed decoding the base64 encoded CSR")?;

        let csr_pem_bytes =
            verify_csr_signature(signed_csr_bytes, signing_public_key).map_err(|err| {
                rustls::Error::General(format!("Failed verifying CSR signature: {err:?}"))
            })?;

        let (_, csr_pem) =
            parse_x509_pem(&csr_pem_bytes).context("Could not parse the csr_bytes")?;
        let (_, csr) = X509CertificationRequest::from_der(&csr_pem.contents)
            .context("Failed parsing csr from PEM to X509CertificationRequest")?;

        // Check the SubjectAlternativeName extension against the value in the request
        if let Some(requested_extensions) = csr.requested_extensions() {
            for extension in requested_extensions {
                if let ParsedExtension::SubjectAlternativeName(ext) = extension {
                    let general_names = &ext.general_names;

                    ensure!(
                        general_names.len() == 1,
                        "The general name vec in the SubjectAlternativeName extension has a length different from 1"
                    );
                    ensure!(
                        general_names[0] == GeneralName::DNSName(&req.domain),
                        "The domain contained in the CSR does not match the one in the request parameters"
                    );
                }
            }
        }

        info!(
            "Verification successful. Uploading the proof for domain {} to Azure Blob Storage",
            req.domain
        );

        let hash_pub_key = hex::encode(Sha256::digest(
            &csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data,
        ));
        let blob_name = format!("by-hash-pub-key/{hash_pub_key}").to_string();

        let proof = Proof {
            signed_csr_b64: req.signed_csr_b64,
            attestation_b64: req.attestation_b64,
        };

        // Straight from the docs: https://crates.io/crates/azure_storage_blobs
        info!("Uploading blob at path {blob_name}");
        info!("{}", serde_json::to_string(&proof)?);

        let blob_client = self.container_client.blob_client(&blob_name);
        blob_client
            .put_block_blob(serde_json::to_vec(&proof)?)
            .content_type("application/json")
            .await
            .context("Error uploading the blob")?;

        let publish_url = self.storage_url.join(&blob_name)?;

        info!("Checking publication of the blob at {publish_url}");
        let published_proof: Proof = serde_json::from_str(
            &reqwest::get(publish_url)
                .await
                .context("Error performing GET request on the publish URL")?
                .text()
                .await?,
        )
        .context("Failed parsing published blob.")?;

        ensure!(
            proof == published_proof,
            "Publication check failed. The uploaded blob does not match the published one."
        );

        info!("Upload successful");

        Ok(MyResponseType { success: true })
    }
}
