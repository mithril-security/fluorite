use axum::extract::Query;
use axum::{Json, extract::State, response::IntoResponse};
use base64::prelude::*;
use oid_registry::{OID_PKCS1_RSAENCRYPTION, OidRegistry};
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use tokio::fs;
use url::Url;
use x509_parser::utils::format_serial;

use attestation::cbor;
use attested_server_verifier::verifier::{
    attestation_validator_after_provisioning, make_cluster_policy, make_node_policy,
};
use provisioning_structs::structs::{
    AttestationBackend, ClusterAttestation, ClusterInfo, NodeAttestationDocument,
    PlatformMeasurements, Proof,
};

use anyhow::{Context, anyhow};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

use crate::web_error::AppError;

#[derive(Clone)]
pub struct MyState {
    pub client: Client,
    pub os_measurement_vec: Vec<u8>,
    pub platform_measurements: PlatformMeasurements,
    pub operator_certificate: String,
    pub bundle_hash: String,
    pub attestation_backend: AttestationBackend,
    pub storage_url: Url,
    pub os_disk_url: Url,
    pub provisioning_package_url: Url,
}

// The struct to represent a single object in the JSON array.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificateEntry {
    pub issuer_ca_id: u64,
    pub issuer_name: String,
    pub common_name: String,
    pub name_value: String,
    pub id: u64,
    pub entry_timestamp: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub result_count: u64,
}

// The API returns a list of these entries.
type CertificateEntries = Vec<CertificateEntry>;

#[derive(Serialize, Deserialize)]
pub(crate) struct Domain {
    domain: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CertificateInfo {
    pub version: String,
    pub public_key: String,
    pub raw_certificate: String,
    pub hash_public_key: String,
    pub issuer: String,
    pub subject: String,
    pub subject_cn: String,
    pub san: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub time_to_expiration: String,
    pub is_valid_now: bool,
    pub serial_number: String,
    pub public_key_algorithm: String,
    pub public_key_size: usize,
    pub public_key_algorithm_parameters: String,
    pub signing_algorithm: String,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Entry {
    pub cert_sh_certificate_entry_info: CertificateEntry,
    pub attestation_backend: AttestationBackend,
    pub cluster_info: Option<ClusterInfo>,
    pub certificate_info: Option<CertificateInfo>,
    pub os_disk_url: String,
    pub provisioning_package_url: String,
    pub attestation_transparency_service_url: String,
    pub attestation_report: Option<Value>,
    pub reason: String,
}

// #[get("/get_entries")]
pub(crate) async fn wrapper_get_entries(
    State(mystate): State<MyState>,
    Query(args): Query<Domain>,
) -> Result<impl IntoResponse, AppError> {
    let result = tokio::spawn(async move { mystate.get_entries(args).await }).await??;
    Ok(Json(result))
}
impl MyState {
    async fn get_certificate_info(
        &self,
        id: u64,
        oid_registry: &OidRegistry<'_>,
    ) -> anyhow::Result<CertificateInfo> {
        log::info!("Downloading certificate entry with ID {} from CT logs.", id);
        let path = format!("./certificates/{id}.crt");

        let certificate_pem_bytes = if fs::try_exists(&path).await.context(format!(
            "Failed to check existance of certificate at {path}"
        ))? {
            log::info!("Using cached certificate with id {}", id);
            fs::read(&path)
                .await
                .context(format!("Failed to read cached certificate at {path}"))?
                .into()
        } else {
            log::info!("Getting certificate with id {} from crt.sh", id);
            let response_bytes = self
                .client
                .get(format!("https://crt.sh/?d={id}"))
                .send()
                .await
                .context(format!("Network error requesting certificate {id}"))?
                .error_for_status()?
                .bytes()
                .await?;

            fs::write(&path, &response_bytes)
                .await
                .context(format!("Failed to write certificate to {path}"))?;

            response_bytes
        };

        log::info!(
            "Got certificate entry with ID {} from CT logs. Processing fields.",
            id
        );
        let parsed_pem = parse_x509_pem(&certificate_pem_bytes)
            .context(format!(
                "Failed parsing PEM certificate for certificate entry with id {id}"
            ))?
            .1;
        let certificate_pem_string = String::from_utf8(certificate_pem_bytes.to_vec())
            .context("Error converting from certificate_pem_bytes to certificate_pem_string")?;

        let certificate = parse_x509_certificate(&parsed_pem.contents)
            .context(format!(
                "Failed parsing DER data for certificate entry with id {id}"
            ))?
            .1;

        let certificate_version = certificate.version.0.to_string();
        let public_key = &certificate.subject_pki;
        let parsed_public_key = &public_key
            .parsed()
            .context("Error parsing the public key")?;

        let public_key_size = parsed_public_key.key_size();
        let public_key_str = format_serial(&public_key.subject_public_key.data);
        let hash_pub_key = hex::encode(Sha256::digest(public_key.subject_public_key.data.clone()));
        let issuer = certificate.issuer().to_string();

        let san = &certificate
            .subject_alternative_name()
            .context("Error getting the certificate Subject Alternative Name. Duplicate Entry.")?
            .ok_or(anyhow!(
                "Error getting the certificate Subject Alternative Name. No Entry."
            ))?
            .value
            .general_names
            .iter()
            .map(|general_name| general_name.to_string())
            .collect::<Vec<String>>();

        let subject = certificate.subject();
        let subject_cn = subject
            .iter_common_name()
            .map(|cn| {
                cn.as_str()
                    .map(|s| s.to_string())
                    .map_err(|e| anyhow!("Error converting Common Name to string: {}", e))
            })
            .collect::<anyhow::Result<Vec<String>>>()?
            .join(",");

        let subject_str = subject.to_string();

        let not_before = certificate.validity.not_before.to_string();
        let not_after = certificate.validity.not_after.to_string();
        let is_valid_now = certificate.validity.is_valid();

        let duration_to_expiration_seconds = certificate
            .validity
            .time_to_expiration()
            .unwrap_or_default()
            .whole_seconds();
        let days = duration_to_expiration_seconds / 86_400; // 60 * 60 * 24
        let hours = (duration_to_expiration_seconds % 86_400) / 3_600;
        let minutes = (duration_to_expiration_seconds % 3_600) / 60;
        let seconds = duration_to_expiration_seconds % 60;
        let duration_to_expiration_str = format!(
            "{} days, {} hours, {} minutes and {} seconds",
            days, hours, minutes, seconds
        );

        let serial_number = certificate.raw_serial_as_string();
        let public_key_algorithm_oid = public_key.algorithm.oid();
        let public_key_algorithm_oid_entry =
            oid_registry.get(public_key_algorithm_oid).ok_or(anyhow!(
                "Did not find public key algorithm in the OID registry: {:?}",
                public_key_algorithm_oid
            ))?;
        let public_key_algorithm = format!(
            "{} ({})",
            public_key_algorithm_oid_entry.description(),
            public_key_algorithm_oid_entry.sn()
        );

        let public_key_algorithm_parameters = if public_key.algorithm.algorithm
            != OID_PKCS1_RSAENCRYPTION
        {
            let public_key_algorithm_parameters_any = public_key
                .algorithm
                .parameters
                .clone()
                .ok_or(anyhow!("Error parsing public key parameters"))?;

            let public_key_algorithm_parameters_oid = &public_key_algorithm_parameters_any
                .oid()
                .context("Error converting public key parameters to OID")?;

            let public_key_algorithm_parameters_oid_entry = oid_registry
                .get(public_key_algorithm_parameters_oid)
                .ok_or(anyhow!(
                    "Did not find public key algorithm parameters in the OID registry: {:?}",
                    public_key_algorithm_parameters_oid
                ))?;

            let public_key_algorithm_parameters = format!(
                "{} ({})",
                public_key_algorithm_parameters_oid_entry.description(),
                public_key_algorithm_parameters_oid_entry.sn()
            );
            public_key_algorithm_parameters
        } else {
            "None".to_string()
        };

        let signing_algorithm_oid = certificate.signature_algorithm.oid();
        let signing_algorithm_description_oid_entry =
            oid_registry.get(signing_algorithm_oid).ok_or(anyhow!(
                "Did not find signing algorithm in the OID registry"
            ))?;
        let signing_algorithm = format!(
            "{} ({})",
            signing_algorithm_description_oid_entry.description(),
            signing_algorithm_description_oid_entry.sn()
        );

        log::info!("Done processing certificate entry with ID {}.", id);
        Ok(CertificateInfo {
            public_key: public_key_str,
            raw_certificate: certificate_pem_string,
            version: certificate_version,
            hash_public_key: hash_pub_key.clone(),
            issuer: issuer,
            subject: subject_str,
            subject_cn: subject_cn,
            san: san.to_vec(),
            not_before: not_before,
            not_after: not_after,
            time_to_expiration: duration_to_expiration_str,
            is_valid_now: is_valid_now,
            serial_number: serial_number,
            public_key_algorithm: public_key_algorithm,
            public_key_size: public_key_size,
            public_key_algorithm_parameters: public_key_algorithm_parameters,
            signing_algorithm: signing_algorithm,
        })
    }

    async fn get_cluster_info(
        &self,
        id: u64,
        hash_public_key: &String,
        expected_attestation_backend: &AttestationBackend,
    ) -> anyhow::Result<(ClusterInfo, Value)> {
        log::info!(
            "Getting proof from Blob Storage for certificate with ID {}.",
            id
        );

        let path = format!("./proofs/{hash_public_key}.json");

        let proof = if fs::try_exists(&path).await.context(format!(
            "Failed to check existance of certificate at {path}"
        ))? {
            log::info!("Using cached proof with hash {}", hash_public_key);
            fs::read(&path)
                .await
                .context(format!("Failed to read cached certificate at {path}"))?
                .into()
        } else {
            log::info!(
                "Getting proof with hash {} from Blob Storage",
                hash_public_key
            );
            let proof_url = self
                .storage_url
                .join(&format!("/by-hash-pub-key/{}", hash_public_key))?;

            let response_bytes = self
                .client
                .get(proof_url.clone())
                .send()
                .await
                .context(format!(
                    "Network error requesting proof with id {id} from blob storage: {proof_url}"
                ))?
                .error_for_status()
                .context(format!(
                    "HTTP error requesting certificate with id {id} from blob storage: {proof_url}"
                ))?
                .bytes()
                .await?;

            fs::write(&path, &response_bytes)
                .await
                .context(format!("Failed to write proof to {path}"))?;

            response_bytes
        };

        log::info!(
            "Got proof from Blob Storage for certificate with ID {}.",
            id
        );
        let pproof: Proof = serde_json::from_slice(&proof)?;
        let attestation_bytes = BASE64_STANDARD
            .decode(pproof.attestation_b64)
            .context("Failed decoding the attestation")?;

        let cluster_attestation: ClusterAttestation =
            cbor::from_slice(&attestation_bytes).context("Error deserializing the attestation")?;
        let cluster_info = attestation_validator_after_provisioning(
            Arc::new(make_cluster_policy(
                &self.operator_certificate,
                &self.bundle_hash,
            )),
            Arc::new(make_node_policy(
                self.platform_measurements.clone(),
                self.os_measurement_vec.clone(),
                *expected_attestation_backend,
            )),
            &cluster_attestation,
        )
        .context("Error getting cluster_info")?;

        let attestation_document = cluster_attestation
            .multi_node_attestation
            .master_attestation_document
            .attestation_document;
        let attestation_report = match attestation_document {
            NodeAttestationDocument::SvsmVtpmAttestationDocument(
                svsm_vtpm_attestation_document,
            ) => serde_json::to_value(&svsm_vtpm_attestation_document.attestation_report)?,
            NodeAttestationDocument::ConfidentialVMAttestationDocument(
                confidential_vm_attestation_document,
            ) => serde_json::to_value(&confidential_vm_attestation_document.response_struct)?,
            NodeAttestationDocument::QEMUVmAttestationDocument(qemuvm_attestation_document) => {
                serde_json::to_value(qemuvm_attestation_document)?
            }
            NodeAttestationDocument::TrustedLaunchVmAttestationDocument(
                trusted_launch_vm_attestation_document,
            ) => serde_json::to_value(trusted_launch_vm_attestation_document)?,
            NodeAttestationDocument::GcpShieldedVmAttestationDocument(
                shielded_vm_attestation_document,
            ) => serde_json::to_value(shielded_vm_attestation_document)?,
        };

        log::info!("Certificate with ID {} has a valid proof.", id);
        Ok((cluster_info, attestation_report))
    }
    async fn validate_entry(
        &self,
        oid_registry: &OidRegistry<'_>,
        id: u64,
        expected_attestation_backend: &AttestationBackend,
    ) -> (
        Option<CertificateInfo>,
        Option<ClusterInfo>,
        Option<Value>,
        String,
    ) {
        let certificate_info = match self.get_certificate_info(id, oid_registry).await {
            Ok(certificate_info) => certificate_info,
            Err(err) => {
                return (None, None, None, format!("{:?} ", err));
            }
        };

        let (cluster_info, attestation_report) = match self
            .get_cluster_info(
                id,
                &certificate_info.hash_public_key,
                expected_attestation_backend,
            )
            .await
        {
            Ok(cluster_info) => cluster_info,
            Err(err) => {
                return (Some(certificate_info), None, None, format!("{:?} ", err));
            }
        };

        (
            Some(certificate_info),
            Some(cluster_info),
            Some(attestation_report),
            String::new(),
        )
    }
    async fn get_entries(self, domain: Domain) -> anyhow::Result<(Vec<Entry>, bool)> {
        let host_url = Url::parse(&domain.domain).context("Error parsing URL")?;
        let host = host_url
            .host_str()
            .ok_or(anyhow!("Could not extract the host name out of the url"))?;
        log::info!("Getting certificates of {} from CT logs.", host);
        // deduplicate=Y -> Remove Precertificates
        // match=single -> Return exact matches
        let response = self
            .client
            .get(format!("https://crt.sh/json?deduplicate=Y&match=single&q={host}"))
            .send()
            .await
            .context("Network error requesting certificates issued for domain to crt.sh")?
            .error_for_status()
            .context("HTTP error requesting certificates issued for domain to crt.sh")?;

        let certificate_entries = response.json::<CertificateEntries>().await?;

        let mut has_wildcard_certificate = false;

        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() > 2 {
            let wildcard_domain = format!("*.{}", parts[1..].join("."));
            let response = self
                .client
                .get(format!(
                    "https://crt.sh/json?match=ILIKE&q={wildcard_domain}"
                ))
                .send()
                .await
                .context("Network error requesting certificates issued for domain to crt.sh")?
                .error_for_status()
                .context("HTTP error requesting certificates issued for domain to crt.sh")?;
            let wildcard_cert_entries = response.json::<CertificateEntries>().await?;
            has_wildcard_certificate = !wildcard_cert_entries.is_empty();
        }

        let oid_registry = OidRegistry::default().with_crypto();
        let attestation_backend = self.attestation_backend;

        let entries = join_all(certificate_entries.iter().map(|certificate_entry| async {
            let id = certificate_entry.id;
            log::info!("Processing certificate with ID: {}", id);
            let (certificate_info, cluster_info, attestation_report, error_message) = self
                .validate_entry(&oid_registry, id, &attestation_backend)
                .await;
            Entry {
                cert_sh_certificate_entry_info: certificate_entry.clone(),
                attestation_backend: attestation_backend,
                certificate_info: certificate_info,
                cluster_info: cluster_info,
                attestation_report: attestation_report,
                reason: error_message,
                attestation_transparency_service_url: self.storage_url.to_string(),
                provisioning_package_url: self.provisioning_package_url.to_string(),
                os_disk_url: self.os_disk_url.to_string(),
            }
        }))
        .await;

        Ok((entries, has_wildcard_certificate))
    }
}
