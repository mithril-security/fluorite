use anyhow::{Context, bail, ensure};
use asn1_rs::oid;
use attestation::cbor;
use dryoc::sign::PublicKey;
use provisioning_structs::structs::AttestationBackend;
use provisioning_structs::structs::AttestationValidator;
use provisioning_structs::structs::OS_MEASUREMENT_SLOT;
use provisioning_structs::structs::PlatformMeasurements;
use provisioning_structs::structs::make_basic_cluster_attestation_validator;
use provisioning_structs::structs::make_basic_multinode_attestation_validator;
use provisioning_structs::structs::node_attestation_document_with_events_validator;
use provisioning_structs::structs::verify_csr_signature;

use base64::prelude::*;
use log::info;
use provisioning_structs::structs::ClusterInfo;
use provisioning_structs::structs::MultiNodeAttestation;
use provisioning_structs::structs::MultiNodeInfo;
use provisioning_structs::structs::NodeAttestationDocumentWithEvents;
use provisioning_structs::structs::NodePolicy;
use provisioning_structs::structs::NodeWithEventsInfo;
use provisioning_structs::structs::Proof;
use provisioning_structs::structs::{BootstrapperTpmEvents, ClusterAttestation, TpmEvent};
use ref_cast::RefCast;
use reqwest::StatusCode;
use reqwest::Url;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::{RootCertStore, pki_types};
use sha2::{Digest, Sha256};
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::task;
use tpm_quote::common::HashingAlgorithm;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

/// A trait that can be used to check a cluster policy
///
/// Implementors can use it to validate the cluster info.
/// They should return an error to signal that the policy is not respected
pub trait ClusterPolicy = Fn(&ClusterInfo) -> anyhow::Result<()>;
pub trait MultinodePolicy = Fn(&MultiNodeInfo) -> anyhow::Result<()>;

pub struct AttestedTlsServerVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
    webserver_attestation_validator: Box<
        dyn AttestationValidator<RawAttestationDocument, (Pem, PublicKey)> + Send + Sync + 'static,
    >,
    blob_storage_url: Option<Url>,
}

impl Debug for AttestedTlsServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerCertVerifierForAttestedService")
    }
}

#[derive(RefCast)]
#[repr(transparent)]
pub struct RawAttestationDocument([u8]);

/// Returns a basic cluster policy that checks the operator certificate and the provisioning bundle digest against provided values
pub fn make_cluster_policy(
    expected_operator_cert: &str,
    expected_provisioning_bundle_digest: &str,
) -> impl ClusterPolicy + Send + Sync + 'static {
    let expected_operator_cert = expected_operator_cert.to_string();
    let expected_provisioning_bundle_digest = expected_provisioning_bundle_digest.to_string();
    move |ClusterInfo {
              operator_cert,
              provisioning_bundle_digest,
              ..
          }|
          -> anyhow::Result<()> {
        ensure!(
            operator_cert == &expected_operator_cert,
            format!(
                "Operator certificate does not match. \nExpected:\n{} \nGot:\n{}\n",
                expected_operator_cert, operator_cert
            )
        );
        ensure!(
            provisioning_bundle_digest == &expected_provisioning_bundle_digest,
            format!(
                "Provisioning bundle digest does not match. \nExpected:\n{} \nGot:\n{}\n",
                expected_provisioning_bundle_digest, provisioning_bundle_digest
            )
        );
        Ok(())
    }
}

pub fn make_node_policy(
    expected_platform_measurements: PlatformMeasurements,
    expected_os_measurement_vec: Vec<u8>,
    expected_attestation_backend: AttestationBackend,
) -> impl NodePolicy + Send + Sync + 'static {
    move |&NodeWithEventsInfo {
              attestation_backend,
              ref pcr_data,
              ..
          }: &NodeWithEventsInfo| {
        ensure!(
            attestation_backend == expected_attestation_backend,
            format!(
                "Wrong attestation backend. \nExpected:\n{} \nGot:\n{}\n",
                attestation_backend, expected_attestation_backend
            )
        );

        // Verification of PCR8 happens in `node_attestation_document_with_events_validator`
        // What's left to verify is PCR 4, the os_measurement, and the platform measurements.

        let os_measurement = pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .context("No SHA256 PCR Bank")?
            .bank
            .get(&OS_MEASUREMENT_SLOT.pcr_slot)
            .context("Failed to get OS Measurement PCR bank")?;

        ensure!(
            os_measurement.0 == expected_os_measurement_vec,
            format!(
                "Bad OS measurement. \nExpected:\n{} \nGot:\n{}\n",
                hex::encode(expected_os_measurement_vec.clone()),
                hex::encode(os_measurement.0.clone())
            )
        );

        if !expected_platform_measurements
            .expected_pcr_data
            .iter()
            .any(|expected_pcr_data| expected_pcr_data.is_subset(pcr_data))
        {
            bail!(
                "None of the expected platform measurements were a subset of the pcr_data from the enclave. \nExpected:\n{} \nGot:\n{}\n",
                serde_json::to_string_pretty(&expected_platform_measurements)?,
                serde_json::to_string_pretty(&pcr_data)?
            )
        }

        Ok(())
    }
}

/// Returns a basic multinode policy that checks the operator certificate against provided values
pub fn make_multinode_policy(
    expected_operator_cert: &str,
) -> impl MultinodePolicy + Send + Sync + 'static {
    let expected_operator_cert = expected_operator_cert.to_string();

    move |MultiNodeInfo {
              operator_cert_pem, ..
          }|
          -> anyhow::Result<()> {
        ensure!(
            operator_cert_pem == &expected_operator_cert,
            format!(
                "Operator certificate does not match. \nExpected:\n{} \nGot:\n{}\n",
                expected_operator_cert, operator_cert_pem
            )
        );
        Ok(())
    }
}

pub trait WebServerAttestationValidator =
    AttestationValidator<RawAttestationDocument, (Pem, PublicKey)>;

pub fn make_webserver_attestation_validator_for_cluster(
    cluster_policy: Arc<dyn ClusterPolicy + Send + Sync>,
    node_policy: Arc<dyn NodePolicy + Send + Sync>,
) -> impl WebServerAttestationValidator + Send + Sync + 'static {
    move |RawAttestationDocument(att_doc): &RawAttestationDocument| -> anyhow::Result<(Pem, PublicKey)> {
        // Parse the attestation document
        let cluster_attestation: ClusterAttestation = cbor::from_slice(att_doc)?;

        // Cluster attestation validation
        let cluster_info = attestation_validator_after_provisioning(
            cluster_policy.clone(),
            node_policy.clone(),
            &cluster_attestation,
        )?;

        let k3s_root_ca_pem = get_root_ca_from_eventlog(&cluster_info.eventlog)?;
        let public_key = get_signing_public_key_from_eventlog(&cluster_info.eventlog)?;
        anyhow::Ok((k3s_root_ca_pem, public_key))
    }
}

pub fn attestation_validator_before_provisioning(
    multinode_policy: impl MultinodePolicy + Send + Sync + 'static,
    node_policy: impl NodePolicy + Send + Sync + 'static,
    multinode_attestation: &MultiNodeAttestation,
) -> anyhow::Result<MultiNodeInfo> {
    let node_policy = &node_policy;

    let node_attestation_validator =
        move |node_attestation: &NodeAttestationDocumentWithEvents| -> anyhow::Result<_> {
            let node_info =
                node_attestation_document_with_events_validator.validate(node_attestation)?;
            node_policy(&node_info)?;
            Ok(node_info)
        };

    let multinode_policy = &multinode_policy;
    let multinode_info = make_basic_multinode_attestation_validator(&node_attestation_validator)
        .validate(multinode_attestation)?;
    multinode_policy(&multinode_info)?;
    Ok(multinode_info)
}

pub fn attestation_validator_after_provisioning(
    cluster_policy: Arc<dyn ClusterPolicy + Send + Sync>,
    node_policy: Arc<dyn NodePolicy + Send + Sync>,
    cluster_attestation: &ClusterAttestation,
) -> anyhow::Result<ClusterInfo> {
    let node_policy = &node_policy;

    let node_attestation_validator =
        move |node_attestation: &NodeAttestationDocumentWithEvents| -> anyhow::Result<_> {
            let node_info = node_attestation_document_with_events_validator
                .validate(node_attestation)
                .context("Error node_attestation_document_with_events_validator")?;
            node_policy(&node_info)?;
            Ok(node_info)
        };

    let cluster_policy = &cluster_policy;
    let cluster_attestation_validator =
        move |cluster_attestation: &ClusterAttestation| -> anyhow::Result<_> {
            let cluster_info =
                make_basic_cluster_attestation_validator(&node_attestation_validator)
                    .validate(cluster_attestation)
                    .context("Error make_basic_cluster_attestation_validator().validate")?;
            cluster_policy(&cluster_info)?;
            Ok(cluster_info)
        };

    // Cluster attestation validation
    let cluster_info = cluster_attestation_validator
        .validate(cluster_attestation)
        .context("Error cluster attestation validation")?;
    Ok(cluster_info)
}

pub fn get_signing_public_key_from_eventlog(
    eventlog: &[TpmEvent],
) -> Result<PublicKey, anyhow::Error> {
    let Some(TpmEvent::Bootstrapper(BootstrapperTpmEvents::SingatureInfo { public_key })) =
        eventlog.get(2)
    else {
        bail!("Could not find a SingatureInfo event in the event_log");
    };
    Ok(public_key.clone())
}

/// Returns the root CA from the list of events in ClusterInfo
fn get_root_ca_from_eventlog(eventlog: &[TpmEvent]) -> Result<Pem, anyhow::Error> {
    let Some(TpmEvent::Bootstrapper(BootstrapperTpmEvents::K3sClusterCreated { k3s_root_ca_pem })) =
        eventlog.first()
    else {
        bail!("Could not find an K3sClusterCreated event in the event_log");
    };
    let (_, root_ca_pem) = parse_x509_pem(k3s_root_ca_pem.as_bytes())
        .context("Failed parsing the K3s CA certificate from the event log")?;
    Ok(root_ca_pem)
}

impl AttestedTlsServerVerifier {
    pub fn new(
        webserver_attestation_validator: impl WebServerAttestationValidator + Send + Sync + 'static,
        blob_storage_url: Option<String>,
    ) -> anyhow::Result<AttestedTlsServerVerifier> {
        let url = if let Some(url) = blob_storage_url {
            Some(Url::parse(&url).context("Could not parse blob storage url")?)
        } else {
            None
        };

        Ok(AttestedTlsServerVerifier {
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
            webserver_attestation_validator: Box::new(webserver_attestation_validator),
            blob_storage_url: url,
        })
    }
}

async fn get_public_proof(url: Url) -> anyhow::Result<Proof> {
    let response = reqwest::get(url)
        .await
        .context("Failed making request to ATS")?;

    if response.status() == StatusCode::OK {
        serde_json::from_str(
            &response
                .text()
                .await
                .context("Failed getting response text")?,
        )
        .context("Error converting response text to Proof.")
    } else {
        Err(anyhow::format_err!("Status code: {}", response.status()))
    }
}
// async fn verify_public_proof(
//     attested_tls_server_verifier: &AttestedTlsServerVerifier,
//     end_entity: &pki_types::CertificateDer<'_>,
// ) -> Result<(Pem, Vec<u8>), rustls::Error> {
//     let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
//         .map_err(|err| rustls::Error::General(format!("Failed parsing cert: {err:?}")))?;

//     let public_key = hex::encode(Sha256::digest(
//         cert.public_key().subject_public_key.data.clone(),
//     ));

//     let url = attested_tls_server_verifier
//         .blob_storage_url
//         .join(format!("/by-hash-pub-key/{public_key}").as_str())
//         .map_err(|err| {
//             rustls::Error::General(format!("Could to compose URL of the blob storage: {err:?}"))
//         })?;

//     info!("Getting the proof from blob storage: {url}");

//     let response = reqwest::get(url)
//         .await
//         .map_err(|err| rustls::Error::General(format!("Failed making request to ATS: {err:?}")))?;

//     let proof: Proof =
//         serde_json::from_str(&response.text().await.map_err(|err| {
//             rustls::Error::General(format!("Failed getting response text: {err:?}"))
//         })?)
//         .map_err(|err| {
//             rustls::Error::General(format!("Error converting response text to Proof: {err:?}",))
//         })?;

//     let decoded_attestation = BASE64_STANDARD
//         .decode(proof.attestation_b64)
//         .map_err(|err| {
//             rustls::Error::General(format!(
//                 "Failed base64 decoding the ClusterAttestation from the Proof: {err:?}"
//             ))
//         })?;

//     // Verify the attestation document stored on the Blob Storage
//     info!("Verifying the attestation document");
//     let (cert_self_signed_root_ca, signing_public_key) = attested_tls_server_verifier
//         .webserver_attestation_validator
//         .validate(RawAttestationDocument::ref_cast(&decoded_attestation))
//         .map_err(|err| rustls::Error::General(format!("Bad attestation document: {err:?}")))?;

//     info!("Attestation document verification successful!");

//     let signed_csr_bytes = BASE64_STANDARD
//         .decode(proof.signed_csr_b64)
//         .map_err(|err| {
//             rustls::Error::General(format!(
//                 "Failed base64 decoding the signed csr from the Proof: {err:?}"
//             ))
//         })?;

//     let csr_pem_bytes =
//         verify_csr_signature(signed_csr_bytes, signing_public_key).map_err(|err| {
//             rustls::Error::General(format!("Failed verifying CSR signature: {err:?}"))
//         })?;

//     let (_, csr_pem) = parse_x509_pem(&csr_pem_bytes).map_err(|err| {
//         rustls::Error::General(format!("Could not parse the csr_pem_bytes: {err:?}"))
//     })?;
//     let (_, csr) = X509CertificationRequest::from_der(&csr_pem.contents).map_err(|err| {
//         rustls::Error::General(format!(
//             "Failed parsing csr from PEM to X509CertificationRequest: {err:?}"
//         ))
//     })?;

//     if csr.certification_request_info.subject_pki != cert.subject_pki {
//         return  Err(rustls::Error::General("The subject public key info contained in the certificate does not match the one included in the CSR".to_string()));
//     }

//     let cert_ext = cert
//         .extensions()
//         .iter()
//         .map(|ext| ext.parsed_extension())
//         .collect::<Vec<&ParsedExtension>>();

//     if let Some(mut requested_extension) = csr.requested_extensions() {
//         requested_extension.try_for_each(|ext| {
//             if !cert_ext.contains(&ext) {
//                 Err(rustls::Error::General(format!(
//                     "Extension not found: {ext:?}"
//                 )))
//             } else {
//                 Ok(())
//             }
//         })?;
//     }
//     Ok((cert_self_signed_root_ca, decoded_attestation))
// }

impl ServerCertVerifier for AttestedTlsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        intermediates: &[pki_types::CertificateDer<'_>],
        server_name: &pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        info!("Verifying TLS connection");

        // First let's check if we are in the case where a self-signed root ca is used
        // In our configuration there should be just one intermediate certificate. This intermediate certificate is the self signed root ca.
        // The self signed root ca certificate should be stored in the attestation. And the attestation needs to be verified.
        // If all these condition are true then we assume we are in the self signed case.

        // If there is just one intermediate certificate it could be that we are in the self signed root ca scenario

        if intermediates.len() == 1 {
            // So try to get the attestation document out of this certificate
            let (_, intermediate_ca_cert) =
                X509Certificate::from_der(&intermediates[0]).map_err(|err| {
                    rustls::Error::General(format!(
                        "Failed parsing the certificate of the intermediate CA: {err:?}"
                    ))
                })?;

            // Get the Cluster AttestationDocument from the intermediate certificate
            let extensions_map = intermediate_ca_cert.extensions_map().map_err(|err| {
                rustls::Error::General(format!("Failed getting the extension map: {err:?}"))
            })?;

            // Same as mithrilos-multinode-proto
            // Hardcoded Custom OID
            let oid = oid!(2.25.636152116);
            let extension = extensions_map.get(&oid);

            // If there is a document we want to try to verify it. It probably means that we are in the scenario where we have a self signed ca.

            if let Some(attestation_value) = extension {
                let (k3s_root_ca, _signing_public_key) = self
                    .webserver_attestation_validator
                    .validate(RawAttestationDocument::ref_cast(&attestation_value.value))
                    .map_err(|err| {
                        rustls::Error::General(format!("Bad attestation document: {err:?}"))
                    })?;

                info!("Attestation document verification successful!");

                // Verify if the certificate that we got was signed by the root ca contained in the attestation document.
                // k3s_root_ca_pem -> Self Signed CA -> End Entity Cert

                let mut roots = RootCertStore::empty();
                roots.add(k3s_root_ca.contents.into()).map_err(|err| {
                    rustls::Error::General(format!(
                        "Failed adding the root ca certificate to the RootCertStore: {err:?}",
                    ))
                })?;
                let self_signed_server_cert_verifier =
                    WebPkiServerVerifier::builder(Arc::new(roots))
                        .build()
                        .map_err(|err| {
                            rustls::Error::General(format!(
                                "Failed building the ClientCertVerifier: {err:?}"
                            ))
                        })?;

                self_signed_server_cert_verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).map_err(|err| rustls::Error::General(format!("Verification of the service certificate using self-signed root CA failed: {err:?}")))?;
                info!("Server certificate verified!");
                info!("Client can safely connect to the cluster.");
                return Ok(ServerCertVerified::assertion());
            }
        }

        let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
            .map_err(|err| rustls::Error::General(format!("Failed parsing cert: {err:?}")))?;

        let public_key = hex::encode(Sha256::digest(
            cert.public_key().subject_public_key.data.clone(),
        ));

        if let Some(blob_storage_url) = self.blob_storage_url.clone() {
            let url = blob_storage_url
                .join(format!("/by-hash-pub-key/{public_key}").as_str())
                .map_err(|err| {
                    rustls::Error::General(format!(
                        "Could to compose URL of the blob storage: {err:?}"
                    ))
                })?;

            info!("Getting the proof from blob storage: {url}");

            let rt_handle = Handle::current();

            // First of all let's check if we can find this server certificate on the Blob Storage
            let proof: Proof = task::block_in_place(move || {
                rt_handle.block_on(async move { get_public_proof(url).await })
            })
            .map_err(|err| {
                rustls::Error::General(format!("Failed getting Proof from Blob Storage: {err:?}"))
            })?;

            info!("Got the proof from blob storage");

            let decoded_attestation =
                BASE64_STANDARD
                    .decode(proof.attestation_b64)
                    .map_err(|err| {
                        rustls::Error::General(format!(
                            "Failed Base64 decoding the ClusterAttestation from the Proof: {err:?}"
                        ))
                    })?;

            // Verify the attestation document stored on the Blob Storage
            info!("Verifying the attestation document");
            // Note _k3s_root_ca is not used because we expect to be in the case where a public CA is used.
            let (_k3s_root_ca, signing_public_key) = self
                .webserver_attestation_validator
                .validate(RawAttestationDocument::ref_cast(&decoded_attestation))
                .map_err(|err| {
                    rustls::Error::General(format!("Bad attestation document: {err:?}"))
                })?;

            info!("Attestation document verification successful!");

            // In the context where we are using a Public CA, we have access to the CSR generated for the certificate.
            // Get the signed CSR from the Proof
            let signed_csr_bytes = BASE64_STANDARD
                .decode(proof.signed_csr_b64)
                .map_err(|err| {
                    rustls::Error::General(format!(
                        "Failed base64 decoding the signed csr from the Proof: {err:?}"
                    ))
                })?;

            // Verify if the CSR was signed by Approver Plugin.
            // To do to this we use the public key extracted from the Attestation Document.
            let csr_pem_bytes = verify_csr_signature(signed_csr_bytes, signing_public_key)
                .map_err(|err| {
                    rustls::Error::General(format!("Failed verifying CSR signature: {err:?}"))
                })?;

            // Parse the CSR
            let (_, csr_pem) = parse_x509_pem(&csr_pem_bytes).map_err(|err| {
                rustls::Error::General(format!("Could not parse the csr_pem_bytes: {err:?}"))
            })?;

            let (_, csr) =
                X509CertificationRequest::from_der(&csr_pem.contents).map_err(|err| {
                    rustls::Error::General(format!(
                        "Failed parsing csr from PEM to X509CertificationRequest: {err:?}"
                    ))
                })?;

            // Verify if the CSR corresponds to the certificate we got for what we are trying to connect to

            if csr.certification_request_info.subject_pki != cert.subject_pki {
                return Err(rustls::Error::General("The subject public key info contained in the certificate does not match the one included in the CSR".to_string()));
            }

            let cert_ext = cert
                .extensions()
                .iter()
                .map(|ext| ext.parsed_extension())
                .collect::<Vec<&ParsedExtension>>();

            // Verify if the CSR and the certificate have the same extensions (SubjectAlternativeName, KeyUsage, ...).
            if let Some(mut requested_extension) = csr.requested_extensions() {
                requested_extension.try_for_each(|ext| {
                    if !cert_ext.contains(&ext) {
                        Err(rustls::Error::General(format!(
                            "Extension not found: {ext:?}"
                        )))
                    } else {
                        Ok(())
                    }
                })?;
            }
            // Check if the certificate was public CA (eg. Google).

            let mut public_roots = RootCertStore::empty();
            public_roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

            let public_root_ca_server_cert_verifier =
                WebPkiServerVerifier::builder(Arc::new(public_roots))
                    .build()
                    .map_err(|err| {
                        rustls::Error::General(format!(
                            "Failed building the ClientCertVerifier: {err:?}"
                        ))
                    })?;

            // Try to check if the certificate is valid according to the publicly trusted CAs
            public_root_ca_server_cert_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;

            info!("Server certificate verified!");
            info!("Client can safely connect to the cluster.");

            return Ok(ServerCertVerified::assertion());
        } else {
            log::error!("intermediates.len() != 1 and the blob storage url is empty!");
            return Err(rustls::Error::General(
                "Could not fetch proof from public storage because the blob storage url is empty"
                    .to_string(),
            ));
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

#[cfg(test)]
mod test {
    use std::{fs::read_to_string, sync::Arc};

    use attestation::cbor;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use provisioning_structs::structs::{
        AttestationBackend, ClusterAttestationResponse, PlatformMeasurements,
    };

    use crate::verifier::{
        attestation_validator_after_provisioning, make_cluster_policy, make_multinode_policy,
        make_node_policy,
    };
    use env_logger::Env;
    use provisioning_structs::structs::ClusterAttestation;
    #[cfg(test)]
    pub(crate) fn init_logger_tests() {
        // Will fail if called more than once, but I don't care about that type of error so i can just discard it.
        let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify() -> anyhow::Result<()> {
        init_logger_tests();

        let operator_cert = read_to_string("./test_data/cert.pem")?;
        let provisioning_bundle_hash =
            "56dd31d27e890097e3c94f09d018944a9bd8abc8377d17e2ad0cf7ffb1bc391c";
        let attestation_backend = AttestationBackend::AzureConfidentialVM;
        let os_measurement_vec = vec![
            177, 51, 25, 124, 45, 151, 253, 237, 37, 169, 55, 79, 190, 203, 203, 147, 95, 183, 231,
            207, 156, 124, 110, 189, 8, 132, 231, 107, 190, 154, 200, 54,
        ];
        let platform_measurements_str = read_to_string("./test_data/measurements_azure.json")?;
        let platform_measurements: PlatformMeasurements =
            serde_json::from_str(&platform_measurements_str)?;
        let attestation_b64 = read_to_string("./test_data/cluster_attestation.b64")?;

        let attestation_bytes = BASE64_STANDARD.decode(attestation_b64)?;
        let cluster_attestation: ClusterAttestation = cbor::from_slice(&attestation_bytes)?;

        let _cluster_info = attestation_validator_after_provisioning(
            Arc::new(make_cluster_policy(
                &operator_cert,
                provisioning_bundle_hash,
            )),
            Arc::new(make_node_policy(
                platform_measurements,
                os_measurement_vec,
                attestation_backend,
            )),
            &cluster_attestation,
        )?;

        Ok(())
    }
}
