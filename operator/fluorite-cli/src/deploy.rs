use anyhow::{Context, anyhow, bail, ensure};
use attested_server_verifier::verifier::{
    attestation_validator_after_provisioning, attestation_validator_before_provisioning,
    make_cluster_policy, make_multinode_policy, make_node_policy,
};
use base64::prelude::*;
use log::{debug, info};
use reqwest::{Client, multipart};
use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha256::try_digest;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use std::{thread, time::Duration};

use provisioning_structs::structs::{
    AZURE_ROOT_CERTS, AttestationBackend, AttestedDocument, ClusterAttestationResponse,
    ClusterConfiguration, ClusterNode, Config, GetInstanceIdentityDocumentResponse,
    ImdsAttestedDocumentResponse, InitAsMasterRequest, InitAsMasterResponse, InitAsSlaveRequest,
    Node, PROTOCOL_PORT, PlatformMeasurements, ProvisionClusterResponse, ProvisioningState, Role,
};

use webpki::{EndEntityCert, KeyUsage, ring};
use x509_parser::{
    certificate::X509Certificate, der_parser::asn1_rs::FromDer, extensions::ParsedExtension,
    oid_registry,
};

use crate::client_tls_config::PeerServerVerifier;
use crate::utils::pem_to_der;
use cms::{
    cert::{CertificateChoices, x509::Certificate},
    content_info::{CmsVersion, ContentInfo},
    signed_data::SignedData,
};

const MAX_RETRIES: u32 = 10;

/// Open and validate an Azure IMDS attested document.
///
/// Azure IMDS document is signed document describing the VM, not to be confused with a remote attestation
/// issued by the TPM or a Trusted Execution Environment.
///
/// Reference : <https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#attested-data>
///
/// Limitation: This implementation does not check the certificates revocation status.
///
/// Returns a parsed AttestedDocument
/// # Errors
/// Returns an error if the document's encoding is not as expected, if any cryptographic
/// validation fails, or if the document's format is incorrect.
// #[context("Failed to open Azure IMDS attested data")]
async fn open_attested_imds_document(
    attested_imds_document: ImdsAttestedDocumentResponse,
) -> anyhow::Result<AttestedDocument> {
    use der::{Decode, Encode};
    ensure!(&attested_imds_document.encoding == "pkcs7");

    let sig_der = BASE64_STANDARD.decode(attested_imds_document.signature)?;
    let ci = ContentInfo::from_der(&sig_der[..])?;

    ensure!(ci.content_type == const_oid::db::rfc5911::ID_SIGNED_DATA);

    let bytes = ci.content.to_der()?;
    let sd = SignedData::from_der(&bytes[..])?;

    ensure!(sd.version == CmsVersion::V1);

    // Build certificate chain to the certificate used to sign the document

    // Step 1 : Extract leaf certificate that is part of the PKCS7 signed data

    let certs: Vec<Certificate> = sd
        .certificates
        .as_ref()
        .context("No certificate was joined to signed data")?
        .0
        .iter()
        .map(|c| {
            let CertificateChoices::Certificate(cert) = c else {
                bail!("Unexpected CertificateChoices variant")
            };
            Ok(cert.clone())
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .context("Failed to find certificate used to sign the document")?;

    ensure!(
        certs.len() == 1,
        "Failed to find certificate: expected 1, found {}",
        certs.len()
    );
    let leaf_cert = certs[0]
        .to_der()
        .context("Failed to encode leaf certificate to DER")?;

    // Step 2 : Fetch the intermediate certificate using the AuthorityInfoAccess in leaf cert
    let (_, cert) = X509Certificate::from_der(&leaf_cert)
        .map_err(|e| anyhow::anyhow!("Bad leaf certificate: {}", e))
        .context("Failed to obtain intermediate certificate")?;

    let extension = cert
        .get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
        .context("Failed to obtain intermediate certificate: error accessing extensions")?
        .context(
            "Failed to obtain intermediate certificate: No AuthorityInfoAccess extension found",
        )?;

    let ParsedExtension::AuthorityInfoAccess(authority_information_access) =
        extension.parsed_extension()
    else {
        bail!(
            "Failed to obtain intermediate certificate: Got bad extension type for AuthorityInfoAccess OID"
        );
    };

    let binding = authority_information_access.as_hashmap();
    let ca_issuers = binding
        .get(&oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS)
        .context(
            "Failed to obtain intermediate certificate: No CA issuer found in AuthorityInfoAccess",
        )?
        .as_slice();

    let &[&x509_parser::prelude::GeneralName::URI(ca_issuers_uri)] = ca_issuers else {
        bail!("Failed to obtain intermediate certificate: Could not get CA URI from CA issuers");
    };

    let cert_as_bytes = reqwest::get(ca_issuers_uri)
        .await
        .context("Failed to obtain intermediate certificate: network request failed")?
        .error_for_status()
        .context("Failed to obtain intermediate certificate: server returned error status")?
        .bytes()
        .await
        .context("Failed to obtain intermediate certificate: failed to read response bytes")?;

    let intermediate_cert = CertificateDer::from(cert_as_bytes.as_ref()).into_owned();

    // Step 3 : Create trust anchors based on Root CAs used by Azure

    // We are pinning the Root CAs. The certs are embedded at compile time.
    // The certificates were sourced from Microsoft's official Azure documentation :
    // https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-ca-details?tabs=root-and-subordinate-cas-list

    let azure_allowed_root_ca = AZURE_ROOT_CERTS;

    // Convert each CA certificate from DER format into a TrustAnchor object.
    let azure_trust_anchor: Vec<rustls_pki_types::TrustAnchor> = azure_allowed_root_ca
        .iter()
        .map(|cert_bytes_der| {
            let cert = CertificateDer::from(*cert_bytes_der);
            webpki::anchor_from_trusted_cert(&cert).unwrap().to_owned()
        })
        .collect();

    // Validate that the pinned Root CAs are part of Mozilla's trusted root CA list.
    // This validation ensures that the pinned Root CAs are publicly recognized and trusted.
    // The assertion will fail if any of those CAs are removed from Mozilla's list, signaling a potential security concern.
    // In such cases, actions such as updating or replacing the pinned CAs should be considered.
    assert!(
        azure_trust_anchor
            .iter()
            .all(|trust_anchor| webpki_roots::TLS_SERVER_ROOTS.contains(trust_anchor))
    );

    // Validate the leaf certificate

    let leaf_cert = CertificateDer::from(leaf_cert);
    let ee_cert = EndEntityCert::try_from(&leaf_cert)?;

    ee_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &azure_trust_anchor[..],
            &[intermediate_cert],
            UnixTime::now(),
            KeyUsage::server_auth(),
            None,
            None,
        )
        .context("Invalid IMDS certificate")?;

    // Warning :
    // Azure documentation states that the IMDS certificate could be for subdomains like "*.metadata.azure.com"
    // So by checking if the cert is valid for domain "metadata.azure.com" we might reject valid certificates.
    ee_cert
        .verify_is_valid_for_subject_name(&ServerName::DnsName("metadata.azure.com".try_into()?))
        .context("Invalid IMDS certificate")?;

    let signature = sd
        .signer_infos
        .0
        .get(0)
        .ok_or(anyhow!("Could get SignerInfo from signed data"))?
        .signature
        .as_bytes();
    let binding = sd
        .encap_content_info
        .econtent
        .context("Failed to find the message")?;
    let message = binding.value();

    // Check the signature

    // For now, we "bruteforce" the signature verification by trying all the ring-supported, non-legacy algorithms.
    // A more efficient way would be to find which signature algorithm is declared in the SignerInfo
    // and use only this algorithm for the verification.
    let algs = [
        ring::ECDSA_P256_SHA256,
        ring::ECDSA_P256_SHA384,
        ring::ECDSA_P384_SHA256,
        ring::ECDSA_P384_SHA384,
        ring::ED25519,
        ring::RSA_PKCS1_2048_8192_SHA256,
        ring::RSA_PKCS1_2048_8192_SHA384,
        ring::RSA_PKCS1_2048_8192_SHA512,
        ring::RSA_PKCS1_3072_8192_SHA384,
        // ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        // ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        // ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ];

    let is_signature_good = algs
        .into_iter()
        .any(|alg| ee_cert.verify_signature(alg, message, signature).is_ok());

    if !is_signature_good {
        bail!("Bad signature");
    }
    let doc = serde_json::from_slice(message).context("Failed to parse the Attested Document")?;
    Ok(doc)
}

/// Gets the node instance identity document of each node
async fn get_nodes_instance_identity_document(
    client: &Client,
    vec_cluster_nodes: &Vec<ClusterNode>,
    attestation_backend: AttestationBackend,
) -> anyhow::Result<Vec<Node>> {
    let mut ret: Vec<Node> = Vec::new();
    for cluster_node in vec_cluster_nodes {
        for att in 1..=MAX_RETRIES {
            info!(
                "Getting instance identity document of: {}. Attempt {} out of {}.",
                &cluster_node.address, att, MAX_RETRIES
            );
            let get_instance_identity_document_endpoint = format!(
                "https://{}:{}/get_instance_identity_document",
                &cluster_node.address, PROTOCOL_PORT
            );
            let response_get_instance_identity_document = client
                .get(get_instance_identity_document_endpoint.clone())
                .send()
                .await;
            match response_get_instance_identity_document {
                Ok(response) => {
                    info!("Status: {}", response.status());
                    if !response.status().is_success() {
                        let status = response.status();
                        let error_text = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "Failed to read response body".to_string());
                        return Err(anyhow!(
                            "Error get_instance_identity_document on {}: Status {}.\nReason: {}",
                            get_instance_identity_document_endpoint,
                            status,
                            error_text
                        ));
                    }

                    let instance_identity_document: GetInstanceIdentityDocumentResponse =
                        serde_json::from_str(response.text().await?.as_str())?;

                    if (attestation_backend == AttestationBackend::AzureTrustedLaunchVM)
                        || (attestation_backend == AttestationBackend::AzureConfidentialVM)
                    {
                        let vm_id = cluster_node.vm_id.clone().ok_or(anyhow!(
                            "vm_id field is empty, and the attestation backend is Azure"
                        ))?;

                        let attested_imds_document = open_attested_imds_document(
                            instance_identity_document.instance_id_document.ok_or(anyhow!("instance_id_document field is empty, and the attestation backend is Azure"))?,
                        )
                        .await?;

                        ensure!(
                            attested_imds_document.vm_id == vm_id,
                            "The vm_id returned by the node does not match the expected value."
                        );
                    }

                    ret.push(Node {
                        address: cluster_node.address.to_string(),
                        port: PROTOCOL_PORT.to_string(),
                        cert_pem: instance_identity_document.cert_pem,
                    });
                    // Break out of the retry loop
                    break;
                }
                Err(err) => {
                    info!(
                        "Network error while attempting to get instance identity document for {}: {}",
                        &cluster_node.address, err
                    );
                    ensure!(
                        att < MAX_RETRIES,
                        "Maximum retries reached in `get_nodes_instance_identity_document`."
                    );
                    info!("Sleeping for 30 seconds.");
                    thread::sleep(Duration::from_secs(30));
                }
            }
        }
    }
    Ok(ret)
}

/// Initializes the nodes in the cluster as slaves (control plane or agent)
async fn init_nodes_as_slaves(
    client: &Client,
    master: &Node,
    cluster_node_vec: Vec<ClusterNode>,
    role: Role,
) -> anyhow::Result<()> {
    for cluster_node in cluster_node_vec {
        let request_body: InitAsSlaveRequest = InitAsSlaveRequest {
            master_cert_pem: master.cert_pem.to_string(),
            master_hostname: master.address.to_string(),
            role,
            name: cluster_node.name,
            public_ip: cluster_node.address.to_string(),
        };

        info!("Initializing {} as slave", &cluster_node.address);
        let init_as_slave_endpoint = format!(
            "https://{}:{}/init_as_slave",
            &cluster_node.address, PROTOCOL_PORT
        );
        let init_as_slave_response = client
            .post(init_as_slave_endpoint.clone())
            .header("Content-Type", "application/json") // Set Content-Type header
            .body(serde_json::to_string(&request_body)?) // Pass the raw JSON string
            .send()
            .await
            .context(format!(
                "Network error trying to send POST request to {}",
                init_as_slave_endpoint
            ))?;

        if !init_as_slave_response.status().is_success() {
            let status = init_as_slave_response.status();
            let error_text = init_as_slave_response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read response body".to_string());
            return Err(anyhow!(
                "Error init_as_slave: Status {}.\nReason: {}",
                status,
                error_text
            ));
        }
    }

    Ok(())
}

pub async fn provision_cluster(
    cluster_file: PathBuf,
    zarf_package_path: PathBuf,
    deployment_config_path: Option<PathBuf>,
    operator_cert_path: PathBuf,
    operator_private_key_path: PathBuf,
    os_measurement_vec: Vec<u8>,
    platform_measurements: PlatformMeasurements,
    attestation_backend: AttestationBackend,
    deployment_size_bytes: u64,
) -> anyhow::Result<()> {
    let operator_cert =
        fs::read_to_string(operator_cert_path).context("Unable to operator certificate file.")?;

    let operator_private_key = fs::read_to_string(operator_private_key_path)
        .context("Unable to operator certificate private key.")?;

    let cert_with_key_pem = format!("{}{}", &operator_cert, &operator_private_key);
    let id = reqwest::Identity::from_pem(cert_with_key_pem.as_bytes())?;
    let dangerous_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .identity(id)
        .danger_accept_invalid_certs(true) // Disable server certificate validation until the init_as_master step is completed
        .build()?;

    let cluster_json_str =
        fs::read_to_string(cluster_file).context("Unable to read cluster file")?;

    let cluster: ClusterConfiguration =
        serde_json::from_str(cluster_json_str.as_str()).context("Can't parse the cluster file")?;

    let config: Config = if let Some(path) = deployment_config_path {
        let config_str =
            fs::read_to_string(path).context("Unable to read deployment variables file path")?;
        serde_yaml::from_str(&config_str).context("Can't parse the deployment variables file")?
    } else {
        Config::empty()
    };

    ensure!(
        !config.package.deploy.set.contains_key("CA_KEY_B64")
            && !config.package.deploy.set.contains_key("CA_CRT_B64")
            && !config.package.deploy.set.contains_key("ATTESTATION_B64")
            && !config
                .package
                .deploy
                .set
                .contains_key("SIGNATURE_PRIVATE_KEY_B64"),
        "The secrets keys `CA_KEY_B64`, `CA_CRT_B64`, `SIGNATURE_PRIVATE_KEY_B64`, `ATTESTATION_B64` are reserved."
    );

    let mut servers = cluster.get_servers();

    // Make sure there is at least one server, as the first server will be promoted to master node
    ensure!(!servers.is_empty());

    let mut server_nodes: Vec<Node> =
        get_nodes_instance_identity_document(&dangerous_client, &servers, attestation_backend)
            .await?;

    let agents = cluster.get_agents();
    let agent_nodes: Vec<Node> =
        get_nodes_instance_identity_document(&dangerous_client, &agents, attestation_backend)
            .await?;

    // Use the first server as master, which will be used to initialize the cluster
    // All the other nodes, will join the cluster as servers or agents.
    let master = servers[0].clone();
    let node_master = server_nodes[0].clone();
    server_nodes.remove(0);
    servers.remove(0);

    init_nodes_as_slaves(&dangerous_client, &node_master, agents, Role::Agent).await?;

    init_nodes_as_slaves(&dangerous_client, &node_master, servers, Role::Server).await?;

    info!("Initializing {} as master", master.address);
    let mut slaves = server_nodes;
    slaves.extend_from_slice(&agent_nodes);
    info!("Slaves: {}", serde_json::to_string_pretty(&slaves)?);
    let request_body = InitAsMasterRequest {
        slaves,
        public_ip: master.address.to_string(),
    };
    let init_as_master_endpoint = format!(
        "https://{}:{}/init_as_master",
        &master.address, PROTOCOL_PORT
    );

    let init_as_master_response = dangerous_client
        .post(init_as_master_endpoint.clone())
        .header("Content-Type", "application/json") // Set Content-Type header
        .body(serde_json::to_string(&request_body)?) // Pass the raw JSON string
        .send()
        .await
        .context(format!(
            "Network error trying to send POST request to {}",
            init_as_master_endpoint
        ))?;

    if !init_as_master_response.status().is_success() {
        let status = init_as_master_response.status();
        let error_text = init_as_master_response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read response body".to_string());
        return Err(anyhow!(
            "Error init_as_master: Status {}.\nReason: {}",
            status,
            error_text
        ));
    }

    let init_as_master_response: InitAsMasterResponse = init_as_master_response
        .json()
        .await
        .context("Error converting InitAsMasterResponse to json")?;

    info!("Multinode verification before provisioning");
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let multi_node_info = attestation_validator_before_provisioning(
        make_multinode_policy(&operator_cert),
        make_node_policy(
            platform_measurements.clone(),
            os_measurement_vec.clone(),
            attestation_backend,
        ),
        &init_as_master_response.multi_node_attestation,
    )
    .context("Error verification")?;
    info!("Verification done");
    let tls_verifier_for_master = PeerServerVerifier::new_with_default_provider(pem_to_der(
        &multi_node_info.master_cert_pem,
    )?);

    let cert_chain = vec![
        CertificateDer::from_pem_slice(operator_cert.as_bytes())
            .context("Error converting operator public key to CertificateDer")?,
    ];
    let key_der = PrivatePkcs8KeyDer::from_pem_slice(operator_private_key.as_bytes())
        .context("Error converting operator private key to PrivatePkcs8KeyDer")?
        .clone_key()
        .into();

    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tls_verifier_for_master))
        .with_client_auth_cert(cert_chain, key_der)
        .context("Error creating the ClientConfig")?;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .use_preconfigured_tls(client_config)
        .build()
        .context("Error when creating reqwest client")?;

    let file_fs = fs::read(&zarf_package_path).context("Unable to read zarf package")?;

    let provisoning_bundle_part = multipart::Part::bytes(file_fs).file_name("package.tar.zst");
    let deployment_config_str =
        serde_yaml::to_string(&config).context("Failed serializing the secrets")?;

    let form = reqwest::multipart::Form::new()
        .part("provisioning_bundle", provisoning_bundle_part)
        .text("deployment_config", deployment_config_str)
        .text("deployment_size", deployment_size_bytes.to_string());
    info!("Started provisioning cluster. Uploading provisioning package...");
    let post_provision_cluster_endpoint = format!(
        "https://{}:{}/master/provision_cluster",
        master.address, PROTOCOL_PORT
    );

    let response_provision_cluster = client
        .post(post_provision_cluster_endpoint.clone())
        .multipart(form)
        .send()
        .await
        .context(format!(
            "Network error trying to send POST request to {}",
            post_provision_cluster_endpoint
        ))?;

    if !response_provision_cluster.status().is_success() {
        let status = response_provision_cluster.status();
        let error_text = response_provision_cluster
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read response body".to_string());
        return Err(anyhow!(
            "Error master/provision_cluster on {}: Status {}.\nReason: {}",
            post_provision_cluster_endpoint,
            status,
            error_text
        ));
    }

    let response_provision_cluster: ProvisionClusterResponse = response_provision_cluster
        .json()
        .await
        .context("Error converting ProvisionClusterResponse to json")?;

    info!(
        "Provisioning cluster response: {:?}",
        response_provision_cluster
    );

    let provisioning_bundle_hash = try_digest(zarf_package_path)?;

    let get_cluster_status_endpoint = format!(
        "https://{}:{}/cluster_status",
        master.address, PROTOCOL_PORT
    );

    loop {
        let response_cluster_status = client
            .get(get_cluster_status_endpoint.clone())
            .send()
            .await
            .context(format!(
                "Network error trying to send get request to {}",
                get_cluster_status_endpoint
            ))?;

        if !response_cluster_status.status().is_success() {
            let status = response_cluster_status.status();
            let error_text = response_cluster_status
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read response body".to_string());
            return Err(anyhow!(
                "Error getting cluster_status on {}: Status {}.\nReason: {}",
                get_cluster_status_endpoint,
                status,
                error_text
            ));
        }

        let cluster_status_response: ProvisioningState = response_cluster_status
            .json()
            .await
            .context("Error converting ProvisioningState to json")?;
        match cluster_status_response {
            ProvisioningState::NotStarted => {
                bail!("Provisioning has not started. How did we get here?!")
            }
            ProvisioningState::Error => {
                bail!("There has been an error during provisioning. Provisioning failed.")
            }
            ProvisioningState::InProgress => {
                info!("Provisioning is still in progress, checking again in 3 seconds.");
                thread::sleep(Duration::from_secs(3))
            }
            ProvisioningState::Provisioned => break, // Provisioning is done, break out of loop
        }
    }

    info!("Cluster successfully provisioned.");
    info!("Getting cluster attestation.");
    let get_cluster_attestation_endpoint = format!(
        "https://{}:{}/master/cluster_attestation",
        master.address, PROTOCOL_PORT
    );

    let cluster_attestation_response = client
        .get(get_cluster_attestation_endpoint.clone())
        .send()
        .await
        .context(format!(
            "Network error trying to send get request to {}",
            get_cluster_attestation_endpoint
        ))?;

    let cluster_attestation_response: ClusterAttestationResponse = cluster_attestation_response
        .json()
        .await
        .context("Error converting ClusterAttestationResponse to json")?;

    debug!(
        "Cluster attestation response: {:?}",
        cluster_attestation_response
    );

    info!("Verifying the cluster attestation.");
    let _cluster_info = attestation_validator_after_provisioning(
        Arc::new(make_cluster_policy(
            &operator_cert,
            provisioning_bundle_hash.as_str(),
        )),
        Arc::new(make_node_policy(
            platform_measurements,
            os_measurement_vec,
            attestation_backend,
        )),
        &cluster_attestation_response.cluster_attestation,
    )
    .context("Error verifying the cluster attestation after provisioning")?;
    info!("The cluster attestation is valid.");

    Ok(())
}
