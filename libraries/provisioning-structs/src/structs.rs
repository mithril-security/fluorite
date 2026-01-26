// Standard library imports
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Display;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

// External crate imports
use anyhow::{Context as _, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::digest::generic_array::GenericArray;
use tokio::runtime::Handle;
use tokio::task;

// Dryoc (crypto)
use dryoc::sign::{PublicKey, SignedMessage};
use dryoc::types::StackByteArray;

// Rustls (certificate/crypto)
use rustls_pki_types::UnixTime;

// TPM, attestation, and related domain imports
use attestation::eventlog::{Event, EventLog, ParsedEventLog};
use attestation::{AsyncVerifyAttestationDocument, VerifyAttestationDocument};
use azure_cvm_attestation::common::ConfidentialVmAttestationDocument;
use azure_trusted_launch_attestation::TrustedLaunchVmAttestationDocument;
use gcp_shielded_vm_attestation::ShieldedVmAttestationDocument as GcpShieldedVmAttestationDocument;
use qemu_attestation::QEMUVmAttestationDocument;
use svsm_sev_attestation::SvsmVtpmAttestationDocument;
use tpm_quote::common::{Digest, HashingAlgorithm, PcrData, PcrIndex, PcrSlot, SanitizedPcrData};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TpmEvent {
    Bootstrapper(BootstrapperTpmEvents),
}

impl Event for TpmEvent {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum BootstrapperTpmEvents {
    BootstrapperStarting {
        service_cert_pem: String,
        operator_cert_pem: String,
    },
    InitAsSlave {
        master_cert: String,
        master_ip: String,
        role: Role,
    },
    InitAsMaster {
        slaves_cert: Vec<String>,
    },
    K3sClusterCreated {
        k3s_root_ca_pem: String,
    },
    K3sClusterStartprovisioning {
        provisioning_bundle_digest: String,
    },
    SingatureInfo {
        public_key: PublicKey,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum NodeAttestationDocument {
    QEMUVmAttestationDocument(QEMUVmAttestationDocument),
    SvsmVtpmAttestationDocument(SvsmVtpmAttestationDocument),
    TrustedLaunchVmAttestationDocument(TrustedLaunchVmAttestationDocument),
    ConfidentialVMAttestationDocument(ConfidentialVmAttestationDocument),
    GcpShieldedVmAttestationDocument(GcpShieldedVmAttestationDocument),
}

impl Display for NodeAttestationDocument {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            NodeAttestationDocument::QEMUVmAttestationDocument(_) => {
                write!(f, "AttestationDocument::QEMUVmAttestationDocument")
            }
            NodeAttestationDocument::SvsmVtpmAttestationDocument(_) => {
                write!(f, "AttestationDocument::SvsmVtpmAttestationDocument")
            }
            NodeAttestationDocument::TrustedLaunchVmAttestationDocument(_) => {
                write!(f, "AttestationDocument::TrustedLaunchVmAttestationDocument")
            }
            NodeAttestationDocument::ConfidentialVMAttestationDocument(_) => {
                write!(f, "AttestationDocument::ConfidentialVMAttestationDocument")
            }
            NodeAttestationDocument::GcpShieldedVmAttestationDocument(_) => {
                write!(f, "AttestationDocument::GcpShieldedVmAttestationDocument")
            }
        }
    }
}

pub struct NodeInfo {
    pub attestation_backend: AttestationBackend,
    pub pcr_data: SanitizedPcrData,
}

#[cfg(feature = "validate-attestation-documents")]
pub fn node_attestation_document_validator(
    attestation: &NodeAttestationDocument,
) -> anyhow::Result<NodeInfo> {
    Ok(match attestation {
        NodeAttestationDocument::TrustedLaunchVmAttestationDocument(attestation_document) => {
            NodeInfo {
                attestation_backend: AttestationBackend::AzureTrustedLaunchVM,
                pcr_data: attestation_document.verify(UnixTime::now())?,
            }
        }
        NodeAttestationDocument::ConfidentialVMAttestationDocument(attestation_document) => {
            let rt_handle = Handle::current();

            let pcr_data = task::block_in_place(move || {
                rt_handle
                    .block_on(async move { attestation_document.verify(UnixTime::now()).await })
            })?;
            NodeInfo {
                attestation_backend: AttestationBackend::AzureConfidentialVM,
                pcr_data: pcr_data,
            }
        }
        NodeAttestationDocument::QEMUVmAttestationDocument(attestation_document) => NodeInfo {
            attestation_backend: AttestationBackend::QEMU,
            pcr_data: attestation_document.verify(UnixTime::now())?,
        },
        NodeAttestationDocument::SvsmVtpmAttestationDocument(attestation_document) => NodeInfo {
            attestation_backend: AttestationBackend::SvsmVtpm,
            pcr_data: attestation_document.verify(UnixTime::now())?,
        },
        NodeAttestationDocument::GcpShieldedVmAttestationDocument(attestation_document) => {
            NodeInfo {
                attestation_backend: AttestationBackend::GcpShieldedVM,
                pcr_data: attestation_document.verify(UnixTime::now())?,
            }
        }
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeAttestationDocumentWithEvents {
    pub attestation_document: NodeAttestationDocument,
    pub serialized_events: EventLog<TpmEvent>,
}

pub struct NodeWithEventsInfo {
    pub attestation_backend: AttestationBackend,
    pub pcr_data: SanitizedPcrData,
    pub events: ParsedEventLog<TpmEvent>,
}

pub const EVENT_LOG_SLOT: PcrIndex = PcrIndex {
    bank: HashingAlgorithm::Sha256,
    pcr_slot: PcrSlot::Slot8,
};

pub const OS_MEASUREMENT_SLOT: PcrIndex = PcrIndex {
    bank: HashingAlgorithm::Sha256,
    pcr_slot: PcrSlot::Slot4,
};

/// A trait that can be used to check a node policy
///
/// Implementors can use it to validate the node info.
/// They should return an error to signal that the policy is not respected
pub trait NodePolicy = Fn(&NodeWithEventsInfo) -> anyhow::Result<()>;

#[cfg(feature = "validate-attestation-documents")]
pub fn node_attestation_document_with_events_validator(
    attestation: &NodeAttestationDocumentWithEvents,
) -> anyhow::Result<NodeWithEventsInfo> {
    let node_claims =
        node_attestation_document_validator.validate(&attestation.attestation_document)?;

    let slot8_digest = node_claims
        .pcr_data
        .pcr_bank(HashingAlgorithm::Sha256)
        .context("No SHA256 PCR Bank")?
        .bank
        .get(&EVENT_LOG_SLOT.pcr_slot)
        .context("Failed to get the Slot 8 PCR bank")?;

    // GenericArray::clone_from_slice will not panic because digests from SanitizedPcrData
    // are guaranted to be of the correct size for their respective hashing algorithm
    let events = attestation
        .serialized_events
        .verify::<Sha256>(GenericArray::clone_from_slice(&slot8_digest.0))?;

    // let pcr_bank_sha256 = node_claims
    //     .pcr_data
    //     .pcr_bank(HashingAlgorithm::Sha256)
    //     .context("No SHA256 PCR Bank")?;

    Ok(NodeWithEventsInfo {
        attestation_backend: node_claims.attestation_backend,
        pcr_data: node_claims.pcr_data,
        events,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MultiNodeAttestation {
    pub master_attestation_document: NodeAttestationDocumentWithEvents,
    pub slaves_attestation_document: Vec<NodeAttestationDocumentWithEvents>,
}

pub struct MultiNodeInfo {
    pub attestation_backend: AttestationBackend,
    pub operator_cert_pem: String,
    pub master_events: Vec<TpmEvent>,
    pub master_cert_pem: String,
    pub os_measurement: Digest,
}

pub trait AttestationValidator<Attestation: ?Sized, Info> {
    fn validate(&self, attestation: &Attestation) -> anyhow::Result<Info>;
}

impl<Input: ?Sized, Output, F> AttestationValidator<Input, Output> for F
where
    F: Fn(&Input) -> anyhow::Result<Output>,
{
    fn validate(&self, input: &Input) -> anyhow::Result<Output> {
        self(input)
    }
}

/// A basic multi-node attestation validator that validates the multi-node attestation document
/// and returns the multi-node info
///
/// The validator verifies that every node is valid according to the node policy (uniformly)
/// and that the multi node protocol is followed by master and slaves.
pub fn make_basic_multinode_attestation_validator(
    node_attestation_validator: &impl AttestationValidator<
        NodeAttestationDocumentWithEvents,
        NodeWithEventsInfo,
    >,
) -> impl AttestationValidator<MultiNodeAttestation, MultiNodeInfo> {
    move |attestation: &MultiNodeAttestation| -> anyhow::Result<MultiNodeInfo> {
        let master_info =
            node_attestation_validator.validate(&attestation.master_attestation_document)?;

        // Only verify if the first two events are [BootstrapperStarting, InitAsMaster]
        // We don't know if this function was called during verification of the Attestation of an initialized Cluster
        // or while the cluster is still being provisioned.
        // It is the responsibility of a Cluster AttestationValidator to validate and apparaise the later events.

        let [
            TpmEvent::Bootstrapper(BootstrapperTpmEvents::BootstrapperStarting {
                operator_cert_pem: master_operator_cert_pem,
                service_cert_pem: master_cert_pem,
            }),
            TpmEvent::Bootstrapper(BootstrapperTpmEvents::InitAsMaster { slaves_cert }),
            master_info_remaining_events @ ..,
        ] = &master_info.events[..]
        else {
            bail!(
                "The first two events of the master node are not of type [BootstrapperStarting, InitAsMaster]"
            );
        };

        // Sanity check
        ensure!(
            attestation.slaves_attestation_document.len() == slaves_cert.len(),
            "The number of slaves_cert in the InitAsMaster event does not equal the number of slave attestation document in the attestation"
        );

        // Using an HashSet because I don't want to make assumptions about the ordering of the slaves certificates,
        // additionally duplicates are removed for free. We don't expect to have duplicate node certificates, so if there are, there is an issue.
        let expected_slaves_cert_set: HashSet<&str> =
            slaves_cert.iter().map(|s| s.as_str()).collect();

        ensure!(
            expected_slaves_cert_set.len() == slaves_cert.len(),
            "The slave_cert in the InitAsMaster event contains duplicate certificates"
        );

        let master_os_measurement = master_info
            .pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .context("No SHA256 PCR Bank")?
            .bank
            .get(&OS_MEASUREMENT_SLOT.pcr_slot)
            .context("Failed to get Master OS Measurement PCR bank")?;

        let mut attested_slaves_cert_set = HashSet::new();
        for slave_attestation in &attestation.slaves_attestation_document {
            let slave_info = node_attestation_validator.validate(slave_attestation)?;

            let [
                TpmEvent::Bootstrapper(BootstrapperTpmEvents::BootstrapperStarting {
                    service_cert_pem: slave_cert,
                    operator_cert_pem: slave_operator_cert_pem,
                    ..
                }),
                TpmEvent::Bootstrapper(BootstrapperTpmEvents::InitAsSlave {
                    master_cert: slave_master_cert,
                    ..
                }),
            ] = &slave_info.events[..]
            else {
                bail!(
                    "The first two events of the slave node are not of type [BootstrapperStarting, InitAsSlave]"
                );
            };

            ensure!(
                slave_operator_cert_pem == master_operator_cert_pem,
                format!(
                    "The operator cert of the slave node does not match the operator cert of the master node \nExpected:\n{} \nGot:\n{}\n",
                    master_operator_cert_pem, slave_operator_cert_pem
                )
            );
            ensure!(
                slave_master_cert == master_cert_pem,
                format!(
                    "The slave node's master cert does not match the master node's cert. \nExpected:\n{} \nGot:\n{}\n",
                    master_cert_pem, slave_master_cert
                )
            );
            let slave_os_measurement = slave_info
                .pcr_data
                .pcr_bank(HashingAlgorithm::Sha256)
                .context("No SHA256 PCR Bank")?
                .bank
                .get(&OS_MEASUREMENT_SLOT.pcr_slot)
                .context("Failed to get Slave OS Measurement PCR bank")?;
            ensure!(
                slave_os_measurement == master_os_measurement,
                format!(
                    "The slave node's os_measurement does not match the master's node os_measurement. \nExpected:\n{} \nGot:\n{}\n",
                    hex::encode(master_os_measurement.0.clone()),
                    hex::encode(slave_os_measurement.0.clone())
                )
            );
            ensure!(
                slave_info.attestation_backend == master_info.attestation_backend,
                format!(
                    "The slave node's attestation backend does not match the master's node attestation backend. \nExpected:\n{} \nGot:\n{}\n",
                    master_info.attestation_backend, slave_info.attestation_backend
                )
            );

            attested_slaves_cert_set.insert(slave_cert.to_string());
        }

        // The second check implies the first one, but I've split them for better error messages
        ensure!(
            expected_slaves_cert_set.len() == attested_slaves_cert_set.len(),
            "The size of the expected slaves cert set does not equal the size of the slaves cert set"
        );
        ensure!(
            expected_slaves_cert_set
                == attested_slaves_cert_set
                    .iter()
                    .map(|s| s.as_str())
                    .collect(),
            "The expected slaves cert set does not equal the slaves cert set"
        );

        // We only return the remaining events of the master's event log.
        Ok(MultiNodeInfo {
            attestation_backend: master_info.attestation_backend,
            operator_cert_pem: master_operator_cert_pem.to_string(),
            master_events: master_info_remaining_events.to_vec(),
            master_cert_pem: master_cert_pem.to_string(),
            os_measurement: master_os_measurement.clone(), // Take the os_measurement of the master node, if we got here all nodes have the same os_measurement
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClusterAttestation {
    pub multi_node_attestation: MultiNodeAttestation,
}

#[derive(Serialize, Deserialize)]
pub struct ClusterInfo {
    pub attestation_backend: AttestationBackend,
    pub operator_cert: String,
    pub provisioning_bundle_digest: String,
    #[serde(skip)]
    pub eventlog: Vec<TpmEvent>,
    pub os_measurement: Digest,
}

/// A basic cluster attestation validator that validates the cluster attestation document
/// and returns the cluster info
///
/// The validator verifies that every node is valid according to the node policy (uniformly)
/// and that the cluster protocol was followed.
pub fn make_basic_cluster_attestation_validator(
    node_attestation_validator: &impl AttestationValidator<
        NodeAttestationDocumentWithEvents,
        NodeWithEventsInfo,
    >,
) -> impl AttestationValidator<ClusterAttestation, ClusterInfo> {
    move |attestation: &ClusterAttestation| -> anyhow::Result<ClusterInfo> {
        let multi_node_info =
            make_basic_multinode_attestation_validator(node_attestation_validator)
                .validate(&attestation.multi_node_attestation)
                .context("Error make_basic_multinode_attestation_validator")?;

        let [
            TpmEvent::Bootstrapper(BootstrapperTpmEvents::K3sClusterCreated { .. }),
            TpmEvent::Bootstrapper(BootstrapperTpmEvents::K3sClusterStartprovisioning {
                provisioning_bundle_digest,
            }),
            TpmEvent::Bootstrapper(BootstrapperTpmEvents::SingatureInfo { .. }),
        ] = &multi_node_info.master_events[..]
        else {
            bail!(
                "The events of the master node are not in the correct order [K3sClusterCreated, K3sClusterStartprovisioning, SingatureInfo]"
            );
        };

        Ok(ClusterInfo {
            attestation_backend: multi_node_info.attestation_backend,
            operator_cert: multi_node_info.operator_cert_pem,
            provisioning_bundle_digest: provisioning_bundle_digest.to_string(),
            eventlog: multi_node_info.master_events,
            os_measurement: multi_node_info.os_measurement,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetAttestationDocumentResponse {
    attestation_document: NodeAttestationDocumentWithEvents,
}

impl GetAttestationDocumentResponse {
    pub fn new(attestation_document: NodeAttestationDocumentWithEvents) -> Self {
        GetAttestationDocumentResponse {
            attestation_document,
        }
    }
    pub fn get_attestation_document(self) -> NodeAttestationDocumentWithEvents {
        self.attestation_document
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InitAsMasterResponse {
    pub multi_node_attestation: MultiNodeAttestation,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum ProvisioningState {
    NotStarted,
    InProgress,
    Error,
    Provisioned,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProvisionClusterResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClusterAttestationResponse {
    pub cluster_attestation: ClusterAttestation,
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum AttestationBackend {
    QEMU,
    SvsmVtpm,
    AzureTrustedLaunchVM,
    AzureConfidentialVM,
    GcpShieldedVM,
}

impl FromStr for AttestationBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SvsmVtpm" => Ok(AttestationBackend::SvsmVtpm),
            "QEMU" => Ok(AttestationBackend::QEMU),
            "AzureTrustedLaunchVM" => Ok(AttestationBackend::AzureTrustedLaunchVM),
            "AzureConfidentialVM" => Ok(AttestationBackend::AzureConfidentialVM),
            "GcpShieldedVM" => Ok(AttestationBackend::GcpShieldedVM),
            _ => Err(anyhow::format_err!(
                "Choose an attestation backend between SvsmVtpm, QEMU, AzureTrustedLaunchVM, AzureConfidentialVM, GcpShieldedVM. "
            )),
        }
    }
}

impl Display for AttestationBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            AttestationBackend::QEMU => write!(f, "QEMU"),

            AttestationBackend::SvsmVtpm => write!(f, "SvsmVtpm"),

            AttestationBackend::AzureTrustedLaunchVM => write!(f, "AzureTrustedLaunchVM"),

            AttestationBackend::AzureConfidentialVM => write!(f, "AzureConfidentialVM"),

            AttestationBackend::GcpShieldedVM => write!(f, "GcpShieldedVM"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct InitAsSlaveRequest {
    pub master_cert_pem: String,
    pub master_hostname: String,
    pub role: Role,
    pub name: String,
    pub public_ip: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum Role {
    Agent,
    Server,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Node {
    pub address: String,
    pub port: String,
    pub cert_pem: String,
}

#[derive(Serialize, Deserialize)]
pub struct InitAsMasterRequest {
    pub slaves: Vec<Node>,
    pub public_ip: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetInstanceIdentityDocumentResponse {
    pub instance_id_document: Option<ImdsAttestedDocumentResponse>,
    pub cert_pem: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ClusterNode {
    pub name: String,
    pub address: String,
    pub vm_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ClusterConfiguration {
    servers: Vec<ClusterNode>,
    agents: Vec<ClusterNode>,
}

impl ClusterConfiguration {
    pub fn get_servers(&self) -> Vec<ClusterNode> {
        self.servers.clone()
    }

    pub fn get_agents(&self) -> Vec<ClusterNode> {
        self.agents.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub struct ImdsAttestedDocumentResponse {
    pub encoding: String,
    pub signature: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestedDocument {
    pub license_type: String,
    pub nonce: String,
    pub plan: Plan,
    pub sku: String,
    pub subscription_id: String,
    pub time_stamp: TimeStamp,
    pub vm_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub name: String,
    pub product: String,
    pub publisher: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeStamp {
    pub created_on: String,
    pub expires_on: String,
}

pub struct CertWithPrivateKeyPem {
    pub cert: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Proof {
    pub signed_csr_b64: String,
    pub attestation_b64: String,
}

pub fn verify_csr_signature(
    signed_csr_bytes: Vec<u8>,
    public_key: PublicKey,
) -> anyhow::Result<Vec<u8>> {
    let signed_csr_message: SignedMessage<StackByteArray<64>, Vec<u8>> =
        SignedMessage::from_bytes(&signed_csr_bytes)
            .context("Error converting signed_csr_bytes to a signed_csr_message")?;

    // Verify the signature of the CSR with the public key contained in the the Attestation Log
    signed_csr_message
        .verify(&public_key)
        .context("The CSR signature could not be verified.")?;

    Ok(signed_csr_message.into_parts().1)
    // With the default configuration we just need to check the presence of the SubjectAlternativeName extension
    // with one DNSName entry, equal to the domain.
    // Here is a typical CSR we expect to see from the cluster:
    // Certificate Request:
    // Data:
    //     Version: 1 (0x0)
    //     Subject:
    //     Subject Public Key Info:
    //         Public Key Algorithm: id-ecPublicKey
    //             Public-Key: (256 bit)
    //             pub:
    //                 04:[...]:e4
    //             ASN1 OID: prime256v1
    //             NIST CURVE: P-256
    //     Attributes:
    //         Requested Extensions:
    //             X509v3 Subject Alternative Name: critical
    //                 DNS:example.com
    //             X509v3 Key Usage: critical
    //                 Digital Signature, Key Encipherment
    // Signature Algorithm: ecdsa-with-SHA256
    // Signature Value:
    //     30:[...]:c7

    // let (_, csr_data) = parse_x509_pem(&csr_pem).context("Could not parse the csr_pem")?;
    // let (_, csr) = X509CertificationRequest::from_der(&csr_data.contents)
    //     .context("Failed parsing csr from PEM to X509CertificationRequest")?;

    // let mut general_names = Vec::new();

    // if let Some(required_extensions) = csr.requested_extensions() {
    //     for extension in required_extensions {
    //         if let ParsedExtension::SubjectAlternativeName(ext) = extension {
    //             general_names = ext.general_names.clone();
    //         }
    //     }
    // } else {
    //     bail!("No requested_extensions found in CSR");
    // }

    // ensure!(
    //     general_names.len() == 1,
    //     "The length of the list of General Names in the SubjectAlternativeName for this CSR must be equal to 1."
    // );
    // ensure!(
    //     general_names[0] == GeneralName::DNSName(&domain),
    //     "The domain contained in the CSR does not match the one in the request parameters"
    // );
    // Ok(csr.certification_request_info.subject_pki)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct PlatformMeasurements {
    pub expected_pcr_data: Vec<PcrData>,
}

/// Handles parsing the measurements from CLI
pub fn parse_cli_measurements(
    platform_measurements_path: PathBuf,
    os_measurement: String,
) -> anyhow::Result<(PlatformMeasurements, Vec<u8>)> {
    ensure!(
        platform_measurements_path.is_file(),
        "The path to the platform measurements file is not valid"
    );

    let platform_measurement_str = fs::read_to_string(platform_measurements_path)
        .context("Unable to read platform measurements file")?;
    let platform_measurements: PlatformMeasurements =
        serde_json::from_str(platform_measurement_str.as_str())
            .context("Can't parse the platform measurements file")?;

    ensure!(!os_measurement.is_empty(), "The os_measurement is empty.");

    let os_measurement_vec =
        hex::decode(os_measurement).context("Error decoding os measurement hex string")?;

    Ok((platform_measurements, os_measurement_vec))
}

// The certificates were sourced from Microsoft's official Azure documentation :
// https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-ca-details?tabs=root-and-subordinate-cas-list
pub const AZURE_ROOT_CERTS: &[&[u8]] = &[
    include_bytes!("../root_ca_azure/DigiCertGlobalRootCA.crt"),
    include_bytes!("../root_ca_azure/DigiCertGlobalRootG2.crt"),
    include_bytes!("../root_ca_azure/DigiCertGlobalRootG3.crt"),
    include_bytes!("../root_ca_azure/DigiCertTLSECCP384RootG5.crt"),
    include_bytes!("../root_ca_azure/DigiCertTLSRSA4096RootG5.crt"),
    include_bytes!("../root_ca_azure/Microsoft ECC Root Certificate Authority 2017.crt"),
    include_bytes!("../root_ca_azure/Microsoft RSA Root Certificate Authority 2017.crt"),
];

pub const PROTOCOL_PORT: &str = "3443";

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub package: Package,
}

#[derive(Serialize, Deserialize)]
pub struct Package {
    pub deploy: Deploy,
}

#[derive(Serialize, Deserialize)]
pub struct Deploy {
    pub set: HashMap<String, String>,
}

impl Config {
    pub fn empty() -> Self {
        Self {
            package: Package {
                deploy: Deploy {
                    set: HashMap::new(),
                },
            },
        }
    }
}
