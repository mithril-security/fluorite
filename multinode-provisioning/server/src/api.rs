use std::{fs, path::Path, sync::Arc};

use crate::tpm::get_attestation_document;
use anyhow::{Context, anyhow, bail, ensure};
use asn1_rs::oid;
use attestation::cbor;
use attestation::eventlog::LiveEventLog;
use axum::{
    Extension, Json,
    extract::{Multipart, State},
};
use base64::prelude::*;
use dryoc::sign::SigningKeyPair;
use log::{debug, error, info};
use provisioning_structs::structs::{
    AttestationBackend, BootstrapperTpmEvents, ClusterAttestation, ClusterAttestationResponse,
    Config, EVENT_LOG_SLOT, GetAttestationDocumentResponse, GetInstanceIdentityDocumentResponse,
    ImdsAttestedDocumentResponse, InitAsMasterRequest, InitAsMasterResponse, InitAsSlaveRequest,
    MultiNodeAttestation, Node, NodeAttestationDocumentWithEvents, ProvisionClusterResponse,
    ProvisioningState, Role, TpmEvent,
};
use rcgen::{BasicConstraints, CustomExtension, Issuer};
use rcgen::{CertificateParams, CertifiedKey, DnType, IsCa, KeyPair};
use rustls::{ClientConfig, pki_types::CertificateDer};
use rustls_pemfile::Item;
use rustls_pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Serialize};
use sha256::try_digest;
use std::{thread, time::Duration};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::{fs::File, io::AsyncWriteExt};
use tpm_quote::generate::tpm_context;

use crate::{
    client_tls_config::PeerServerVerifier, server_tls_acceptor::TlsData, web_error::AppError,
};
use axum::response::IntoResponse;
use std::process::Command;

pub(crate) struct MasterState {
    slaves: Vec<Node>,
    slaves_attestation_document: Vec<NodeAttestationDocumentWithEvents>,
    event_log: LiveEventLog<TpmEvent>,
    public_ip: String,
}

pub(crate) enum Status {
    Initial,
    Slave {
        master_cert: CertificateDer<'static>,
        attestation_document: NodeAttestationDocumentWithEvents,
        master_hostname: String,
        role: Role,
        public_ip: String,
        name: String,
    },
    Master(MasterState),
}

#[derive(Clone)]
pub struct MyState {
    pub status: Arc<Mutex<Status>>,
    pub certified_key: Arc<CertifiedKey<KeyPair>>,
    pub creator_cert: CertificateDer<'static>,
    pub provisioning_state: Arc<Mutex<ProvisioningState>>,
    pub attestation_backend: AttestationBackend,
}

pub(crate) async fn handler(tls_data: Extension<TlsData>) -> String {
    format!("{:?}", tls_data)
}

pub(crate) fn ensure_request_is_from_creator(
    tlsdata: &TlsData,
    creator_cert: &CertificateDer<'static>,
) -> anyhow::Result<()> {
    let [cert] = &tlsdata.peer_certificates[..] else {
        bail!("Peer certificates is not a single certificate");
    };
    if cert != creator_cert {
        bail!("Bad certificate. The certificate is not the operator's certificate.")
    }
    Ok(())
}

pub(crate) fn ensure_request_is_from_master(
    tlsdata: &TlsData,
    master_cert: &CertificateDer,
) -> anyhow::Result<()> {
    let [peer_cert] = &tlsdata.peer_certificates[..] else {
        bail!("Peer certificates is not a single certificate");
    };
    if peer_cert != master_cert {
        bail!("Presented certificate is not the expected client certificate");
    }
    Ok(())
}

impl MyState {
    // #[get("/get_instance_identity_document")]
    async fn get_instance_identity_document(
        self,
        tlsdata: TlsData,
    ) -> anyhow::Result<GetInstanceIdentityDocumentResponse> {
        if ensure_request_is_from_creator(&tlsdata, &self.creator_cert).is_err() {
            bail!("Unauthorized. Only the creator can call get_instance_identity_document");
        }

        if self.attestation_backend == AttestationBackend::AzureTrustedLaunchVM
            || self.attestation_backend == AttestationBackend::AzureConfidentialVM
        {
            Ok(GetInstanceIdentityDocumentResponse {
                instance_id_document: Some(get_imds_id_document().await?),
                cert_pem: self.certified_key.cert.pem(),
            })
        } else {
            Ok(GetInstanceIdentityDocumentResponse {
                instance_id_document: None,
                cert_pem: self.certified_key.cert.pem(),
            })
        }
    }

    async fn init_as_slave(
        self,
        tls_data: TlsData,
        args: InitAsSlaveRequest,
    ) -> anyhow::Result<()> {
        if ensure_request_is_from_creator(&tls_data, &self.creator_cert).is_err() {
            bail!("Unauthorized. Only the creator can call init_as_slave");
        }

        let mut state = self.status.lock().await;

        if !matches!(*state, Status::Initial) {
            bail!("Server is not in initial state");
        }

        let (pem_item, _remaining) =
            rustls_pemfile::read_one_from_slice(args.master_cert_pem.as_bytes())
                .map_err(|err| anyhow!("{:?}", err))?
                .context("No PEM")?;

        let cert = match pem_item {
            Item::X509Certificate(ref_client_cert_der) => ref_client_cert_der,
            _ => bail!("Pem file provided is not a X509 Certificate"),
        };

        let tpm_ctx = tpm_context()?;
        let mut event_log = LiveEventLog::new(tpm_ctx, EVENT_LOG_SLOT);

        event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::BootstrapperStarting {
                service_cert_pem: self.certified_key.cert.pem(),
                operator_cert_pem: der_to_str(self.creator_cert)?,
            },
        ))?;

        event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::InitAsSlave {
                master_cert: args.master_cert_pem,
                master_ip: args.master_hostname.clone(),
                role: args.role,
            },
        ))?;

        let attestation_document = get_attestation_document(self.attestation_backend)
            .await
            .context("Error getting attestation document in init_as_slave")?;

        let attestation_document_with_events = NodeAttestationDocumentWithEvents {
            attestation_document,
            serialized_events: event_log.get_eventlog().clone(),
        };
        *state = Status::Slave {
            master_cert: cert,
            attestation_document: attestation_document_with_events,
            master_hostname: args.master_hostname,
            role: args.role,
            name: args.name,
            public_ip: args.public_ip,
        };

        Ok(())
    }

    async fn init_as_master(
        self,
        tls_data: TlsData,
        // identity: Identity,
        args: InitAsMasterRequest,
    ) -> anyhow::Result<InitAsMasterResponse> {
        if ensure_request_is_from_creator(&tls_data, &self.creator_cert).is_err() {
            bail!("Unauthorized. Only the creator can call init_as_master");
        }
        let mut state = self.status.lock().await;

        if !matches!(*state, Status::Initial) {
            bail!("Server is not in initial state");
        }
        let tpm_ctx = tpm_context()?;
        let mut event_log = LiveEventLog::new(tpm_ctx, EVENT_LOG_SLOT);

        event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::BootstrapperStarting {
                service_cert_pem: self.certified_key.cert.pem(),
                operator_cert_pem: der_to_str(self.creator_cert)?,
            },
        ))?;

        let mut slaves_attestation_document = vec![];
        for slave in &args.slaves {
            let slave_cert = pem_to_der(&slave.cert_pem)?;
            let server_verifier = PeerServerVerifier::new_with_default_provider(slave_cert);

            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(server_verifier))
                .with_client_auth_cert(
                    vec![self.certified_key.cert.der().clone().into_owned()],
                    PrivatePkcs8KeyDer::from(self.certified_key.signing_key.serialize_der()).into(),
                )?;

            let client = reqwest::Client::builder()
                .use_rustls_tls()
                .use_preconfigured_tls(config)
                .build()
                .context("Error when creating reqwest client")?;

            let response = client
                .get(format!(
                    "https://{}:{}/slave/get_attestation_document",
                    slave.address, slave.port
                ))
                .send()
                .await
                .context("Error while requesting get_attestation_document from a slave")?;

            if response.status().is_success() {
                let slave_attestation_document_resp: GetAttestationDocumentResponse = response
                    .json()
                    .await
                    .context("Error while parsing get_attestation_document from a slave")?;
                slaves_attestation_document
                    .push(slave_attestation_document_resp.get_attestation_document());
            } else {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Failed to read body".to_string());
                bail!(format!(
                    "Error code returned by slave in get_attestation_document. {}. {}",
                    status, body
                ))
            }
        }
        let slaves_cert: Vec<String> = args
            .slaves
            .iter()
            .map(|node| node.cert_pem.clone())
            .collect();

        event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::InitAsMaster { slaves_cert },
        ))?;

        let attestation_document = get_attestation_document(self.attestation_backend)
            .await
            .context("Error getting the attestation document in init_as_master")?;

        let master_attest_document = NodeAttestationDocumentWithEvents {
            attestation_document,
            serialized_events: event_log.get_eventlog().clone(),
        };
        let multi_node_attestation = MultiNodeAttestation {
            master_attestation_document: master_attest_document,
            slaves_attestation_document: slaves_attestation_document.clone(),
        };
        *state = Status::Master(MasterState {
            slaves: args.slaves.clone(),
            slaves_attestation_document,
            event_log,
            public_ip: args.public_ip,
        });

        let response = InitAsMasterResponse {
            multi_node_attestation,
        };
        Ok(response)
    }

    async fn cluster_attestation(
        self,
        tls_data: TlsData,
        // identity: Identity,
    ) -> anyhow::Result<ClusterAttestationResponse> {
        if ensure_request_is_from_creator(&tls_data, &self.creator_cert).is_err() {
            bail!("Unauthorized. Only the creator can call /master/cluster_attestation");
        }
        let mut state = self.status.lock().await;

        let Status::Master(ref mut master_state) = *state else {
            bail!("Server is not initialized as master");
        };

        let state = self.provisioning_state.lock().await;
        if !matches!(*state, ProvisioningState::Provisioned) {
            bail!("The cluster is not yet provisioned");
        }

        let attestation_document = get_attestation_document(self.attestation_backend)
            .await
            .context("Error getting the attestation document in cluster_attestation")?;

        let master_attest_document = NodeAttestationDocumentWithEvents {
            attestation_document,
            serialized_events: master_state.event_log.get_eventlog().clone(),
        };

        let multi_node_attestation = MultiNodeAttestation {
            master_attestation_document: master_attest_document,
            slaves_attestation_document: master_state.slaves_attestation_document.clone(),
        };

        let cluster_attestation = ClusterAttestation {
            multi_node_attestation,
        };
        Ok(ClusterAttestationResponse {
            cluster_attestation,
        })
    }
    async fn slave_get_attestation_document(
        self,
        tls_data: TlsData,
    ) -> anyhow::Result<GetAttestationDocumentResponse> {
        let state = self.status.lock().await;

        let (attestation_doc, master_cert) = match *state {
            Status::Slave {
                ref master_cert,
                ref attestation_document,
                ..
            } => (attestation_document, master_cert),
            _ => {
                bail!("Server is not initialized as slave")
            }
        };

        if ensure_request_is_from_master(&tls_data, master_cert).is_err() {
            bail!("only master node can call /slave/get_attestation_document");
        }

        Ok(GetAttestationDocumentResponse::new(attestation_doc.clone()))
    }

    async fn cluster_status(self, tls_data: TlsData) -> anyhow::Result<ProvisioningState> {
        if ensure_request_is_from_creator(&tls_data, &self.creator_cert).is_err() {
            bail!("only the creator can provision the cluster");
        }

        Ok(*self.provisioning_state.lock().await)
    }

    async fn slave_join_cluster(
        self,
        args: JoinClusterRequest,
        tls_data: TlsData,
    ) -> anyhow::Result<()> {
        let state = self.status.lock().await;

        let (master_cert, _attestation_doc, master_hostname, role, public_ip, name) = match *state {
            Status::Slave {
                ref master_cert,
                ref attestation_document,
                ref master_hostname,
                ref role,
                ref public_ip,
                ref name,
            } => (
                master_cert,
                attestation_document,
                master_hostname,
                role,
                public_ip,
                name,
            ),
            _ => {
                bail!("Invalid request, server is not initialized as slave")
            }
        };

        if ensure_request_is_from_master(&tls_data, master_cert).is_err() {
            bail!("only master node can call /slave/join_cluster");
        }

        let mut child = match role {
            Role::Agent => {
                info!(
                    "INSTALL_K3S_BIN_DIR_READ_ONLY=true INSTALL_K3S_SKIP_DOWNLOAD=true K3S_TOKEN={} K3S_URL={} K3S_NODE_NAME={} /usr/local/bin/install.sh agent {} ",
                    args.k3s_token,
                    format!("https://{master_hostname}:6443"),
                    name,
                    format!("--node-external-ip={}", public_ip).as_str()
                );

                Command::new("/usr/local/bin/install.sh")
                    .args([
                        "agent",
                        format!("--node-external-ip={}", public_ip).as_str(),
                    ])
                    .env("INSTALL_K3S_SKIP_DOWNLOAD", "true")
                    .env("INSTALL_K3S_BIN_DIR_READ_ONLY", "true")
                    .env("K3S_TOKEN", args.k3s_token)
                    .env("K3S_URL", format!("https://{master_hostname}:6443"))
                    .env("K3S_NODE_NAME", name)
                    .spawn()
                    .context("Error starting /usr/local/bin/k3s agent (slave)")?
            }
            Role::Server => {
                info!(
                    "INSTALL_K3S_BIN_DIR_READ_ONLY=true INSTALL_K3S_SKIP_DOWNLOAD=true K3S_TOKEN={} K3S_URL={} K3S_NODE_NAME={} /usr/local/bin/install.sh server --disable=traefik {} --flannel-external-ip --flannel-backend=wireguard-native",
                    args.k3s_token,
                    format!("https://{master_hostname}:6443"),
                    name,
                    format!("--node-external-ip={}", public_ip).as_str(),
                );

                Command::new("/usr/local/bin/install.sh")
                    .args([
                        "server",
                        "--disable=traefik",
                        format!("--node-external-ip={}", public_ip).as_str(),
                        "--flannel-external-ip",
                        "--flannel-backend=wireguard-native",
                    ])
                    .env("INSTALL_K3S_SKIP_DOWNLOAD", "true")
                    .env("INSTALL_K3S_BIN_DIR_READ_ONLY", "true")
                    .env("K3S_TOKEN", args.k3s_token)
                    .env("K3S_URL", format!("https://{master_hostname}:6443"))
                    .env("K3S_NODE_NAME", name)
                    .spawn()
                    .context("Error starting /usr/local/bin/k3s server (slave)")?
            }
        };

        let status = child.wait().context(
            "Startup of the slave node failed. Please check k3s log: `journalctl -xeu k3s -f`",
        )?;

        let status_code = status.code().ok_or(anyhow::format_err!(
            "Error getting exit code of k3s join cluster command"
        ))?;

        info!(
            "Startup of the k3s service for the slave node exited with status code: {}",
            status_code
        );

        // Detach the process so it continues running independently
        tokio::spawn(async move {
            let status = child
                .wait()
                .expect("Subcommand exited with non-zero exit code");
            info!("Subcommand exited with: {}", status.code().unwrap());
        });

        Ok(())
    }

    // #[post("/master/provision_cluster")]
    async fn master_provision_cluster(
        self,
        mut args: Multipart,
        tls_data: TlsData,
    ) -> anyhow::Result<ProvisionClusterResponse> {
        if ensure_request_is_from_creator(&tls_data, &self.creator_cert).is_err() {
            bail!("only the creator can provision the cluster");
        }

        let mut state = self.status.lock().await;

        let Status::Master(ref mut master_state) = *state else {
            bail!("Server is not initialized as master");
        };

        {
            let mut provisioning_state = self.provisioning_state.lock().await;

            if !matches!(*provisioning_state, ProvisioningState::NotStarted) {
                bail!(
                    "Cluster provisioning has already started, check the status at the /cluster_status endpoint"
                )
            }
            *provisioning_state = ProvisioningState::InProgress;
        }

        let bundle_path = Path::new("/tmp/package.tar.zst");
        let mut deployment_config = Config::empty();
        let mut deployment_size = None;
        while let Some(field) = args.next_field().await.expect("Failed to get next field!") {
            match field.name().unwrap() {
                "provisioning_bundle" => {
                    let mut file = File::create(bundle_path)
                        .await
                        .expect("Failed to open file handle!");

                    let bytes = &field.bytes().await?;
                    let bundle_size = bytes.len() as u64;

                    // Enough space for the bundle itself, zarf cache and some extra room
                    let tpm_path = String::from("/tmp");

                    let tpm_size = (bundle_size * 3).max(5 * 1024 * 1024 * 1024); // At least 5 GB

                    mount_helper(tpm_path, tpm_size)
                        .await
                        .context("Error remounting /tmp")?;

                    file.write_all(bytes)
                        .await
                        .expect("Failed to write file bytes!");
                }
                "deployment_config" => {
                    let txt = field.text().await?;
                    debug!("{}", txt);
                    deployment_config = serde_yaml::from_str(&txt)
                        .context("Error deserializing deployment config")?;
                    ensure!(
                        !deployment_config
                            .package
                            .deploy
                            .set
                            .contains_key("CA_KEY_B64")
                            && !deployment_config
                                .package
                                .deploy
                                .set
                                .contains_key("CA_CRT_B64")
                            && !deployment_config
                                .package
                                .deploy
                                .set
                                .contains_key("ATTESTATION_B64")
                            && !deployment_config
                                .package
                                .deploy
                                .set
                                .contains_key("SIGNATURE_PRIVATE_KEY_B64"),
                        "The secrets keys `CA_KEY_B64`, `CA_CRT_B64`, `SIGNATURE_PRIVATE_KEY_B64`, `ATTESTATION_B64` are reserved."
                    );
                }
                "deployment_size" => {
                    // The deployment size in bytes
                    let sz: u64 = field
                        .text()
                        .await?
                        .parse()
                        .context("Could not convert deployment_size to u64")?;
                    deployment_size = Some(sz);
                }
                _ => continue,
            }
        }

        // Esure the file was written
        if !bundle_path.exists() {
            let mut provisioning_state = self.provisioning_state.lock().await;
            *provisioning_state = ProvisioningState::Error;
            bail!(anyhow::format_err!(
                "Required provisioning package {} is missing.",
                bundle_path.display()
            ));
        }

        log::info!("Setting up file system mount points for the provisioning bundle deployments");

        if let Some(deployment_size) = deployment_size {
            let tpm_path = String::from("/var/lib/rancher");

            mount_helper(tpm_path, deployment_size)
                .await
                .context("Error remounting /var/lib/rancher")?;
        }

        let root_ca_key_pair = KeyPair::generate()?;
        let mut root_ca_certificate_params = CertificateParams::default();
        root_ca_certificate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_ca_certificate_params
            .distinguished_name
            .push(DnType::CommonName, "rootCA");
        let root_ca_cert = root_ca_certificate_params.self_signed(&root_ca_key_pair)?;

        master_state.event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::K3sClusterCreated {
                k3s_root_ca_pem: root_ca_cert.pem(),
            },
        ))?;

        master_state.event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::K3sClusterStartprovisioning {
                provisioning_bundle_digest: try_digest(bundle_path)?,
            },
        ))?;

        let keypair = SigningKeyPair::gen_with_defaults();

        master_state.event_log.push_event(&TpmEvent::Bootstrapper(
            BootstrapperTpmEvents::SingatureInfo {
                public_key: keypair.public_key.clone(),
            },
        ))?;

        deployment_config.package.deploy.set.insert(
            "SIGNATURE_PRIVATE_KEY_B64".to_string(),
            BASE64_STANDARD.encode(keypair.secret_key.clone()),
        );

        let intermediate_ca_key_pair = KeyPair::generate()?;
        let mut intermediate_ca_certificate_params = CertificateParams::default();
        intermediate_ca_certificate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_ca_certificate_params
            .distinguished_name
            .push(DnType::CommonName, "intermediateCA");

        let attestation_document = get_attestation_document(self.attestation_backend)
            .await
            .context("Error getting the attestation document in provision_cluster")?;

        let master_attest_document = NodeAttestationDocumentWithEvents {
            attestation_document,
            serialized_events: master_state.event_log.get_eventlog().clone(),
        };

        let multi_node_attestation = MultiNodeAttestation {
            master_attestation_document: master_attest_document,
            slaves_attestation_document: master_state.slaves_attestation_document.clone(),
        };

        let cluster_attestation = ClusterAttestation {
            multi_node_attestation,
        };

        let attestation_document_vec_u8 = cbor::to_vec(&cluster_attestation)?;

        deployment_config.package.deploy.set.insert(
            "ATTESTATION_B64".to_string(),
            BASE64_STANDARD.encode(attestation_document_vec_u8.clone()),
        );

        // Use: https://oid-base.com/get/2.25 6361521164412852795
        // Generated with `random.randint(0, (1<<63)-1)`
        // https://github.com/rustls/rcgen/blob/dd0e101b707a7c7d962df40c175aa94a68fc8771/rcgen/tests/generic.rs#L80
        // Currently they don't support arcs with number larger than an u64, this is why the number was generated this way.
        let oid = oid!(2.25.636152116);

        let custom_extension_attestation_document = CustomExtension::from_oid_content(
            oid.iter().unwrap().collect::<Vec<u64>>().as_slice(),
            attestation_document_vec_u8,
        );

        intermediate_ca_certificate_params
            .custom_extensions
            .push(custom_extension_attestation_document);

        let intermediate_ca_cert = intermediate_ca_certificate_params.signed_by(
            &intermediate_ca_key_pair,
            &Issuer::from_params(&root_ca_certificate_params, &root_ca_key_pair),
        )?;

        let ca_crt = format!("{}{}", intermediate_ca_cert.pem(), root_ca_cert.pem());
        deployment_config
            .package
            .deploy
            .set
            .insert("CA_CRT_B64".to_string(), BASE64_STANDARD.encode(ca_crt));

        let ca_key = intermediate_ca_key_pair.serialize_pem();

        deployment_config
            .package
            .deploy
            .set
            .insert("CA_KEY_B64".to_string(), BASE64_STANDARD.encode(ca_key));

        let public_ip = master_state.public_ip.clone();
        let slaves = master_state.slaves.clone();

        // TODO:  provision_cluster_helper starts a subtask that can fail, we want to be able to track that and set
        // provisioning_state = ProvisioningState::Error appropriately
        tokio::spawn(async move {
            if let Err(e) = provision_cluster_helper(
                public_ip,
                slaves,
                self.certified_key,
                bundle_path,
                deployment_config,
            )
            .await
            {
                let mut provisioning_state = self.provisioning_state.lock().await;
                *provisioning_state = ProvisioningState::Error;
                error!("Error in the cluster provisioning helper: {}", e);
            } else {
                let mut provisioning_state = self.provisioning_state.lock().await;
                *provisioning_state = ProvisioningState::Provisioned;
                info!("Cluster provisioned successfully!");
            };
        });

        Ok(ProvisionClusterResponse { message: "Cluster provisioning started. Check the progress by GETting the /cluster_status endpoint".to_string() })
    }
}

// #[post("/init_as_slave")]
pub(crate) async fn init_as_slave(
    Extension(tls_data): Extension<TlsData>,
    State(mystate): State<MyState>,
    Json(args): Json<InitAsSlaveRequest>,
) -> Result<impl IntoResponse, AppError> {
    tokio::spawn(async move { mystate.init_as_slave(tls_data, args).await }).await??;
    Ok(Json(()))
}

// #[post("/init_as_master")]
pub(crate) async fn init_as_master(
    Extension(tls_data): Extension<TlsData>,
    State(mystate): State<MyState>,
    Json(args): Json<InitAsMasterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result =
        tokio::spawn(async move { mystate.init_as_master(tls_data, args).await }).await??;
    Ok(Json(result))
}

// #[get("/slave/get_attestation_document")]
pub(crate) async fn slave_get_attestation_document(
    Extension(tls_data): Extension<TlsData>,
    State(mystate): State<MyState>,
) -> Result<impl IntoResponse, AppError> {
    let result =
        tokio::spawn(async move { mystate.slave_get_attestation_document(tls_data).await })
            .await??;
    Ok(Json(result))
}

// #[get("/cluster_status")]
pub(crate) async fn cluster_status(
    Extension(tls_data): Extension<TlsData>,
    State(mystate): State<MyState>,
) -> Result<impl IntoResponse, AppError> {
    let result = tokio::spawn(async move { mystate.cluster_status(tls_data).await }).await??;
    Ok(Json(result))
}

// #[post("/slave/get_attestation_document")]
pub(crate) async fn slave_join_cluster(
    State(mystate): State<MyState>,
    Extension(tls_data): Extension<TlsData>,
    Json(args): Json<JoinClusterRequest>,
) -> Result<impl IntoResponse, AppError> {
    tokio::spawn(async move { mystate.slave_join_cluster(args, tls_data).await }).await??;
    Ok(Json(()))
}

// #[get("/master/cluster_attestation")]
pub(crate) async fn cluster_attestation(
    State(mystate): State<MyState>,
    Extension(tls_data): Extension<TlsData>,
) -> Result<impl IntoResponse, AppError> {
    let result = tokio::spawn(async move { mystate.cluster_attestation(tls_data).await }).await??;
    Ok(Json(result))
}

// #[post("/master/provision_cluster")]
pub(crate) async fn master_provision_cluster(
    State(mystate): State<MyState>,
    Extension(tls_data): Extension<TlsData>,
    args: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let result =
        tokio::spawn(async move { mystate.master_provision_cluster(args, tls_data).await })
            .await??;
    Ok(Json(result))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct JoinClusterRequest {
    k3s_token: String,
}

// #[get("/get_instance_identity_document")]
pub(crate) async fn get_instance_identity_document(
    Extension(tls_data): Extension<TlsData>,
    State(mystate): State<MyState>,
) -> Result<impl IntoResponse, AppError> {
    let result =
        tokio::spawn(async move { mystate.get_instance_identity_document(tls_data).await })
            .await??;
    Ok(Json(result))
}

pub(crate) fn pem_to_der(pem_cert: &str) -> anyhow::Result<CertificateDer<'static>> {
    let (pem_item, _remaining) = rustls_pemfile::read_one_from_slice(pem_cert.as_bytes())
        .map_err(|e| anyhow!("{:?}", e))
        .context("Could not read a PEM file")?
        .context("No PEM item")?;

    let Item::X509Certificate(cert_der) = pem_item else {
        bail!("Pem file provided is not a X509 Certificate");
    };
    Ok(cert_der)
}

pub(crate) fn der_to_str(cert_der: CertificateDer<'static>) -> anyhow::Result<String> {
    let base64_cert = BASE64_STANDARD.encode(cert_der);
    Ok(format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_cert
            .as_bytes()
            .chunks(64) // PEM format splits base64 into 64-character lines
            .map(std::str::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n")
    ))
}

async fn mount_helper(path: String, size_bytes: u64) -> anyhow::Result<()> {
    let mut child = Command::new("/usr/bin/mount")
        .args(["-o", &format!("remount,size={}", size_bytes), &path])
        .spawn()
        .context(anyhow::format_err!(
            "Error starting mount command to remount {}",
            path
        ))?;

    let status = child
        .wait()
        .context("Error waiting for the mount command to complete")?;

    let status_code = status.code().ok_or(anyhow::format_err!(
        "Error getting the status code of the mount command"
    ))?;

    log::info!("Mount command exited with: {}", status_code);
    ensure!(
        status.success(),
        "The mount command did not complete successfully"
    );

    Ok(())
}
async fn provision_cluster_helper(
    public_ip: String,
    slaves: Vec<Node>,
    certified_key: Arc<CertifiedKey<KeyPair>>,
    bundle_path: &Path,
    deployment_config: Config,
) -> anyhow::Result<()> {
    info!(
        "INSTALL_K3S_BIN_DIR_READ_ONLY=true INSTALL_K3S_SKIP_DOWNLOAD=true K3S_NODE_NAME=master /usr/local/bin/install.sh server --disable=traefik --cluster-init --flannel-backend=wireguard-native --write-kubeconfig-mode 644 --flannel-external-ip --node-external-ip={}",
        public_ip
    );

    let mut child = Command::new("/usr/local/bin/install.sh")
        .args([
            "server",
            "--disable=traefik",
            "--cluster-init",
            "--flannel-backend=wireguard-native",
            "--write-kubeconfig-mode",
            "644",
            "--flannel-external-ip",
            format!("--node-external-ip={}", public_ip).as_str(),
        ])
        .env("INSTALL_K3S_SKIP_DOWNLOAD", "true")
        .env("INSTALL_K3S_BIN_DIR_READ_ONLY", "true")
        .env("K3S_NODE_NAME", "master")
        .spawn()
        .context("Error starting /usr/local/bin/k3s server (master)")?;

    let status = child.wait().context(
        "Startup of the master node failed. Please check k3s log: `journalctl -xeu k3s -f`",
    )?;

    let status_code = status.code().ok_or(anyhow::format_err!(
        "Error getting exit code of the k3s service for the master node"
    ))?;

    info!(
        "Startup of the k3s service for the master node exited with status code: {}",
        status_code
    );

    ensure!(
        status.success(),
        format!(
            "Startup of the k3s service for the master node exited with status code: {}",
            status_code
        )
    );

    let k3s_token: String = loop {
        debug!("Waiting for the creation of /var/lib/rancher/k3s/server/token");
        let file = File::open("/var/lib/rancher/k3s/server/token").await;
        if let Ok(mut file) = file {
            let mut contents = vec![];
            file.read_to_end(&mut contents).await?;

            let token = String::from_utf8(contents)?.trim().to_string();
            break token;
        }
        thread::sleep(Duration::from_millis(2000));
    };

    // Wait some extra time for the master to be ready
    thread::sleep(Duration::from_millis(2000));
    for slave in slaves {
        let slave_cert = pem_to_der(&slave.cert_pem)?;
        let server_verifier = PeerServerVerifier::new_with_default_provider(slave_cert);
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(server_verifier))
            .with_client_auth_cert(
                vec![certified_key.cert.der().clone().into_owned()],
                PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der()).into(),
            )?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .use_preconfigured_tls(config)
            .build()?;
        let req = JoinClusterRequest {
            k3s_token: k3s_token.clone(),
        };
        let resp = client
            .post(format!(
                "https://{}:{}/slave/join_cluster",
                slave.address, slave.port
            ))
            .json(&req)
            .send()
            .await?;
        if resp.error_for_status().is_err() {
            bail!(format!(
                "VM with IP {} has not been able to join the cluster",
                slave.address
            ));
        }
    }

    // Wait for all the workers to be ready
    // Interact with the kubernetes API to verify that the slaves are ready
    // Avoid sleeping if there are no slaves
    info!("Sleeping another 15s. Give time for all the nodes to wake up");
    // TODO: Is there a way of avoiding having to wait for this fixed amount of time, but loop until the server is ready?
    thread::sleep(Duration::from_secs(15));

    info!(
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml zarf init --confirm --set REGISTRY_MEM_LIMIT=40Gi --tmpdir /tmp"
    );

    // Increase the memory limit of the registry, as by default it's set to 40Gi, and the deployment of ollama/ray triggers the OOM killer.

    let mut child = Command::new("zarf")
        .args([
            "init",
            "--confirm",
            "--set",
            "REGISTRY_MEM_LIMIT=40Gi",
            "--zarf-cache",
            "/root/.zarf-cache",
            "--tmpdir",
            "/tmp",
        ])
        .env("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
        .spawn()
        .context("Error starting zarf init")?;
    let status = child.wait()?;

    let status_code = status.code().ok_or(anyhow::format_err!(
        "Error getting exit code of the azrf init command"
    ))?;

    info!("Subcommand exited with: {}", status_code);
    ensure!(status.success(), "Zarf package initialization failed");

    info!(
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml zarf package deploy {} --confirm --retries 10",
        bundle_path.display()
    );
    let args = vec![
        "package".to_string(),
        "deploy".to_string(),
        bundle_path.display().to_string(),
        "--confirm".to_string(),
        "--retries".to_string(),
        "10".to_string(),
        "--oci-concurrency".to_string(),
        "1".to_string(),
        "--timeout".to_string(),
        "25m".to_string(),
        "--zarf-cache".to_string(),
        "/tmp/.zarf-cache".to_string(),
    ];

    // secrets.0.iter().for_each(|(secret_name, secret_value)| {
    //     args.push("--set".to_string());
    //     let variable = format!("\"{}={}\"", secret_name, secret_value);
    //     debug!("{}", variable);
    //     args.push(variable);
    // });

    let zarf_config = serde_yaml::to_string(&deployment_config)
        .context("Error serializing the deployment config")?;
    debug!("/tmp/zarf-config.yaml: \n{}", zarf_config);
    fs::write("/tmp/zarf-config.yaml", zarf_config).context("Error writing zarf-config.yaml")?;

    let mut child = Command::new("zarf")
        .args(args)
        .env("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
        .env("ZARF_CONFIG", "/tmp/zarf-config.yaml")
        .spawn()
        .context("Error starting zarf package deploy")?;

    let status = child.wait()?;
    let status_code = status.code().ok_or(anyhow::format_err!(
        "Error getting exit code of the zarf deploy command"
    ))?;

    info!("Subcommand exited with: {}", status_code);
    ensure!(status.success(), "Zarf package deployment failed");
    info!(
        "The cluster was provisioned, hooray! Removing provisioning package from {}",
        bundle_path.display()
    );

    fs::remove_file(bundle_path).context("Failed removing provisioning package")?;

    Ok(())
}

async fn get_imds_id_document() -> anyhow::Result<ImdsAttestedDocumentResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // The URL we're making a request to
    let url = "http://169.254.169.254/metadata/attested/document?api-version=2021-01-01";

    // Make the GET request, passing in the URL and the headers
    let response = client.get(url).header("Metadata", "true").send().await;
    let response = match response {
        Ok(response) => response.error_for_status()?.json().await?,
        Err(_) => ImdsAttestedDocumentResponse {
            encoding: String::new(),
            signature: String::new(),
        },
    };

    Ok(response)
}
