use azure_core::auth::AccessToken;
use azure_core::auth::TokenCredential;
use azure_mgmt_resources::models::ResourceGroup;
use azure_mgmt_storage::Client;
use azure_mgmt_storage::models::{
    Encryption, EncryptionService, EncryptionServices, NetworkRuleSet, PublicNetworkAccess, Sku,
    SkuName, StorageAccount, StorageAccountCreateParameters, StorageAccountKey,
    StorageAccountListKeysResult, StorageAccountPropertiesCreateParameters, Tier,
    encryption::KeySource,
    encryption_service::KeyType,
    network_rule_set::{Bypass, DefaultAction},
    storage_account_create_parameters::Kind,
    storage_account_properties_create_parameters::{
        AccessTier, DnsEndpointType, MinimumTlsVersion,
    },
};

use anyhow::{Context, anyhow, bail, ensure};
use azure_storage::StorageCredentials;
use azure_storage_blobs::prelude::{ClientBuilder, ContainerClient, StaticWebsite};
use azure_svc_blobstorage::models::StorageServiceProperties;
use log::info;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;
use std::{str::FromStr, sync::Arc};
use tokio::time::sleep;
use url::Url;

#[derive(Clone)]
pub struct AzureHelper {
    pub subscription_id: String,
    credential: Arc<dyn TokenCredential>,
}

impl AzureHelper {
    pub async fn new(subscription_id: String) -> anyhow::Result<Self> {
        let credential: Arc<dyn TokenCredential> = azure_identity::create_credential()
            .context("Error creating TokenCredential azure_identity")?;

        Ok(Self {
            subscription_id,
            credential,
        })
    }
    pub fn get_azure_mgmt_storage_client(&self) -> anyhow::Result<azure_mgmt_storage::Client> {
        Ok(azure_mgmt_storage::Client::builder(self.credential.clone()).build()?)
    }
    pub fn get_azure_svc_blobstorage_client(
        &self,
        endpoint: azure_core::Url,
    ) -> anyhow::Result<azure_svc_blobstorage::Client> {
        Ok(
            azure_svc_blobstorage::Client::builder(self.credential.clone())
                .endpoint(endpoint)
                .build()?,
        )
    }

    pub async fn do_request(
        &self,
        request_builder: reqwest::RequestBuilder,
        token: AccessToken,
    ) -> anyhow::Result<reqwest::Response> {
        Ok(request_builder
            .header("Authorization", format!("Bearer {}", token.token.secret()))
            .send()
            .await?)
    }

    pub async fn create_resource_group(
        &self,
        resource_client: &azure_mgmt_resources::Client,
        resource_group_name: String,
        location: String,
    ) -> anyhow::Result<()> {
        let resource_group = ResourceGroup {
            id: None,
            name: Some(resource_group_name.clone()),
            type_: None,
            properties: None,
            location: location.clone(),
            managed_by: None,
            tags: None,
        };
        let resource_groups_client = resource_client.resource_groups_client();
        let create_resource_group_request = resource_groups_client.create_or_update(
            resource_group_name.clone(),
            resource_group,
            self.subscription_id.clone(),
        );
        create_resource_group_request
            .send()
            .await?
            .into_body()
            .await?;
        Ok(())
    }

    pub async fn enable_static_website_blob_storage(
        &self,
        blob_endpoint: Url,
    ) -> anyhow::Result<()> {
        info!("Enabling Static Website on blob storage: {}", blob_endpoint);
        let static_website = StaticWebsite {
            enabled: true,
            index_document: None,
            error_document404_path: None,
            default_index_document_path: None,
        };
        let storage_service_properties = StorageServiceProperties {
            logging: None,
            hour_metrics: None,
            minute_metrics: None,
            cors: None,
            default_service_version: None,
            delete_retention_policy: None,
            static_website: Some(static_website),
        };

        // Does not work (see: https://github.com/Azure/azure-sdk-for-rust/issues/2630)
        // let azure_svc_blobstorage_client = self.get_azure_svc_blobstorage_client(blob_endpoint)?;
        // let service_client = azure_svc_blobstorage_client.service_client();
        // service_client.set_properties(storage_service_properties).send().await?;

        let req_body = azure_core::xml::to_xml(&storage_service_properties)?;
        let request_builder = reqwest::Client::new()
            .put(blob_endpoint.clone())
            .header("x-ms-version", "2021-12-02")
            .header("content-type", "application/xml")
            .query(&[("restype", "service"), ("comp", "properties")])
            .body(req_body);

        let storage_token = self
            .credential
            .get_token(&["https://storage.azure.com/.default"])
            .await
            .context("Error getting storage_token in enable_static_website_blob_storage")?;

        self.do_request(request_builder, storage_token.clone())
            .await?
            .text()
            .await?;

        info!(
            "Successfully enabled Static Website on blob storage: {}",
            blob_endpoint
        );

        Ok(())
    }
    pub async fn create_storage_account(
        &self,
        storage_client: &azure_mgmt_storage::Client,
        resource_group_name: String,
        location: String,
        storage_account_name: String,
    ) -> anyhow::Result<StorageAccount> {
        info!("Creating Storage Account {}", storage_account_name);
        let storage_account_client = storage_client.storage_accounts_client();

        let storage_account_sku = Sku {
            name: SkuName::StandardRagrs,
            tier: Some(Tier::Standard),
        };
        let encryption_services = EncryptionServices {
            blob: Some(EncryptionService {
                enabled: Some(true),
                last_enabled_time: None,
                key_type: Some(KeyType::Account),
            }),
            file: Some(EncryptionService {
                enabled: Some(true),
                last_enabled_time: None,
                key_type: Some(KeyType::Account),
            }),
            table: None,
            queue: None,
        };
        let encryption = Encryption {
            services: Some(encryption_services),
            key_source: Some(KeySource::MicrosoftStorage),
            require_infrastructure_encryption: Some(false),
            keyvaultproperties: None,
            identity: None,
        };
        let network_rule_set = NetworkRuleSet {
            bypass: Some(Bypass::AzureServices),
            resource_access_rules: Vec::new(),
            virtual_network_rules: Vec::new(),
            ip_rules: Vec::new(),
            default_action: DefaultAction::Allow,
        };
        let storage_account_properties = StorageAccountPropertiesCreateParameters {
            allowed_copy_scope: None,
            public_network_access: Some(PublicNetworkAccess::Enabled),
            sas_policy: None,
            key_policy: None,
            custom_domain: None,
            encryption: Some(encryption),
            network_acls: Some(network_rule_set),
            access_tier: Some(AccessTier::Hot),
            azure_files_identity_based_authentication: None,
            supports_https_traffic_only: Some(true),
            is_sftp_enabled: None,
            is_local_user_enabled: None,
            enable_extended_groups: None,
            is_hns_enabled: None,
            large_file_shares_state: None,
            routing_preference: None,
            allow_blob_public_access: Some(true),
            minimum_tls_version: Some(MinimumTlsVersion::Tls12),
            allow_shared_key_access: Some(true),
            is_nfs_v3_enabled: None,
            allow_cross_tenant_replication: Some(false),
            default_to_o_auth_authentication: None,
            immutable_storage_with_versioning: None,
            dns_endpoint_type: Some(DnsEndpointType::Standard),
        };
        let parameters = StorageAccountCreateParameters {
            sku: storage_account_sku,
            kind: Kind::StorageV2,
            location: location,
            extended_location: None,
            tags: None,
            identity: None,
            properties: Some(storage_account_properties),
        };
        let create_storage_account_request = storage_account_client.create(
            resource_group_name,
            storage_account_name.clone(),
            parameters,
            self.subscription_id.clone(),
        );

        let storage_account_response = create_storage_account_request.send().await?;

        let (status, headers, body) = storage_account_response.into_raw_response().deconstruct();

        let management_token = self
            .credential
            .get_token(&["https://management.azure.com/.default"])
            .await
            .context("Error getting management_token in create_storage_account")?;

        // https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations#create-storage-account-202-with-location-and-retry-after
        let storage_account: StorageAccount = match status {
            azure_core::StatusCode::Accepted => {
                let url = Url::from_str(
                    headers
                        .get_str(&azure_core::headers::LOCATION)
                        .context("Could not get the URL to follow async operation status.")?,
                )?;

                let mut retry_after = headers
                    .get_str(&azure_core::headers::RETRY_AFTER)
                    .or_else(|_| Err(anyhow!("Missing retry-after header key")))?
                    .parse::<u64>()?;

                loop {
                    sleep(Duration::from_secs(retry_after)).await;

                    let response = self
                        .do_request(
                            reqwest::Client::new().get(url.clone()),
                            management_token.clone(),
                        )
                        .await?;

                    match response.status() {
                        StatusCode::ACCEPTED => {
                            retry_after = response
                                .headers()
                                .get("retry-after")
                                .ok_or_else(|| anyhow!("Missing retry-after header key"))?
                                .to_str()?
                                .parse::<u64>()?;
                        }
                        StatusCode::OK => {
                            let response_body = response.text().await?;
                            break serde_json::from_str(&response_body)?;
                        }
                        _ => bail!("Unexpected response status code in create_storage_account"),
                    }
                }
            }
            azure_core::StatusCode::Created | azure_core::StatusCode::Ok => {
                serde_json::from_str(&body.collect_string().await?)?
            }
            _ => {
                bail!("Unexpected status code: {:?}", status)
            }
        };

        info!(
            "Successfully created Storage Account {}",
            storage_account_name
        );

        Ok(storage_account)
    }

    pub async fn get_container_client(
        &self,
        storage_client: Client,
        resource_group_name: String,
        storage_account_name: String,
        container_name: String,
    ) -> anyhow::Result<ContainerClient> {
        let storage_account_credentials = self
            .get_storage_account_credentials(
                &storage_client,
                resource_group_name.clone(),
                storage_account_name.clone(),
            )
            .await?;

        ensure!(
            !storage_account_credentials.is_empty(),
            "No credentials for the storage account"
        );

        let key = storage_account_credentials[0].clone();
        let key_value = key
            .value
            .ok_or(anyhow!("Error getting the storage account key value"))?;
        let storage_credentials =
            StorageCredentials::access_key(storage_account_name.clone(), key_value);
        let blob_service_client_builder =
            ClientBuilder::new(storage_account_name, storage_credentials);

        let container_client = blob_service_client_builder.container_client(container_name);

        Ok(container_client)
    }

    pub async fn get_storage_account_credentials(
        &self,
        storage_client: &azure_mgmt_storage::Client,
        resource_group_name: String,
        storage_account_name: String,
    ) -> anyhow::Result<Vec<StorageAccountKey>> {
        info!(
            "Getting storage account credentials for Storage Account: {}",
            storage_account_name
        );
        let storage_account_client = storage_client.storage_accounts_client();
        // For some reason the API returns `permissions`: "FULL"
        // So I have to do manual parsing
        let mut keys: Value = serde_json::from_value(
            storage_account_client
                .list_keys(
                    resource_group_name,
                    storage_account_name.clone(),
                    self.subscription_id.clone(),
                )
                .send()
                .await?
                .into_raw_response()
                .json::<Value>()
                .await?,
        )?;
        keys.as_object_mut()
            .and_then(|keys| {
                keys.get_mut("keys").and_then(|keys_array| {
                    keys_array.as_array_mut().and_then(|keys_array| {
                        for key in keys_array.iter_mut() {
                            key["permissions"] = Value::String(
                                key["permissions"]
                                    .as_str()
                                    .and_then(|s| {
                                        let s = s.to_ascii_lowercase();
                                        let mut c = s.chars();
                                        match c.next() {
                                            None => Some(String::new()),
                                            Some(f) => Some(
                                                f.to_uppercase().collect::<String>() + c.as_str(),
                                            ),
                                        }
                                    })
                                    .unwrap_or("".to_string()),
                            );
                        }
                        Some(keys_array)
                    });
                    Some(keys_array)
                });
                Some(keys)
            })
            .ok_or(anyhow!("Error capitalizing the permissions value"))?;

        let keys: StorageAccountListKeysResult = serde_json::from_value(keys)
            .context("Error converting to StorageAccountListKeysResult")?;
        info!(
            "Successfully retried storage account credentials for Storage Account: {}",
            storage_account_name
        );

        Ok(keys.keys)
    }
}
