//! GCP Compute API client for Shielded Instance operations

use anyhow::{Context, bail};
use log::{debug, info};
use serde::{Deserialize, Serialize};

/// The GCP API scope needed for Compute Engine operations
const COMPUTE_SCOPE: &str = "https://www.googleapis.com/auth/compute.readonly";

/// Shielded Instance Identity response from GCP API
///
/// This is the response from:
/// GET https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}/getShieldedInstanceIdentity
///
/// Reference: https://cloud.google.com/compute/docs/reference/rest/v1/instances/getShieldedInstanceIdentity
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedInstanceIdentity {
    /// The kind of resource (always "compute#shieldedInstanceIdentity")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// An Attestation Key (AK) made by the RSA 2048 algorithm issued to the Shielded Instance's vTPM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<ShieldedInstanceIdentityEntry>,

    /// An Endorsement Key (EK) made by the RSA 2048 algorithm issued to the Shielded Instance's vTPM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<ShieldedInstanceIdentityEntry>,

    /// An Attestation Key (AK) made by the ECC P256 algorithm issued to the Shielded Instance's vTPM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p256_signing_key: Option<ShieldedInstanceIdentityEntry>,

    /// An Endorsement Key (EK) made by the ECC P256 algorithm issued to the Shielded Instance's vTPM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p256_encryption_key: Option<ShieldedInstanceIdentityEntry>,
}

/// An identity entry containing the key and optional certificate
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedInstanceIdentityEntry {
    /// A PEM-encoded public key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_pub: Option<String>,

    /// A PEM-encoded X.509 certificate (this field can be empty)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_cert: Option<String>,
}

/// Type alias for backwards compatibility
pub type ShieldedVmIdentity = ShieldedInstanceIdentity;

/// Fetch the Shielded Instance identity from GCP Compute API
///
/// This calls the getShieldedInstanceIdentity API to retrieve the AK and EK keys
/// for the specified instance.
///
/// # Arguments
///
/// * `project` - GCP project ID
/// * `zone` - GCP zone (e.g., "us-central1-a")
/// * `instance` - Instance name or ID
///
/// # Returns
///
/// The Shielded Instance identity containing signing keys (AK) and encryption keys (EK)
/// for both RSA 2048 and ECC P256 algorithms.
pub async fn get_shielded_instance_identity(
    project: &str,
    zone: &str,
    instance: &str,
) -> anyhow::Result<ShieldedInstanceIdentity> {
    info!(
        "Fetching Shielded Instance identity for {}/{}/{}",
        project, zone, instance
    );

    // Get authentication using application default credentials
    let provider = gcp_auth::provider()
        .await
        .context("Failed to create GCP auth provider")?;

    let token = provider
        .token(&[COMPUTE_SCOPE])
        .await
        .context("Failed to get GCP access token")?;

    // Build the API URL using v1 API
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/getShieldedInstanceIdentity",
        project, zone, instance
    );

    debug!("Calling GCP API: {}", url);

    // Make the API request
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(token.as_str())
        .header("Content-Type", "application/json")
        .send()
        .await
        .context("Failed to send request to GCP API")?;

    let status = response.status();

    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error body".to_string());

        bail!("GCP API returned error status {}: {}", status, error_body);
    }

    let identity: ShieldedInstanceIdentity = response
        .json()
        .await
        .context("Failed to parse Shielded Instance identity response")?;

    info!("Successfully fetched Shielded Instance identity");
    debug!("Identity: {:?}", identity);

    Ok(identity)
}

/// Backwards compatibility alias
pub async fn get_shielded_vm_identity(
    project: &str,
    zone: &str,
    instance: &str,
) -> anyhow::Result<ShieldedInstanceIdentity> {
    get_shielded_instance_identity(project, zone, instance).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_shielded_instance_identity() {
        let json = r#"{
            "kind": "compute#shieldedInstanceIdentity",
            "signingKey": {
                "ekPub": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----\n"
            },
            "encryptionKey": {
                "ekPub": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----\n",
                "ekCert": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
            },
            "eccP256SigningKey": {
                "ekPub": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n"
            },
            "eccP256EncryptionKey": {
                "ekPub": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n"
            }
        }"#;

        let identity: ShieldedInstanceIdentity =
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(
            identity.kind,
            Some("compute#shieldedInstanceIdentity".to_string())
        );
        assert!(identity.signing_key.is_some());
        assert!(identity.encryption_key.is_some());
        assert!(identity.ecc_p256_signing_key.is_some());
        assert!(identity.ecc_p256_encryption_key.is_some());
    }
}
