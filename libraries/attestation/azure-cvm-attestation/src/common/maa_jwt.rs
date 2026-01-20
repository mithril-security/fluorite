use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MaaClaims {
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub jti: String,
    pub nbf: i64,
    pub secureboot: bool,
    pub x_ms_attestation_type: String,
    pub x_ms_azurevm_attestation_protocol_ver: String,
    pub x_ms_azurevm_attested_pcrs: Vec<i64>,
    pub x_ms_azurevm_bootdebug_enabled: bool,
    pub x_ms_azurevm_dbvalidated: bool,
    pub x_ms_azurevm_dbxvalidated: bool,
    pub x_ms_azurevm_debuggersdisabled: bool,
    pub x_ms_azurevm_default_securebootkeysvalidated: bool,
    pub x_ms_azurevm_elam_enabled: bool,
    pub x_ms_azurevm_flightsigning_enabled: bool,
    pub x_ms_azurevm_hvci_policy: i64,
    pub x_ms_azurevm_hypervisordebug_enabled: bool,
    pub x_ms_azurevm_is_windows: bool,
    pub x_ms_azurevm_kerneldebug_enabled: bool,
    pub x_ms_azurevm_osbuild: String,
    pub x_ms_azurevm_osdistro: String,
    pub x_ms_azurevm_ostype: String,
    pub x_ms_azurevm_osversion_major: i64,
    pub x_ms_azurevm_osversion_minor: i64,
    pub x_ms_azurevm_signingdisabled: bool,
    pub x_ms_azurevm_testsigning_enabled: bool,
    pub x_ms_azurevm_vmid: String,
    pub x_ms_isolation_tee: XMsIsolationTee,
    pub x_ms_policy_hash: String,
    pub x_ms_runtime: XMsRuntime2,
    pub x_ms_ver: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct XMsIsolationTee {
    pub x_ms_attestation_type: String,
    #[serde(rename = "x-ms-compliance-status")]
    pub x_ms_compliance_status: String,
    pub x_ms_runtime: XMsRuntime,
    pub x_ms_sevsnpvm_authorkeydigest: String,
    pub x_ms_sevsnpvm_bootloader_svn: i64,
    #[serde(rename = "x-ms-sevsnpvm-familyId")]
    pub x_ms_sevsnpvm_family_id: String,
    pub x_ms_sevsnpvm_guestsvn: i64,
    pub x_ms_sevsnpvm_hostdata: String,
    pub x_ms_sevsnpvm_idkeydigest: String,
    #[serde(rename = "x-ms-sevsnpvm-imageId")]
    pub x_ms_sevsnpvm_image_id: String,
    pub x_ms_sevsnpvm_is_debuggable: bool,
    pub x_ms_sevsnpvm_launchmeasurement: String,
    pub x_ms_sevsnpvm_microcode_svn: i64,
    pub x_ms_sevsnpvm_migration_allowed: bool,
    pub x_ms_sevsnpvm_reportdata: String,
    pub x_ms_sevsnpvm_reportid: String,
    pub x_ms_sevsnpvm_smt_allowed: bool,
    pub x_ms_sevsnpvm_snpfw_svn: i64,
    pub x_ms_sevsnpvm_tee_svn: i64,
    pub x_ms_sevsnpvm_vmpl: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct XMsRuntime {
    pub keys: Vec<Key>,
    pub user_data: String,
    pub vm_configuration: VmConfiguration,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Key {
    pub e: String,
    pub key_ops: Vec<String>,
    pub kid: String,
    pub kty: String,
    pub n: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmConfiguration {
    pub console_enabled: bool,
    pub secure_boot: bool,
    pub tpm_enabled: bool,
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct XMsRuntime2 {
    pub client_payload: ClientPayload,
    pub keys: Vec<Key2>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientPayload {
    pub nonce: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Key2 {
    pub e: String,
    #[serde(rename = "key_ops")]
    pub key_ops: Vec<String>,
    pub kid: String,
    pub kty: String,
    pub n: String,
}
