use serde::{Deserialize, Serialize};
mod json_base64;
pub mod json_base64url;
pub mod maa_jwt;
use tpm_quote::common::Quote;

use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};

pub const VTPM_AK_HANDLE: u32 = 0x81000003;

#[serde_as]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Proof {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub snp_report: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub vcek_cert_chain: String,
}

#[serde_as]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OsInfo {
    #[serde(rename = "OSBuild")]
    #[serde_as(as = "Base64")]
    pub os_build: String,
    #[serde(rename = "OSDistro")]
    #[serde_as(as = "Base64")]
    pub os_distro: String,
    #[serde(rename = "OSType")]
    #[serde_as(as = "Base64")]
    pub os_type: String,
    #[serde(rename = "OSVersionMajor")]
    pub os_version_major: i64,
    #[serde(rename = "OSVersionMinor")]
    pub os_version_minor: i64,
}

#[serde_as]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttestationInfo {
    pub attestation_protocol_version: String,
    pub client_payload: ClientPayload,
    pub isolation_info: IsolationInfo,
    #[serde(flatten)]
    pub os_info: OsInfo,
    #[serde_as(as = "Base64")]
    pub tcg_logs: Vec<u8>,
    pub tpm_info: TpmInfo,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientPayload {
    pub nonce: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IsolationInfo {
    pub evidence: Evidence,
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[serde_as]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Evidence {
    #[serde(with = "json_base64")]
    pub proof: Proof,
    #[serde_as(as = "Base64")]
    pub run_time_data: Vec<u8>,
}

#[serde_as]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TpmInfo {
    #[serde_as(as = "Base64")]
    pub aik_cert: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub aik_pub: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub enc_key_certify_info: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub enc_key_certify_info_signature: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub enc_key_pub: Vec<u8>,
    #[serde(rename = "PCRs")]
    pub pcrs: Vec<Pcr>,
    #[serde_as(as = "Base64")]
    pub pcr_quote: Vec<u8>,
    pub pcr_set: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub pcr_signature: Vec<u8>,
}

#[serde_as]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Pcr {
    #[serde_as(as = "Base64")]
    pub digest: Vec<u8>,
    pub index: u8,
}

#[derive(Serialize, Deserialize)]
pub struct MaaResponse {
    #[serde(with = "json_base64url")]
    pub token: EncryptedJwt,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedJwt {
    #[serde_as(as = "Base64")]
    pub jwt: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub encrypted_inner_key: Vec<u8>,
    pub encryption_params: EncryptionParams,
    #[serde_as(as = "Base64")]
    pub authentication_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockMode {
    #[serde(rename = "ChainingModeCBC")]
    ChainingModeCbc,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockCipherPadding {
    PKCS7,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    AES,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptionParams {
    pub block_mode: BlockMode,
    pub block_padding: BlockCipherPadding,
    pub cipher: CipherAlgorithm,
    pub key_size_in_bits: u64,
    #[serde_as(as = "Base64")]
    pub iv: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseStruct {
    pub jwt: String,
    pub quote: Quote,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfidentialVmAttestationDocument {
    pub response_struct: ResponseStruct,
}
