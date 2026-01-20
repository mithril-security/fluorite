use log::info;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use vtpm::get_quote;
mod eph_key_tpm;
mod imds_operations;
use attestation::AsyncGenerateAttestationDocument;

pub(crate) mod tpm;
pub(crate) mod vtpm;
use std::{fs, str::FromStr};

use crate::common::ConfidentialVmAttestationDocument;
use crate::common::OsInfo;
use crate::generate::eph_key_tpm::decrypt_jwt;
use crate::generate::vtpm::HclReport;
use crate::vtpm::ALL_8_SLOTS;
use anyhow::bail;
use anyhow::Context as AnyhowContext;
use eph_key_tpm::{create_ephemeral_key, decrypt_inner_key};
use fn_error_context::context;
use imds_operations::get_vcek_certchain;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tss_esapi::{
    handles::KeyHandle,
    structures::{Attest, AttestInfo, Digest, PcrSelectionList, PcrSlot, PublicBuffer, Signature},
    tcti_ldr::DeviceConfig,
    traits::{Marshall, UnMarshall},
    Context, TctiNameConf,
};

use crate::common::{
    json_base64url, AttestationInfo, ClientPayload, Evidence, IsolationInfo, MaaResponse, Pcr,
    Proof, ResponseStruct, TpmInfo, VTPM_AK_HANDLE,
};
use async_trait::async_trait;
use tpm_quote::generate::AttestationKeyHandle;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Root {
    #[serde(with = "json_base64url")]
    pub attestation_info: AttestationInfo,
}

#[cfg(test)]
mod test {
    use crate::common::MaaResponse;
    use crate::generate::eph_key_tpm::decrypt_jwt;
    use crate::Root;
    use anyhow::{ensure, Context};
    use std::fs;

    #[test]
    fn test_deserialize_serialize_attestation_info() -> anyhow::Result<()> {
        let root: Root = serde_json::from_slice(
            &fs::read("./test_data/attestation_info.json").context("Error reading file")?,
        )
        .context("Error parsing file to Root Attestation Info")?;

        let roundtrip_str = serde_json::to_string(&root).context("Error converting to string")?;
        let _: Root = serde_json::from_str(&roundtrip_str).context("Error roundtrip")?;

        Ok(())
    }

    #[test]
    fn test_deserialize_maa_response() -> anyhow::Result<()> {
        let _: MaaResponse = serde_json::from_slice(
            &fs::read("./test_data/attestation_claim.json").context("Error reading file")?,
        )
        .context("Error parsing file to MaaResponse")?;

        Ok(())
    }

    #[test]
    fn test_deserialize_maa_response_and_decrypt() -> anyhow::Result<()> {
        let maa_response: MaaResponse = serde_json::from_slice(
            &fs::read("./test_data/attestation_claim.json").context("Error reading file")?,
        )
        .context("Error parsing file to MaaResponse")?;

        let decrypted_inner_key =
            hex::decode("98f43b8c1a066a458745d198ddff0d78ac9f86b629baa4b09c0f5452d73f7348")?;

        decrypt_jwt(decrypted_inner_key, maa_response.token)?;
        Ok(())
    }

    #[test]
    fn test_deserialize_maa_response_and_decrypt_with_wrong_key() -> anyhow::Result<()> {
        let maa_response: MaaResponse = serde_json::from_slice(
            &fs::read("./test_data/attestation_claim.json").context("Error reading file")?,
        )
        .context("Error parsing file to MaaResponse")?;

        let decrypted_inner_key =
            hex::decode("1111111111111111111111111111111111111111111111111111111111111111")?;

        let decryption_result = decrypt_jwt(decrypted_inner_key, maa_response.token);

        ensure!(
            decryption_result.is_err(),
            "Decryption should have failed because the key provided is wrong"
        );
        Ok(())
    }
}

fn pcr_slot_to_index(pcr_slot: &PcrSlot) -> u8 {
    match pcr_slot {
        PcrSlot::Slot0 => 0,
        PcrSlot::Slot1 => 1,
        PcrSlot::Slot2 => 2,
        PcrSlot::Slot3 => 3,
        PcrSlot::Slot4 => 4,
        PcrSlot::Slot5 => 5,
        PcrSlot::Slot6 => 6,
        PcrSlot::Slot7 => 7,
        PcrSlot::Slot8 => 8,
        PcrSlot::Slot9 => 9,
        PcrSlot::Slot10 => 10,
        PcrSlot::Slot11 => 11,
        PcrSlot::Slot12 => 12,
        PcrSlot::Slot13 => 13,
        PcrSlot::Slot14 => 14,
        PcrSlot::Slot15 => 15,
        PcrSlot::Slot16 => 16,
        PcrSlot::Slot17 => 17,
        PcrSlot::Slot18 => 18,
        PcrSlot::Slot19 => 19,
        PcrSlot::Slot20 => 20,
        PcrSlot::Slot21 => 21,
        PcrSlot::Slot22 => 22,
        PcrSlot::Slot23 => 23,
        PcrSlot::Slot24 => 24,
        PcrSlot::Slot25 => 25,
        PcrSlot::Slot26 => 26,
        PcrSlot::Slot27 => 27,
        PcrSlot::Slot28 => 28,
        PcrSlot::Slot29 => 29,
        PcrSlot::Slot30 => 30,
        PcrSlot::Slot31 => 31,
    }
}

#[context("Failed to get TpmInfo")]
fn get_tpm_info(
    ctx: &mut tss_esapi::Context,
    pcr_selection_list: PcrSelectionList,
) -> anyhow::Result<(TpmInfo, KeyHandle, Digest, PcrSelectionList)> {
    let ak_cert = tpm::get_ak_cert()?;
    let ak_pub = tpm::get_ak_pub()?;

    let quote = get_quote(&[], pcr_selection_list)?;

    let msg = quote.message();
    let sig = quote.signature();

    let rquote = Attest::unmarshall(&msg)?;

    let &AttestInfo::Quote {
        info: ref quote_info,
    } = rquote.attested()
    else {
        bail!("Failed to extract quote from attested");
    };

    let pcr_data = quote.pcr_data();
    let pcr_sha256 = pcr_data
        .pcr_bank(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
        .context("Bad selection, no SHA256 bank in PCRData")?;

    let pcrs: Vec<Pcr> = pcr_sha256
        .into_iter()
        .map(|(pcr_slot, digest)| Pcr {
            digest: digest.to_vec(),
            index: pcr_slot_to_index(&pcr_slot),
        })
        .collect();

    let pcr_set: Vec<u8> = pcr_sha256
        .into_iter()
        .map(|(pcr_slot, _digest)| pcr_slot_to_index(&pcr_slot))
        .collect();

    let (primarykey_res, certify_info, certify_sig) =
        create_ephemeral_key(ctx, quote_info.pcr_digest(), quote_info.pcr_selection())?;

    let Signature::RsaSsa(ref certify_rsa_sig) = certify_sig else {
        Err(vtpm::QuoteError::WrongSignature)?
    };
    let certify_sig = certify_rsa_sig.signature().to_vec();

    let tpm_info = TpmInfo {
        aik_cert: ak_cert,
        aik_pub: ak_pub,
        enc_key_certify_info: certify_info.marshall()?,
        enc_key_certify_info_signature: certify_sig,
        enc_key_pub: PublicBuffer::try_from(primarykey_res.out_public)?.marshall()?,
        pcrs: pcrs,
        pcr_quote: msg,
        pcr_set: pcr_set,
        pcr_signature: sig,
    };
    Ok((
        tpm_info,
        primarykey_res.key_handle,
        quote_info.pcr_digest().clone(),
        quote_info.pcr_selection().clone(),
    ))
}

async fn get_isolation_info() -> anyhow::Result<IsolationInfo> {
    let hcl_report = HclReport::new(
        vtpm::get_report().context("Error getting tpm report. Are you running as root?")?,
    )?;
    let snp_report = hcl_report.report_slice().to_vec();
    let runtime_data = hcl_report.var_data_slice().to_vec();

    Ok(IsolationInfo {
        evidence: Evidence {
            proof: Proof {
                snp_report,
                vcek_cert_chain: get_vcek_certchain().await?,
            },
            run_time_data: runtime_data,
        },
        type_field: "SevSnp".to_string(),
    })
}

fn get_os_info() -> OsInfo {
    OsInfo {
        // For Linux OS, this field is not application and will be ignored by the
        // attestation service.
        os_build: "NotApplication".to_string(),
        os_distro: "Ubuntu".to_string(),
        os_type: "Linux".to_string(),
        os_version_major: 24,
        os_version_minor: 4,
    }
}

async fn get_maa_token(
    client_payload: ClientPayload,
    pcr_selection_list: PcrSelectionList,
) -> anyhow::Result<ResponseStruct, anyhow::Error> {
    let os_info: OsInfo = get_os_info();

    let isolation_info = get_isolation_info()
        .await
        .context("Error getting isolation info")?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?);
    let mut ctx =
        Context::new(conf).context("Error creating TPM context. Are you running as root?")?;

    let tpm_info_pcr_selection_list = PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, ALL_8_SLOTS)
        .build()?;

    let (tpm_info, key_handle, pcr_digest, pcr_selection) =
        get_tpm_info(&mut ctx, tpm_info_pcr_selection_list).context("Error getting TPM info")?;

    let attest_info = AttestationInfo {
        attestation_protocol_version: "3.0".to_string(),
        client_payload: client_payload,
        isolation_info,
        os_info: os_info,
        tcg_logs: fs::read("/sys/kernel/security/tpm0/binary_bios_measurements")?,
        tpm_info,
    };
    let req_body = Root {
        attestation_info: attest_info,
    };

    let client = Client::new();
    let response = client
        .post("https://testattest.eus.attest.azure.net/attest/AzureGuest?api-version=2020-10-01")
        .json(&req_body)
        .send()
        .await?;

    let maa_response: MaaResponse = response
        .json()
        .await
        .context("Error deserializing MaaResponse")?;

    let inner_key = decrypt_inner_key(
        &mut ctx,
        &maa_response.token.encrypted_inner_key,
        &key_handle,
        &pcr_digest,
        &pcr_selection,
    )?;
    info!("Successfully Decrypted inner key");

    let decrypted_jwt = decrypt_jwt(inner_key, maa_response.token)?;

    let jwt = String::from_utf8(decrypted_jwt)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?);
    let mut ctx = Context::new(conf)?;

    let ak_tpm_handle: TpmHandle = TpmHandle::try_from(VTPM_AK_HANDLE)?;
    let mut ak_handle: AttestationKeyHandle =
        AttestationKeyHandle::from_tpm_handle(&mut ctx, ak_tpm_handle)?;

    let quote = ak_handle.quote(&pcr_selection_list.clone())?;

    Ok(ResponseStruct { jwt: jwt, quote })
}

pub struct AzureCvmAttestationDocumentGenerator();

impl AzureCvmAttestationDocumentGenerator {
    pub fn new() -> Self {
        Self()
    }
}

#[async_trait]
impl AsyncGenerateAttestationDocument for AzureCvmAttestationDocumentGenerator {
    type AttestationDocument = ConfidentialVmAttestationDocument;

    /// Produce an attestation document attesting to the selected PCR list
    ///
    /// This function should only be called on Azure Confidential VM.
    async fn generate_attestation_document(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
    ) -> anyhow::Result<Self::AttestationDocument> {
        let attestation_result = gpu_attestation_server::attest()
            .await
            .context("Error obtaining gpu attestation")?;

        let client_payload = ClientPayload {
            nonce: gpu_attestation_server::serialize_attestation(attestation_result)?,
        };

        let response_struct = get_maa_token(client_payload, pcr_selection_list.clone())
            .await
            .context("Error obtaining maa token")?;

        let doc = ConfidentialVmAttestationDocument { response_struct };

        Ok(doc)
    }
}
