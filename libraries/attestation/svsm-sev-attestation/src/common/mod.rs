use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::{serde_as, IfIsHumanReadable};
use sev::Generation;
use tpm_quote::common::Quote;
use ring::rand::{SecureRandom, SystemRandom};

use sev::{
    certs::snp,
    certs::snp::{ca, Certificate, Verifiable},
    firmware::{guest::AttestationReport, host::TcbVersion},
};
use x509_parser::{certificate::X509Certificate, pem::Pem, prelude::FromDer};

pub const VTPM_AK_HANDLE: u32 = 0x81000002;

/// Retrieves the Attestation report certification chain.
///  
/// Returns DER-encoded certificates, ordered from leaf to root.
/// This function should be called for an SVSM environment implementing vTPM.
///
///  
/// # Errors
///
/// This function will return an error if:
///
///
///
///
// pub fn request_verified_sev_cert_chain(
//     host_generation: Generation,
//     chip_id: [u8; 64],
//     reported_tcb: TcbVersion,
// ) -> anyhow::Result<MyChain> {

//     Ok(chain.try_into()?)
// }

// amd_sev::certs::snp::chain::Chain does not implement Serialize, Deserialize, so I created my own wrapper.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyChain {
    #[serde_as(as = "IfIsHumanReadable<Base64>")]
    pub ark_der: Vec<u8>,
    #[serde_as(as = "IfIsHumanReadable<Base64>")]
    pub ask_der: Vec<u8>,
    #[serde_as(as = "IfIsHumanReadable<Base64>")]
    pub vek_der: Vec<u8>,
}

impl TryFrom<snp::Chain> for MyChain {
    type Error = anyhow::Error;

    fn try_from(value: snp::Chain) -> Result<Self, Self::Error> {
        Ok(Self {
            ark_der: value.ca.ark.to_der()?,
            ask_der: value.ca.ask.to_der()?,
            vek_der: value.vek.to_der()?,
        })
    }
}

impl TryInto<snp::Chain> for MyChain {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<snp::Chain, Self::Error> {
        Ok(snp::Chain::from_der(
            &self.ark_der,
            &self.ask_der,
            &self.vek_der,
        )?)
    }
}
/// Attestation Document for SVSM vTPM AMD-SEV SNP VM
///
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SvsmVtpmAttestationDocument {
    pub quote: Quote,
    pub attestation_report: AttestationReport,
    pub sev_cert_chain: MyChain,
    #[serde_as(as = "IfIsHumanReadable<Base64>")]
    pub ak_pub_key: Vec<u8>,
    #[serde_as(as = "IfIsHumanReadable<Base64>")]
    pub nonce: Vec<u8>
}

pub fn parse_and_verify_snp_chain(chain_bytes: &[u8]) -> anyhow::Result<ca::Chain> {
    if chain_bytes.is_empty() {
        bail!("Certificate chain is empty")
    }

    // Transform the bytes into an iterator over the PEM objects
    let mut pem_chain = Pem::iter_from_buffer(chain_bytes);

    // Get the ASK, and try to parse it
    let ask_pem = pem_chain
        .next()
        .ok_or_else(|| anyhow::format_err!("Error getting next element of pem buffer"))?
        .map_err(|e| anyhow::format_err!("Failed to parse ARK PEM: {:?}", e))?;

    let (_, ask_cert) = X509Certificate::from_der(&ask_pem.contents)
        .map_err(|e| anyhow::format_err!("Failed to parse ASK certificate: {:?}", e))?;

    // Get the ARK, and try to parse it
    let ark_pem = pem_chain
        .next()
        .ok_or_else(|| anyhow::format_err!("Error getting next element of pem buffer"))?
        .map_err(|e| anyhow::format_err!("Failed to parse ARK PEM: {:?}", e))?;

    let (_, ark_cert) = X509Certificate::from_der(&ark_pem.contents)
        .map_err(|e| anyhow::format_err!("Failed to parse ARK certificate: {:?}", e))?;

    // The certificate chain should only contain an ASK certificate and an ARK certificate
    ensure!(
        pem_chain.next().is_none(),
        "Pem chain is not empty after getting the ask and ark certificate"
    );

    // Verify the SNP CA Chain
    let ca_chain = ca::Chain::from_der(ark_cert.as_raw(), ask_cert.as_raw())
        .context("Error ca::Chain::from_pem(ark_cert.as_raw(), ask_cert.as_raw())")?;

    let _ = ca_chain
        .verify()
        .context("ca_chain could not be verified")?;

    Ok(ca_chain)
}

pub async fn request_vcek_cert(
    host_generation: Generation,
    chip_id: [u8; 64],
    reported_tcb: TcbVersion,
) -> anyhow::Result<Certificate> {
    let hw_id = hex::encode(chip_id);

    let url = format!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            host_generation.titlecase(),
            hw_id,
            reported_tcb.bootloader, reported_tcb.tee, reported_tcb.snp, reported_tcb.microcode);

    let vek_bytes = loop {
        let response = reqwest::get(&url).await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read response body".to_string());

            println!(
                "Request to {} was not successful. Status {}.\nReason: {}",
                url, status, error_text
            );
            println!("Sleeping two seconds.");
            sleep(Duration::from_secs(2));
        } else {
            break response.bytes().await?.to_vec();
        }
    };

    let cert =
        Certificate::from_der(&vek_bytes).context("Error converting vcek bytes to Certificate")?;
    Ok(cert)
}

pub fn generate_nonce() -> anyhow::Result<[u8; 64 as usize]> {
    // Generates cryptographically strong nonce to be sent to the SPDM requester via the nvml api for the attestation report.
    let mut random_bytes = [0u8; 64 as usize];
    let sys_random = SystemRandom::new();
    sys_random
        .fill(&mut random_bytes)
        .map_err(|e| anyhow::format_err!("Error filling buffer with random bytes: {:?}", e))?;

    Ok(random_bytes)
}