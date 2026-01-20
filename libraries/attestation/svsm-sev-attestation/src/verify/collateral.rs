use std::collections::HashMap;

use anyhow::{bail, Context};
use fn_error_context::context;
use sev::{certs::snp::Certificate, firmware::host::TcbVersion};

use asn1_rs::{oid, Oid};
use x509_parser::prelude::X509Extension;

enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
}

impl SnpOid {
    fn oid(&self) -> Oid<'_> {
        match self {
            SnpOid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
            SnpOid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
            SnpOid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
            SnpOid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
            SnpOid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
        }
    }
}
impl std::fmt::Display for SnpOid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.oid().to_id_string())
    }
}

fn check_cert_ext_byte(ext: &X509Extension, val: u8) -> anyhow::Result<()> {
    if ext.value[0] != 0x2 {
        bail!("Invalid type encountered.");
    }

    if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
        bail!("Invalid octet length encountered.");
    }

    let byte_value = ext
        .value
        .last()
        .ok_or_else(|| anyhow::format_err!("x509extension is None"))?;

    if *byte_value == val {
        Ok(())
    } else {
        bail!("*byte_value != val: {} != {}", byte_value, val)
    }
}

fn check_cert_ext_bytes(ext: &X509Extension, val: &[u8]) -> bool {
    ext.value == val
}

#[context("Invalid Attestation report metadata.")]
pub fn validate_cert_metadata(
    cert: &Certificate,
    chip_id: [u8; 64],
    reported_tcb: TcbVersion,
) -> anyhow::Result<()> {
    let vek_der = &cert.to_der()?;
    let (_, cert) = x509_parser::parse_x509_certificate(vek_der)?;

    let extensions: HashMap<Oid, &X509Extension> = cert.extensions_map()?;

    if let Some(cert_bootloader) = extensions.get(&SnpOid::BootLoader.oid()) {
        check_cert_ext_byte(cert_bootloader, reported_tcb.bootloader)
            .context("Report TCB Bootloader from certificate does not match.")?;
        log::info!("Report TCB boot loader from certificate match attestation report.");
    }

    if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
        check_cert_ext_byte(cert_tee, reported_tcb.tee)
            .context("Report TCB TEE from certificate does not match.")?;

        log::info!("Report TCB TEE from certificate match attestation report.");
    }

    if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
        check_cert_ext_byte(cert_snp, reported_tcb.snp)
            .context("Report TCB SNP from certificate does not match.")?;
        log::info!("Report TCB SNP from certificate match attestation report.");
    }

    if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
        check_cert_ext_byte(cert_ucode, reported_tcb.microcode)
            .context("Report TCB Microcode from certificate does not match.")?;

        log::info!("Report TCB Microcode from certificate match attestation report.");
    }

    if let Some(cert_hw_id) = extensions.get(&SnpOid::HwId.oid()) {
        if !check_cert_ext_bytes(cert_hw_id, chip_id.as_ref()) {
            bail!("Report TCB hardware ID from certificate does not match.");
        }
        log::info!("Report TCB hardware ID from certificate match attestation report.");
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use sev::{
        certs::snp::{self, ca, Verifiable},
        firmware::{guest::AttestationReport, host::TcbVersion},
        Generation,
    };

    use crate::{request_vcek_cert, verify::validate_cert_metadata};

    #[tokio::test]
    async fn test_validate_cert_metadata() -> anyhow::Result<()> {
        use sev::certs::snp::{Chain, Verifiable};

        use crate::common::request_vcek_cert;
        use crate::parse_and_verify_snp_chain;
        use std::fs;
        use std::result::Result::Ok;
        let ask_ark_genoa = fs::read("test_data/cert_chain/ask_ark_genoa.cert")?;
        let attestation_report = fs::read("test_data/attestation_report_genoa.bin")?;

        let report = AttestationReport::from_bytes(&attestation_report)?;
        let host_generation = Generation::Genoa;

        let vek = request_vcek_cert(host_generation, *report.chip_id, report.reported_tcb).await?;

        let ca_chain = parse_and_verify_snp_chain(&ask_ark_genoa)?;
        let chain = Chain {
            ca: ca_chain,
            vek: vek,
        };

        let vek = chain.verify()?;

        validate_cert_metadata(vek, *report.chip_id, report.reported_tcb)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_and_verify_sev_cert_chain_and_metadata() -> anyhow::Result<()> {
        let host_generation = Generation::Genoa;
        let chip_id = [
            144, 13, 141, 168, 115, 185, 104, 141, 47, 237, 188, 121, 179, 181, 115, 185, 126, 10,
            176, 140, 61, 181, 199, 66, 92, 199, 198, 157, 197, 234, 9, 29, 196, 135, 165, 5, 185,
            173, 124, 56, 179, 133, 202, 59, 55, 155, 177, 17, 50, 84, 185, 181, 182, 1, 127, 84,
            70, 98, 6, 124, 48, 64, 253, 51,
        ];

        let reported_tcb = TcbVersion::new(None, 7, 0, 23, 72);

        let ca_chain = ca::Chain::from(host_generation);
        let _ = ca_chain.verify()?;

        let vcek_leaf_cert = request_vcek_cert(host_generation, chip_id, reported_tcb).await?;

        validate_cert_metadata(&vcek_leaf_cert, chip_id, reported_tcb)?;

        let chain = snp::Chain {
            ca: ca_chain,
            vek: vcek_leaf_cert,
        };

        let _ = chain.verify()?;

        Ok(())
    }
}
