use nvml_wrapper::{
    enums::device::DeviceArchitecture,
    structs::device::{ConfidentialComputeGpuAttestationReport, ConfidentialComputeGpuCertificate},
    Device, Nvml,
};
use nvml_wrapper_sys::bindings::NVML_CC_GPU_CEC_NONCE_SIZE;

pub struct MyNvmlHandler {
    nvml: Nvml,
}

impl MyNvmlHandler {
    pub fn new() -> anyhow::Result<Self> {
        let nvml = Nvml::init()?;
        Ok(Self { nvml })
    }
    pub fn get_device(&self, idx: u32) -> anyhow::Result<Device<'_>> {
        self.nvml.device_by_index(idx).map_err(|e| {
            anyhow::format_err!("Error getting device with index {}. Error: {:?}", idx, e)
        })
    }
    pub fn get_device_count(&self) -> anyhow::Result<u32> {
        self.nvml
            .device_count()
            .map_err(|e| anyhow::format_err!("Error getting the number of devices (GPUs): {:?}", e))
    }

    pub fn get_gpu_uuid(&self, idx: u32) -> anyhow::Result<String> {
        self.get_device(idx)?.uuid().map_err(|e| {
            anyhow::format_err!(
                "Error getting the device UUID for GPU with index {}. Error: {:?}",
                idx,
                e
            )
        })
    }

    pub fn get_gpu_architecture(&self, idx: u32) -> anyhow::Result<DeviceArchitecture> {
        self.get_device(idx)?.architecture().map_err(|e| {
            anyhow::format_err!(
                "Error getting the device architecture for GPU with index {}. Error: {:?}",
                idx,
                e
            )
        })
    }

    pub fn get_gpu_vbios_version(&self, idx: u32) -> anyhow::Result<String> {
        self.get_device(idx)?.vbios_version().map_err(|e| {
            anyhow::format_err!(
                "Error getting the device VBIOS version for GPU with index {}. Error: {:?}",
                idx,
                e
            )
        })
    }
    pub fn get_gpu_info_rom_image_version(&self, idx: u32) -> anyhow::Result<String> {
        self.get_device(idx)?
            .info_rom_image_version().map_err(|e| {
                anyhow::format_err!(
                    "Error getting the device Info Rom Image Version for GPU with index {}. Error: {:?}",
                    idx,
                    e
                )
            })
    }

    pub fn get_sys_driver_version(&self) -> anyhow::Result<String> {
        self.nvml.sys_driver_version().map_err(|e| {
            anyhow::format_err!("Error getting the sys driver version. Error: {:?}", e)
        })
    }

    pub fn get_gpu_certificate_chain(
        &self,
        idx: u32,
    ) -> anyhow::Result<ConfidentialComputeGpuCertificate> {
        let mut chain = self
            .get_device(idx)?
            .confidential_compute_gpu_certificate()
            .map_err(|e| {
                anyhow::format_err!(
                    "Error getting the certificate chain for GPU with index {}. Error: {:?}",
                    idx,
                    e
                )
            })?;
        chain
            .attestation_cert_chain
            .truncate(chain.attestation_cert_chain_size as usize);
        chain.cert_chain.truncate(chain.cert_chain_size as usize);

        Ok(chain)
    }

    pub fn get_gpu_attestation_report(
        &self,
        idx: u32,
        nonce: [u8; NVML_CC_GPU_CEC_NONCE_SIZE as usize],
    ) -> anyhow::Result<ConfidentialComputeGpuAttestationReport> {
        let mut report = self
            .get_device(idx)?
            .confidential_compute_gpu_attestation_report(nonce)
            .map_err(|e| {
                anyhow::format_err!(
                    "Error getting the attestation report for GPU with index {}. Error: {:?}",
                    idx,
                    e
                )
            })?;
        report
            .attestation_report
            .truncate(report.attestation_report_size as usize);
        report
            .cec_attestation_report
            .truncate(report.cec_attestation_report_size as usize);

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{ensure, Context};
    use log::debug;
    use nvml_wrapper::structs::device::{
        ConfidentialComputeGpuAttestationReport, ConfidentialComputeGpuCertificate,
    };
    use x509_parser::{pem::parse_x509_pem, prelude::X509Certificate};

    use crate::{
        parse_certificate_chain_pem,
        utils::{generate_nonce, init_logger_tests, verify_gpu_certificate_chain},
        MyNvmlHandler, DEVICE_ROOT_CERT,
    };

    #[test]
    fn get_gpus_attestation_reports() -> anyhow::Result<()> {
        init_logger_tests();

        let nvmlhandler = MyNvmlHandler::new()?;
        let num_gpus = nvmlhandler.get_device_count()?;

        let gpus_attestation_reports: Vec<ConfidentialComputeGpuAttestationReport> = (0..num_gpus)
            .map(|idx| {
                let nonce = generate_nonce()?;

                nvmlhandler.get_gpu_attestation_report(idx, nonce)
            })
            .collect::<Result<Vec<_>, _>>()?;

        debug!("{:?}", gpus_attestation_reports);
        Ok(())
    }

    #[test]
    fn get_gpus_certificate_chains() -> anyhow::Result<()> {
        init_logger_tests();

        let nvmlhandler = MyNvmlHandler::new()?;

        let num_gpus = nvmlhandler.get_device_count()?;

        let gpus_certificate_chains: Vec<ConfidentialComputeGpuCertificate> = (0..num_gpus)
            .map(|idx| nvmlhandler.get_gpu_certificate_chain(idx))
            .collect::<Result<Vec<_>, _>>()?;

        debug!("{:?}", gpus_certificate_chains);

        Ok(())
    }

    #[test]
    fn get_gpus_certificate_chains_and_verify() -> anyhow::Result<()> {
        init_logger_tests();

        let nvmlhandler = MyNvmlHandler::new()?;

        let num_gpus = nvmlhandler.get_device_count()?;

        let gpus_certificate_chains: Vec<ConfidentialComputeGpuCertificate> = (0..num_gpus)
            .map(|idx| nvmlhandler.get_gpu_certificate_chain(idx))
            .collect::<Result<Vec<_>, _>>()?;

        debug!("{:?}", gpus_certificate_chains);

        for gpus_certificate_chain in gpus_certificate_chains {
            let attestation_report_cert_chain_pem =
                parse_certificate_chain_pem(&gpus_certificate_chain.attestation_cert_chain)
                    .context("Error parsing pem chain")?;

            let attestation_report_cert_chain: Vec<X509Certificate<'_>> =
                attestation_report_cert_chain_pem
                    .iter()
                    .map(|pem| pem.parse_x509())
                    .collect::<Result<Vec<_>, _>>()?;

            ensure!(
                attestation_report_cert_chain.len() > 1,
                "The attestation_cert_chain has a contains less than two certificates"
            );

            let (_, root_cert_pem) = parse_x509_pem(DEVICE_ROOT_CERT)?;
            let root_cert = root_cert_pem
                .parse_x509()
                .context("Error parsing x509 root cert")?;

            ensure!(
                root_cert == attestation_report_cert_chain[attestation_report_cert_chain.len() - 1],
                "Root certificate received from GPU does not match expected DEVICE_ROOT_CERT"
            );

            // Do not check the fwid because it will make the test will fail on other machines
            let attestation_report_fwid = "".to_string();
            verify_gpu_certificate_chain(&attestation_report_cert_chain, attestation_report_fwid)
                .context("GPU attestation report certificate chain validation failed.")?;
        }

        Ok(())
    }
}
