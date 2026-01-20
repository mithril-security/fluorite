use anyhow::Context;
use tss_esapi::{
    abstraction::nv,
    handles::TpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    structures::PublicBuffer,
    tcti_ldr::DeviceConfig,
    traits::Marshall,
    Context as tssContext, TctiNameConf,
};

use std::convert::{TryFrom, TryInto};

pub const VTPM_AK_HANDLE: u32 = 0x81000003;
pub const VTPM_AK_CERT_NV_INDEX: u32 = 0x01C101D0;

/// Get the AK pub of the vTPM
pub fn get_ak_pub() -> anyhow::Result<Vec<u8>> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = tssContext::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;
    let public_buffer = PublicBuffer::try_from(pk)?;
    Ok(public_buffer.marshall()?)
}

pub fn get_ak_cert() -> anyhow::Result<Vec<u8>> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_AK_CERT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context =
        tssContext::new(conf).context("Error creating TPM context. Are you running as root?")?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let ak_cert = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(ak_cert)
}

#[cfg(test)]
mod test {
    use crate::tpm::get_ak_cert;
    use anyhow::Context;
    #[test]
    #[ignore]
    fn test_get_ak_cert() -> anyhow::Result<()> {
        get_ak_cert().context("Failed getting ak get")?;

        Ok(())
    }
}
