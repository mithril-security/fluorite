use aes::cipher::generic_array::{typenum::U16, typenum::U32, GenericArray};
use anyhow::{bail, Context as AnyhowContext};
use fn_error_context::context;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    Attest, CreatePrimaryKeyResult, Data, Digest, PcrSelectionList, PcrSelectionListBuilder,
    PcrSlot, Public, PublicKeyRsa, PublicRsaParameters, RsaDecryptionScheme, RsaExponent,
    SignatureScheme, SymmetricDefinition,
};

use tss_esapi::{interface_types::session_handles::AuthSession, Context};

use crate::common::EncryptedJwt;
use crate::generate::tpm::VTPM_AK_HANDLE;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

const VTPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

#[context("Failed to create_ephemeral_key")]
pub fn create_ephemeral_key(
    ctx: &mut tss_esapi::Context,
    pcr_digest: &tss_esapi::structures::Digest,
    pcr_selection: &tss_esapi::structures::PcrSelectionList,
) -> Result<
    (
        CreatePrimaryKeyResult,
        Attest,
        tss_esapi::structures::Signature,
    ),
    anyhow::Error,
> {
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    let obj_attributes = ObjectAttributes::builder()
        .with_decrypt(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_no_da(true)
        .build()?;

    let rsa_params = PublicRsaParameters::builder()
        .with_scheme(tss_esapi::structures::RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::ZERO_EXPONENT)
        .build()?;
    // Set the alg to TPM2_ALG_NULL so the caller can specify the alg such as TPM2_ALG_OAEP or TPM2_ALG_RSAES
    // .with_scheme(Null)

    let auth_policy = get_ephemeral_key_policy_digest(ctx, pcr_digest, pcr_selection)?;
    // .with_symmetric(S)

    //println!("begin public template");
    let public_template = Public::builder()
        .with_object_attributes(obj_attributes)
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .with_rsa_parameters(rsa_params)
        .with_auth_policy(auth_policy)
        .build()?;
    //println!("end public template");

    // ctx
    let primary_creation_res = ctx.execute_with_nullauth_session(|ctx| {
        anyhow::Ok(
            ctx.create_primary(Hierarchy::Null, public_template, None, None, None, None)
                .context("Failed to create Ephemeral Key")?,
        )
    })?;

    let obj_handle = ctx.tr_from_tpm_public(VTPM_AK_HANDLE.try_into()?)?;
    // Certify
    let (attest, sig) = ctx.execute_with_sessions(
        (
            Some(AuthSession::Password),
            Some(AuthSession::Password),
            None,
        ),
        |ctx| {
            ctx.certify(
                primary_creation_res.key_handle.into(),
                obj_handle.into(),
                Data::default(),
                SignatureScheme::Null,
            )
        },
    )?;
    Ok((primary_creation_res, attest, sig))
}

#[context("Failed to get_ephemeral_key_policy_digest")]
fn get_ephemeral_key_policy_digest(
    ctx: &mut Context,
    pcr_digest: &tss_esapi::structures::Digest,
    pcr_selection: &tss_esapi::structures::PcrSelectionList,
) -> anyhow::Result<Digest> {
    //println!("begin");
    let auth_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Trial,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .context("Empty Session")?;

    //println!("end");

    let AuthSession::PolicySession(session) = auth_session else {
        bail!("Bad session type");
    };

    let _selection_list: tss_esapi::structures::PcrSelectionList = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &VTPM_QUOTE_PCR_SLOTS)
        .build()?;

    ctx.policy_pcr(session, pcr_digest.clone(), pcr_selection.clone())?;
    Ok(ctx.policy_get_digest(session)?)
}

pub(crate) fn decrypt_inner_key(
    ctx: &mut tss_esapi::Context,
    encrypted_inner_key: &[u8],
    key_handle: &KeyHandle,
    pcr_digest: &Digest,
    pcr_selection: &PcrSelectionList,
) -> anyhow::Result<Vec<u8>> {
    let auth_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Policy,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .context("Empty Session")?;

    ctx.policy_pcr(
        auth_session.try_into()?,
        pcr_digest.clone(),
        pcr_selection.clone(),
    )?;

    ctx.set_sessions((Some(auth_session), None, None));
    let ret_rsa_decrypt = ctx.rsa_decrypt(
        key_handle.clone(),
        PublicKeyRsa::try_from(encrypted_inner_key)?,
        RsaDecryptionScheme::RsaEs,
        Data::default(),
    )?;
    Ok(ret_rsa_decrypt.to_vec())
}

/// Implements NIST SP 800-108 KDF in Counter Mode with HMAC-SHA256
/// Reference: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
///
///
fn sp800_108_counter_kdf(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    length_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    // TODO: Replace with a https://crates.io/crates/kbkdf once it's stable
    // let counter = Counter::<HmacSha256, HmacSha256>::default();
    // let key = counter
    //     .derive(Params::builder(key).with_label(label).with_context(context).use_separator(true).use_l(true).build())
    //     .unwrap();

    let mut derived_key = Vec::with_capacity(length_bytes);
    let mut counter: u32 = 1;
    let l_bits: u32 = (length_bytes as u32) * 8; // Length of derived key in bits
    type HmacSha256 = Hmac<Sha256>;

    // The loop continues until we have generated enough bytes
    while derived_key.len() < length_bytes {
        let mut mac = HmacSha256::new_from_slice(key)?;

        // NIST SP 800-108 Input Construction:
        // Input = [i] || Label || 0x00 || Context || [L]

        // 1. Counter (i) - 32-bit Big Endian
        mac.update(&counter.to_be_bytes());

        // 2. Label
        mac.update(label);

        // 3. Separator (0x00)
        mac.update(&[0x00]);

        // 4. Context
        mac.update(context);

        // 5. Length of output key in bits ([L]) - 32-bit Big Endian
        mac.update(&l_bits.to_be_bytes());

        let result = mac.finalize().into_bytes();
        derived_key.extend_from_slice(&result);

        counter += 1;
    }

    // Truncate to the exact requested length
    derived_key.truncate(length_bytes);

    Ok(derived_key)
}

pub(crate) fn decrypt_jwt(
    inner_key: Vec<u8>,
    encrypted_token: EncryptedJwt,
) -> anyhow::Result<Vec<u8>> {
    let auth_label = "Authentication_Key_HMAC_384".as_bytes();
    let auth_context =
        "Application: AzureAttestation, Protocol: 3.0, Purpose: Message_Authentication".as_bytes();

    let derived_auhentication_key =
        sp800_108_counter_kdf(&inner_key, auth_label, auth_context, 0x30)?;

    // First check the tag
    type HmacSha384 = Hmac<Sha384>;
    let mut mac = HmacSha384::new_from_slice(&derived_auhentication_key)
        .context("Error creating HmacSha384")?;
    mac.update(&encrypted_token.jwt);
    mac.verify_slice(&encrypted_token.authentication_data)
        .context("Error verifying encrypted token tag")?;

    // Once the tag is checked, decrypt the message
    let enc_label = "Encryption_Key_Aes_Cbc".as_bytes();
    let enc_context =
        "Application: AzureAttestation, Protocol: 3.0, Purpose: Message_Encryption".as_bytes();

    let derived_encryption_key = sp800_108_counter_kdf(&inner_key, enc_label, enc_context, 0x20)?;

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let bytes: GenericArray<_, U32> = GenericArray::clone_from_slice(&derived_encryption_key);
    let iv: GenericArray<_, U16> =
        GenericArray::clone_from_slice(&encrypted_token.encryption_params.iv);
    let cipher = Aes256CbcDec::new(&bytes, &iv);
    let mut buffer = encrypted_token.jwt.to_vec();
    let decrypted_slice = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| anyhow::format_err!("Decryption error"))?;

    Ok(decrypted_slice.to_vec())
}
