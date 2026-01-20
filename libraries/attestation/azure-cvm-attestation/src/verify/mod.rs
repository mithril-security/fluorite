extern crate base64 as b64;
use async_trait::async_trait;
use b64::prelude::*;
use chrono::DateTime;
use gpu_attestation_server::verify_gpu_evidence;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::DecodingKey;
use log::info;
use pkcs8::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use rsa::BigUint;
use webpki::types::CertificateDer;

use crate::common::ConfidentialVmAttestationDocument;
use tpm_quote::common::SanitizedPcrData;
use tpm_quote::verify::AttestationKey;

use crate::common::maa_jwt::MaaClaims;
use anyhow::anyhow;
use anyhow::{bail, ensure, Context};
use rustls_pki_types::UnixTime;
use tpm_quote::verify::RsaAttestationKey;

use attestation::AsyncVerifyAttestationDocument;

#[async_trait]
impl AsyncVerifyAttestationDocument for ConfidentialVmAttestationDocument {
    async fn verify(&self, _now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        // Create trust anchors based on Root CAs used by Azure

        // We are pinning the Root CAs. The certs are embedded at compile time.
        // The certificates were sourced from Microsoft's official Azure documentation :
        // https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-ca-details?tabs=root-and-subordinate-cas-list
        let mut client_builder = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false);

        let azure_allowed_root_ca = vec![
            include_bytes!("../common/root_ca_azure/DigiCertGlobalRootCA.crt").to_vec(),
            include_bytes!("../common/root_ca_azure/DigiCertGlobalRootG2.crt").to_vec(),
            include_bytes!("../common/root_ca_azure/DigiCertGlobalRootG3.crt").to_vec(),
            include_bytes!("../common/root_ca_azure/DigiCertTLSECCP384RootG5.crt").to_vec(),
            include_bytes!("../common/root_ca_azure/DigiCertTLSRSA4096RootG5.crt").to_vec(),
            include_bytes!(
                "../common/root_ca_azure/Microsoft ECC Root Certificate Authority 2017.crt"
            )
            .to_vec(),
            include_bytes!(
                "../common/root_ca_azure/Microsoft RSA Root Certificate Authority 2017.crt"
            )
            .to_vec(),
        ];

        // Convert each CA certificate from DER format into a TrustAnchor object.
        for cert in &azure_allowed_root_ca {
            let cert = CertificateDer::from(cert.clone());

            let anchor = webpki::anchor_from_trusted_cert(&cert)
                .context("Error converting cert ot TrustAnchor")?;

            // Validate that the pinned Root CAs are part of Mozilla's trusted root CA list.
            // This validation ensures that the pinned Root CAs are publicly recognized and trusted.
            // The assertion will fail if any of those CAs are removed from Mozilla's list, signaling a potential security concern.
            // In such cases, actions such as updating or replacing the pinned CAs should be considered.
            ensure!(webpki_roots::TLS_SERVER_ROOTS.contains(&anchor));

            client_builder =
                client_builder.add_root_certificate(reqwest::Certificate::from_der(&cert)?);
        }

        let client = client_builder.build()?;

        let jwks: JwkSet = client
            .get("https://testattest.eus.attest.azure.net/certs")
            .send()
            .await
            .context("Error conneting to the Attestation Service")?
            .json()
            .await
            .context("Error getting the jwk set from Attestation Service")?;

        let header = jsonwebtoken::decode_header(&self.response_struct.jwt)?;
        let kid = header
            .kid
            .ok_or(anyhow!("JWT doesn't have a `kid` header field"))?;
        let jwk = jwks
            .find(&kid)
            .ok_or(anyhow!("No matching JWK found for the given kid"))?;

        // NOTE: We print only print a warning if the JWT token has expried as we currently
        // Do not support the logic to refresh the token if it has expired.
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let maa_token = match jsonwebtoken::decode::<MaaClaims>(
            &self.response_struct.jwt,
            &DecodingKey::from_jwk(jwk)?,
            &validation,
        ) {
            Ok(token) => token,
            Err(err) => {
                // 1. Check if it's an ExpiredSignature
                if let ErrorKind::ExpiredSignature = err.kind() {
                    // 2. To "continue anyway", we must decode again without expiration validation
                    validation.validate_exp = false;
                    let token = jsonwebtoken::decode::<MaaClaims>(
                        &self.response_struct.jwt,
                        &DecodingKey::from_jwk(jwk)?,
                        &validation,
                    )?; // This ? will bail if even the non-exp decode fails

                    let dt =
                        DateTime::from_timestamp(token.claims.exp, 0).expect("invalid timestamp");

                    log::warn!(
                        "Token has expired but continuing anyway. Token expired: {} ",
                        dt
                    );

                    token
                } else {
                    // 3. Otherwise, bail (return the error)
                    return Err(err.into());
                }
            }
        };

        if maa_token.claims.iss == "https://testattest.eus.attest.azure.net"
            && maa_token.claims.x_ms_attestation_type == "azurevm"
            && maa_token.claims.x_ms_isolation_tee.x_ms_attestation_type == "sevsnpvm"
            && maa_token.claims.x_ms_isolation_tee.x_ms_compliance_status == "azure-compliant-cvm"
            && !maa_token
                .claims
                .x_ms_isolation_tee
                .x_ms_sevsnpvm_is_debuggable
        {
            info!("{}", "Claims verified");
        } else {
            bail!("Insecure claims, verification failed");
        }

        let deserialized_attestation = gpu_attestation_server::deserialize_attestation(
            maa_token.claims.x_ms_runtime.client_payload.nonce,
        )
        .context("Error deserializing attestation")?;

        verify_gpu_evidence(deserialized_attestation)
            .await
            .context("Error verifying attestation result")?;

        let ak_pub_list = maa_token.claims.x_ms_isolation_tee.x_ms_runtime.keys;

        // https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design#runtime-claims

        for key in ak_pub_list {
            // An array of keys in JWK format. Expected kid: HCLAkPub (vTPM AK public), HCLEkPub (vTPM EK public).
            if key.kid == "HCLAkPub" {
                let ak_pub_key_n_base64 = &BASE64_URL_SAFE_NO_PAD.decode(key.n)?;
                let ak_pub_key_e_base64 = &BASE64_URL_SAFE_NO_PAD.decode(key.e)?;

                let ak_pub_key_n = BigUint::from_bytes_be(ak_pub_key_n_base64);
                let ak_pub_key_e = BigUint::from_bytes_be(ak_pub_key_e_base64);
                let public_key = rsa::RsaPublicKey::new(ak_pub_key_n, ak_pub_key_e)
                    .context("Error creating RsaPublicKey")?;

                let attestation_key = RsaAttestationKey::try_from_pem(
                    &public_key.to_public_key_pem(LineEnding::LF)?,
                )?;
                let sanitized_pcrs = attestation_key.verify_quote(&self.response_struct.quote);

                return sanitized_pcrs;
            }
        }

        bail!("Could not verify quote!");
    }
}
