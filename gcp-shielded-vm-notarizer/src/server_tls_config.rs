//! TLS configuration for the notarizer server with client certificate verification.
//!
//! The server requires clients to present a certificate matching the creator certificate
//! that was provided via instance metadata.

use rustls::{
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::CertificateDer,
    server::danger::ClientCertVerified,
};
use std::sync::Arc;

/// Client certificate verifier that requires the client certificate to match
/// a specific creator certificate.
#[derive(Debug)]
pub struct CreatorCertificateVerifier {
    /// The expected creator certificate (DER-encoded)
    creator_cert_der: Arc<Vec<u8>>,
    /// Supported signature algorithms
    supported_algs: WebPkiSupportedAlgorithms,
}

impl CreatorCertificateVerifier {
    /// Create a new verifier that accepts only the specified creator certificate.
    pub fn new(creator_cert_der: Vec<u8>, provider: CryptoProvider) -> Self {
        Self {
            creator_cert_der: Arc::new(creator_cert_der),
            supported_algs: provider.signature_verification_algorithms,
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for CreatorCertificateVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Compare the presented certificate with the expected creator certificate
        if end_entity.as_ref() == self.creator_cert_der.as_slice() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Client certificate does not match creator certificate".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
