use std::sync::Arc;

use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};

#[derive(Debug)]
pub(crate) struct PeerServerVerifier {
    server_cert: pki_types::CertificateDer<'static>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl PeerServerVerifier {
    pub(crate) fn new_with_default_provider(
        server_cert: pki_types::CertificateDer<'static>,
    ) -> PeerServerVerifier {
        PeerServerVerifier {
            server_cert,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PeerServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if &self.server_cert != end_entity {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::from(Box::from(
                    "certificate presented by peer differ from the expected one",
                )))),
            ));
        }
        // There must be no intermediates certificates
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
