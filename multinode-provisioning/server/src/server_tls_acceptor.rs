use axum::{Extension, middleware::AddExtension};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use futures_util::future::BoxFuture;
use rustls_pki_types::CertificateDer;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;

#[derive(Debug, Clone)]
pub(crate) struct TlsData {
    pub peer_certificates: Vec<CertificateDer<'static>>,
}

#[derive(Debug, Clone)]
pub(crate) struct CustomAcceptor {
    inner: RustlsAcceptor,
}

impl CustomAcceptor {
    pub(crate) fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for CustomAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, TlsData>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let server_conn = stream.get_ref().1;
            let peer_certificates = server_conn.peer_certificates().unwrap_or(&[]);
            let tls_data = TlsData {
                peer_certificates: peer_certificates.to_vec(),
            };
            let service = Extension(tls_data).layer(service);

            Ok((stream, service))
        })
    }
}
