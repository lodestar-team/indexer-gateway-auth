//! TLS termination and mTLS client-certificate handling.
//!
//! When `tls.enabled` is set, the proxy terminates TLS itself with `rustls`
//! (ring provider). With `tls.require_client_cert`, it additionally requires and
//! verifies a client certificate against `tls.client_ca`, extracts the
//! certificate's identity (CN and SANs), and injects it into each request as a
//! [`ClientCert`] extension — which the pipeline then maps to a principal.
//!
//! The serve loop is hand-rolled over `tokio-rustls` + `hyper-util` because the
//! peer certificate is only reachable from the completed TLS connection, not via
//! `axum::serve`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::ConnectInfo;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use x509_parser::prelude::*;

use crate::auth::ClientCert;
use crate::config::Tls;

/// Build a `rustls` server config from the TLS configuration.
pub fn load_server_config(tls: &Tls) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_path = tls.cert.as_ref().context("tls.enabled requires tls.cert")?;
    let key_path = tls.key.as_ref().context("tls.enabled requires tls.key")?;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("configuring TLS protocol versions")?;

    let config = if tls.require_client_cert {
        let ca_path = tls
            .client_ca
            .as_ref()
            .context("require_client_cert requires tls.client_ca")?;
        let roots = load_root_store(ca_path)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("building client certificate verifier")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("loading server certificate/key")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("loading server certificate/key")?
    };

    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates from {}", path.display()))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {}", path.display());
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing private key from {}", path.display()))?
        .with_context(|| format!("no private key found in {}", path.display()))
}

fn load_root_store(path: &Path) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots
            .add(cert)
            .with_context(|| format!("adding CA from {} to trust store", path.display()))?;
    }
    Ok(roots)
}

/// Serve `app` over TLS on `listener`, injecting connection info and (when
/// present) the verified client certificate identity into each request.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    tokio::pin!(shutdown);

    loop {
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => accepted.context("accepting TCP connection")?,
            _ = &mut shutdown => {
                tracing::info!("TLS listener shutting down");
                return Ok(());
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            serve_connection(acceptor, tcp, peer, app).await;
        });
    }
}

async fn serve_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    app: Router,
) {
    let tls_stream = match acceptor.accept(tcp).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, %peer, "TLS handshake failed");
            return;
        }
    };

    // Extract the verified client certificate identity, if mTLS presented one.
    let client_cert = {
        let (_, conn) = tls_stream.get_ref();
        conn.peer_certificates().and_then(extract_identity)
    };

    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let app = app.clone();
        let client_cert = client_cert.clone();
        async move {
            let mut req = req.map(axum::body::Body::new);
            req.extensions_mut().insert(ConnectInfo(peer));
            if let Some(cert) = client_cert {
                req.extensions_mut().insert(cert);
            }
            app.oneshot(req).await
        }
    });

    if let Err(e) = AutoBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(tls_stream), service)
        .await
    {
        tracing::debug!(error = %e, %peer, "error serving TLS connection");
    }
}

/// Parse a client certificate chain's leaf into a [`ClientCert`] identity.
pub fn extract_identity(certs: &[CertificateDer<'_>]) -> Option<ClientCert> {
    let leaf = certs.first()?;
    let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_string);

    let mut sans = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(s) | GeneralName::RFC822Name(s) | GeneralName::URI(s) => {
                    sans.push(s.to_string());
                }
                _ => {}
            }
        }
    }

    Some(ClientCert { subject_cn, sans })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    /// Generate a self-signed cert with the given CN and DNS SAN, returning DER.
    fn make_cert(cn: &str, dns_san: &str) -> Vec<u8> {
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params
            .subject_alt_names
            .push(SanType::DnsName(dns_san.try_into().unwrap()));
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extract_identity_reads_cn_and_san() {
        let der = make_cert("operator.indexer.eth", "ci.indexer.eth");
        let cert = CertificateDer::from(der);
        let identity = extract_identity(std::slice::from_ref(&cert)).unwrap();
        assert_eq!(identity.subject_cn.as_deref(), Some("operator.indexer.eth"));
        assert!(identity.sans.iter().any(|s| s == "ci.indexer.eth"));
    }

    #[test]
    fn extract_identity_handles_empty_chain() {
        assert!(extract_identity(&[]).is_none());
    }

    #[test]
    fn extract_identity_rejects_garbage() {
        let cert = CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(extract_identity(std::slice::from_ref(&cert)).is_none());
    }
}
