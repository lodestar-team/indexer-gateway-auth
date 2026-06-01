//! End-to-end TLS / mTLS tests with a real handshake.
//!
//! A CA signs both a server certificate and a client certificate; the gateway is
//! configured for mTLS (`require_client_cert`) and maps the client CN to a
//! principal. A `reqwest` client presenting that identity must succeed and be
//! mapped to `operator`; a client presenting no certificate must be rejected at
//! the TLS layer.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::Request;
use axum::Router;
use http::{header, StatusCode};
use iga::audit::AuditSink;
use iga::auth::Authenticator;
use iga::config::Config;
use iga::proxy::Proxy;
use iga::server::{build_router, AppOptions, AppState};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::net::TcpListener;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Pem {
    cert: String,
    key: String,
}

/// A self-signed CA plus a server and client certificate it issues.
struct TestPki {
    ca_pem: String,
    server: Pem,
    client: Pem,
}

fn build_pki(client_cn: &str) -> TestPki {
    // CA
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert (SAN 127.0.0.1), signed by CA.
    let mut server_params = CertificateParams::new(vec![]).unwrap();
    server_params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    // Client cert (CN = client_cn), signed by CA.
    let mut client_params = CertificateParams::new(vec![]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, client_cn);
    client_params.distinguished_name = dn;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    TestPki {
        ca_pem: ca_cert.pem(),
        server: Pem {
            cert: server_cert.pem(),
            key: server_key.serialize_pem(),
        },
        client: Pem {
            cert: client_cert.pem(),
            key: client_key.serialize_pem(),
        },
    }
}

fn write_temp(label: &str, contents: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("iga-{}-{}-{label}.pem", std::process::id(), n));
    std::fs::write(&path, contents).unwrap();
    path
}

async fn spawn_upstream() -> (SocketAddr, Arc<Mutex<usize>>) {
    let hits = Arc::new(Mutex::new(0usize));
    let sink = hits.clone();
    let app = Router::new().fallback(move |_req: Request| {
        let sink = sink.clone();
        async move {
            *sink.lock().unwrap() += 1;
            (StatusCode::OK, r#"{"data":{"ok":true}}"#)
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, hits)
}

/// Spawn the gateway over mTLS, returning its address and the audit file path.
async fn spawn_mtls_gateway(
    upstream: SocketAddr,
    pki: &TestPki,
) -> (SocketAddr, std::path::PathBuf) {
    let cert_path = write_temp("server-cert", &pki.server.cert);
    let key_path = write_temp("server-key", &pki.server.key);
    let ca_path = write_temp("ca", &pki.ca_pem);
    let audit_path = std::env::temp_dir().join(format!(
        "iga-mtls-audit-{}-{}.log",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&audit_path);

    let toml = format!(
        r#"
listen = "127.0.0.1:0"
metrics = "127.0.0.1:0"
[upstream]
agent_management = "http://{upstream}"
[tls]
enabled = true
cert = "{cert}"
key = "{key}"
require_client_cert = true
client_ca = "{ca}"
[auth]
mode = "mtls"
[[auth.mtls]]
subject = "operator.indexer.eth"
name = "operator"
scopes = ["read", "write"]
"#,
        cert = cert_path.display(),
        key = key_path.display(),
        ca = ca_path.display(),
    );
    let config = Config::from_toml_str(&toml).unwrap();
    let authenticator = Authenticator::from_config(&config.auth).unwrap();
    let proxy = Proxy::new(reqwest::Client::new(), &config.upstream);
    let audit = AuditSink::file(&audit_path).unwrap();
    let state = AppState::new(&config, authenticator, proxy, audit, AppOptions::default());
    let app = build_router(state);

    let tls_config = iga::tls::load_server_config(&config.tls).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        iga::tls::serve(listener, tls_config, app, std::future::pending::<()>())
            .await
            .unwrap();
    });
    (addr, audit_path)
}

#[tokio::test]
async fn mtls_client_is_mapped_to_principal_and_allowed() {
    let pki = build_pki("operator.indexer.eth");
    let (upstream, hits) = spawn_upstream().await;
    let (gateway, audit_path) = spawn_mtls_gateway(upstream, &pki).await;

    // A client presenting the CA-signed identity.
    let identity_pem = format!("{}{}", pki.client.key, pki.client.cert);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // we are testing client auth, not server trust
        .identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    let resp = client
        .post(format!("https://{gateway}/"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"query":"mutation { setIndexingRule(rule: {}) { id } }"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(*hits.lock().unwrap(), 1);

    // The audit trail attributes the write to the mapped principal.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let contents = std::fs::read_to_string(&audit_path).unwrap();
    let line = contents.lines().next().expect("an audit line");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["principal"], "operator");
    assert_eq!(v["scope"], "write");
    let _ = std::fs::remove_file(&audit_path);
}

#[tokio::test]
async fn connection_without_client_certificate_is_rejected() {
    let pki = build_pki("operator.indexer.eth");
    let (upstream, hits) = spawn_upstream().await;
    let (gateway, _audit) = spawn_mtls_gateway(upstream, &pki).await;

    // No client identity → the mandatory client-auth handshake must fail.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let result = client
        .post(format!("https://{gateway}/"))
        .body(r#"{"query":"{ indexingRules { id } }"}"#)
        .send()
        .await;
    assert!(result.is_err(), "handshake without client cert must fail");
    assert_eq!(*hits.lock().unwrap(), 0);
}
