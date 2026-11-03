//! tailnet-certbot server
//!
//! Accepts a CSR over plain HTTP (the tailnet provides transport encryption),
//! signs it with the configured root CA, and returns the PEM certificate.

use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use rcgen::{
    CertificateSigningRequestParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

const DEFAULT_CONFIG: &str = "/data/config.toml";

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    certificate: CertificateConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct ServerConfig {
    /// HTTP path the signing endpoint is served on.
    path: String,
    /// Socket address to listen on.
    serve_on: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            serve_on: "0.0.0.0:8000".into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct CertificateConfig {
    cert: PathBuf,
    srl: PathBuf,
    key: PathBuf,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            cert: "/data/root-ca.crt".into(),
            srl: "/data/root-ca.srl".into(),
            key: "/data/root-ca.key".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    srl: PathBuf,
}

/// The mutex serialises signing so the serial file is never read and
/// written concurrently.
type AppState = Arc<Mutex<Ca>>;

fn load_ca(cfg: &CertificateConfig) -> Result<Ca, String> {
    let key_pem = fs::read_to_string(&cfg.key)
        .map_err(|e| format!("reading CA key {}: {e}", cfg.key.display()))?;
    let key = KeyPair::from_pem(&key_pem).map_err(|e| {
        format!(
            "parsing CA key {}: {e} (the key must be an unencrypted PKCS#8 \"PRIVATE KEY\"; \
             convert with `openssl pkcs8 -topk8 -nocrypt`)",
            cfg.key.display()
        )
    })?;
    let cert_pem = fs::read_to_string(&cfg.cert)
        .map_err(|e| format!("reading CA cert {}: {e}", cfg.cert.display()))?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
        .map_err(|e| format!("parsing CA cert {}: {e}", cfg.cert.display()))?;
    Ok(Ca {
        issuer,
        srl: cfg.srl.clone(),
    })
}

// ---------------------------------------------------------------------------
// serial number handling (OpenSSL-compatible hex `.srl` file)
// ---------------------------------------------------------------------------

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let padded = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_owned()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).ok())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn increment(bytes: &mut Vec<u8>) {
    for b in bytes.iter_mut().rev() {
        let (v, overflow) = b.overflowing_add(1);
        *b = v;
        if !overflow {
            return;
        }
    }
    bytes.insert(0, 1);
}

/// Reads the serial file, increments it, persists it and returns the new
/// serial (same semantics as `openssl x509 -CAserial`). If the file does not
/// exist a random serial is created (like `-CAcreateserial`).
fn next_serial(path: &Path) -> Result<Vec<u8>, String> {
    let mut serial = match fs::read_to_string(path) {
        Ok(s) => parse_hex(&s)
            .ok_or_else(|| format!("serial file {} is not valid hex", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut buf = vec![0u8; 20];
            getrandom::fill(&mut buf).map_err(|e| format!("generating random serial: {e}"))?;
            buf[0] &= 0x7f;
            eprintln!("serial file {} not found, creating it", path.display());
            buf
        }
        Err(e) => return Err(format!("reading serial file {}: {e}", path.display())),
    };
    increment(&mut serial);

    // write atomically so a crash can never leave a truncated serial file
    let tmp = path.with_extension("srl.tmp");
    fs::write(&tmp, format!("{}\n", to_hex(&serial)))
        .and_then(|_| fs::rename(&tmp, path))
        .map_err(|e| format!("writing serial file {}: {e}", path.display()))?;
    Ok(serial)
}

// ---------------------------------------------------------------------------
// request handling
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SignRequest {
    csr: String,
    #[serde(rename = "alt-dns", default)]
    alt_dns: Vec<String>,
    #[serde(rename = "alt-ips", default)]
    alt_ips: Vec<IpAddr>,
    /// Validity period of the issued certificate, in days.
    #[serde(rename = "valid-for")]
    valid_for: u32,
}

struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        eprintln!("error: {}", self.1);
        (self.0, format!("{}\n", self.1)).into_response()
    }
}

fn bad_request(msg: impl Into<String>) -> AppError {
    AppError(StatusCode::BAD_REQUEST, msg.into())
}

fn internal(msg: impl Into<String>) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
}

fn sign(ca: &Ca, req: SignRequest) -> Result<String, AppError> {
    if req.valid_for == 0 {
        return Err(bad_request("valid-for must be at least 1 day"));
    }
    let mut csr = CertificateSigningRequestParams::from_pem(&req.csr)
        .map_err(|e| bad_request(format!("invalid CSR: {e}")))?;

    let params = &mut csr.params;

    // subjectAltName: whatever the CSR asked for plus the request's alt names
    for dns in req.alt_dns {
        let name = dns
            .clone()
            .try_into()
            .map_err(|_| bad_request(format!("invalid DNS name: {dns:?}")))?;
        params.subject_alt_names.push(SanType::DnsName(name));
    }
    for ip in req.alt_ips {
        params.subject_alt_names.push(SanType::IpAddress(ip));
    }
    let mut seen = Vec::with_capacity(params.subject_alt_names.len());
    params.subject_alt_names.retain(|san| {
        if seen.contains(san) {
            false
        } else {
            seen.push(san.clone());
            true
        }
    });
    if params.subject_alt_names.is_empty() {
        return Err(bad_request("no subject alternative names were requested"));
    }

    // fixed extensions; never trust the CSR for these
    params.use_authority_key_identifier_extension = true; // authorityKeyIdentifier=keyid
    params.is_ca = IsCa::ExplicitNoCa; // basicConstraints=CA:FALSE
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment, // nonRepudiation
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment,
    ];
    params.name_constraints = None;
    params.crl_distribution_points.clear();
    params.custom_extensions.clear();

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(req.valid_for.into());

    let serial = next_serial(&ca.srl).map_err(internal)?;
    params.serial_number = Some(SerialNumber::from_slice(&serial));

    let cert = csr
        .signed_by(&ca.issuer)
        .map_err(|e| internal(format!("signing certificate: {e}")))?;

    let sans: Vec<String> = csr
        .params
        .subject_alt_names
        .iter()
        .map(|san| match san {
            SanType::DnsName(n) => n.as_str().to_owned(),
            SanType::IpAddress(ip) => ip.to_string(),
            other => format!("{other:?}"),
        })
        .collect();
    eprintln!("issued certificate serial {} for [{}]", to_hex(&serial), sans.join(", "));

    Ok(cert.pem())
}

async fn handle(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ca = state.lock().await;
    let pem = sign(&ca, req)?;
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], pem))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
    eprintln!("shutting down");
}

async fn run() -> Result<(), String> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_owned());
    let config: Config = toml::from_str(
        &fs::read_to_string(&config_path)
            .map_err(|e| format!("reading config {config_path}: {e}"))?,
    )
    .map_err(|e| format!("parsing config {config_path}: {e}"))?;

    let ca = load_ca(&config.certificate)?;

    let mut path = config.server.path.clone();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }

    let app = Router::new()
        .route(&path, post(handle))
        .with_state(Arc::new(Mutex::new(ca)));

    let listener = tokio::net::TcpListener::bind(&config.server.serve_on)
        .await
        .map_err(|e| format!("binding {}: {e}", config.server.serve_on))?;
    eprintln!("listening on http://{}{path}", config.server.serve_on);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_increment() {
        let mut v = parse_hex("0aff").unwrap();
        increment(&mut v);
        assert_eq!(to_hex(&v), "0B00");
        let mut v = parse_hex("FFFF").unwrap();
        increment(&mut v);
        assert_eq!(to_hex(&v), "010000");
        assert_eq!(parse_hex("abc").unwrap(), vec![0x0a, 0xbc]);
        assert!(parse_hex("xyz").is_none());
        assert!(parse_hex("").is_none());
    }
}
