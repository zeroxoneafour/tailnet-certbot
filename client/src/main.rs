//! tailnet-certbot client
//!
//! Posts the configured CSR (plus alt names) to the tailnet-certbot server
//! and saves the returned certificate. The CSR must already exist.

use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

const DEFAULT_CONFIG: &str = "/data/config.toml";

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    client: ClientConfig,
    #[serde(default)]
    certificate: CertificateConfig,
    #[serde(default)]
    alt_names: AltNames,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    /// Full URL of the server's signing endpoint.
    server: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct CertificateConfig {
    csr: PathBuf,
    cert: PathBuf,
    /// Requested validity period of the certificate, in days.
    valid_for: u32,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            csr: "/data/server.csr".into(),
            cert: "/data/server.crt".into(),
            valid_for: 365,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct AltNames {
    dns: Vec<String>,
    ip: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------
// protocol
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SignRequest<'a> {
    csr: &'a str,
    #[serde(rename = "alt-dns")]
    alt_dns: &'a [String],
    #[serde(rename = "alt-ips")]
    alt_ips: &'a [IpAddr],
    #[serde(rename = "valid-for")]
    valid_for: u32,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Write via a temporary file + rename so an existing file is never left
/// half-written.
fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(contents.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, path))
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Read a required input file, failing with a clear message if it is absent.
fn read_required(what: &str, path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("reading {what} {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn run() -> Result<(), String> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_owned());
    let config: Config = toml::from_str(
        &fs::read_to_string(&config_path)
            .map_err(|e| format!("reading config {config_path}: {e}"))?,
    )
    .map_err(|e| format!("parsing config {config_path}: {e}"))?;

    let cfg = &config.certificate;
    let csr = read_required("CSR", &cfg.csr)?;

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();

    eprintln!("requesting certificate from {}", config.client.server);
    let mut resp = agent
        .post(&config.client.server)
        .send_json(SignRequest {
            csr: &csr,
            alt_dns: &config.alt_names.dns,
            alt_ips: &config.alt_names.ip,
            valid_for: cfg.valid_for,
        })
        .map_err(|e| format!("request to {} failed: {e}", config.client.server))?;

    let status = resp.status();
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading response: {e}"))?;
    if !status.is_success() {
        return Err(format!("server returned {status}: {}", body.trim()));
    }
    if !body.trim_start().starts_with("-----BEGIN CERTIFICATE-----") {
        return Err("server response is not a PEM certificate".into());
    }

    write_atomic(&cfg.cert, &body)?;
    eprintln!("saved certificate to {}", cfg.cert.display());
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
