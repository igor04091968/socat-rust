//! Optional, fail-closed TLS endpoints. Plain TCP remains the default.
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Tls,
    Gost,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GostCipher {
    #[default]
    Kuznyechik,
    Magma,
    Gost28147,
    Legacy28147,
}

impl GostCipher {
    pub fn openssl_name(self) -> &'static str {
        match self {
            Self::Kuznyechik => "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC",
            Self::Magma => "GOST2012-MAGMA-MAGMAOMAC",
            Self::Gost28147 => "IANA-GOST2012-GOST8912-GOST8912",
            Self::Legacy28147 => "LEGACY-GOST2012-GOST8912-GOST8912",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundTls {
    #[serde(default)]
    pub mode: Mode,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    /// Presence requires a trusted client certificate (mTLS); absence allows TLS clients.
    pub client_ca: Option<PathBuf>,
    #[serde(default)]
    pub gost_cipher: Option<GostCipher>,
    #[serde(default = "handshake_seconds")]
    pub handshake_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTls {
    #[serde(default)]
    pub mode: Mode,
    /// Explicit trust roots; the system OpenSSL configuration is not used for trust.
    pub ca_file: PathBuf,
    /// Name/IP to verify against the certificate; also used for DNS SNI.
    pub server_name: String,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    #[serde(default)]
    pub gost_cipher: Option<GostCipher>,
    #[serde(default = "handshake_seconds")]
    pub handshake_timeout_seconds: u64,
}

fn handshake_seconds() -> u64 {
    10
}

fn validate_mode(mode: Mode, seconds: u64) -> Result<()> {
    if !cfg!(feature = "tls") {
        bail!("TLS requested but this binary was built without feature tls");
    }
    if cfg!(feature = "legacy-kernel") {
        bail!("TLS is not supported with legacy-kernel; use the modern runtime");
    }
    if mode == Mode::Gost && !cfg!(feature = "tls-gost") {
        bail!("GOST requested but this binary was built without feature tls-gost");
    }
    if !(1..=120).contains(&seconds) {
        bail!("TLS handshake timeout must be 1..120 seconds");
    }
    Ok(())
}

impl InboundTls {
    pub fn validate(&self) -> Result<()> {
        validate_mode(self.mode, self.handshake_timeout_seconds)?;
        if self.mode == Mode::Tls && self.gost_cipher.is_some() {
            bail!("gost_cipher requires explicit mode = gost");
        }
        if self.certificate.as_os_str().is_empty() || self.private_key.as_os_str().is_empty() {
            bail!("inbound TLS certificate/private_key must not be empty");
        }
        Ok(())
    }
}
impl OutboundTls {
    pub fn validate(&self) -> Result<()> {
        validate_mode(self.mode, self.handshake_timeout_seconds)?;
        if self.mode == Mode::Tls && self.gost_cipher.is_some() {
            bail!("gost_cipher requires explicit mode = gost");
        }
        if self.server_name.trim().is_empty()
            || self.server_name.chars().any(char::is_whitespace)
            || self.server_name.contains('\0')
        {
            bail!("outbound TLS server_name must be an explicit certificate name/IP");
        }
        if self.ca_file.as_os_str().is_empty() {
            bail!("outbound TLS requires ca_file");
        }
        if self.certificate.is_some() != self.private_key.is_some() {
            bail!("outbound TLS client certificate and private_key must be supplied together");
        }
        Ok(())
    }
}

#[cfg(feature = "tls")]
mod enabled {
    use super::*;
    use anyhow::Context;
    #[cfg(feature = "tls-gost")]
    use anyhow::anyhow;
    use openssl::ssl::{
        Ssl, SslAcceptor, SslConnector, SslContextBuilder, SslFiletype, SslMethod, SslOptions,
        SslVerifyMode, SslVersion,
    };
    use std::{pin::Pin, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpStream,
        time::timeout,
    };
    use tokio_openssl::SslStream;

    pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
    pub type Stream = Box<dyn Io>;

    #[derive(Clone, Default)]
    pub struct Runtime {
        server: Option<Arc<SslAcceptor>>,
        client: Option<Arc<SslConnector>>,
        inbound: Option<InboundTls>,
        outbound: Option<OutboundTls>,
    }

    fn setup(ctx: &mut SslContextBuilder, mode: Mode, cipher: GostCipher) -> Result<()> {
        ctx.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        ctx.set_options(SslOptions::NO_COMPRESSION | SslOptions::NO_RENEGOTIATION);
        if mode == Mode::Gost {
            initialize_gost()?;
            // This backend implements the GOST TLS 1.2 suites only. No silent
            // negotiation of standard RSA/ECDSA suites or NULL encryption.
            ctx.set_max_proto_version(Some(SslVersion::TLS1_2))?;
            ctx.set_cipher_list(cipher.openssl_name())
                .context("enable selected GOST TLS 1.2 cipher suite")?;
        } else {
            ctx.set_cipher_list("ECDHE+AESGCM:ECDHE+CHACHA20")?;
            ctx.set_ciphersuites(
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
            )?;
        }
        Ok(())
    }

    impl Runtime {
        pub fn build(inbound: Option<&InboundTls>, outbound: Option<&OutboundTls>) -> Result<Self> {
            // Register GOST algorithms before loading any GOST certificates/keys.
            if inbound.is_some_and(|c| c.mode == Mode::Gost)
                || outbound.is_some_and(|c| c.mode == Mode::Gost)
            {
                initialize_gost()?;
            }
            let server = if let Some(c) = inbound {
                c.validate()?;
                let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
                setup(&mut b, c.mode, c.gost_cipher.unwrap_or_default())?;
                b.set_certificate_chain_file(&c.certificate)
                    .with_context(|| {
                        format!("load inbound certificate {}", c.certificate.display())
                    })?;
                b.set_private_key_file(&c.private_key, SslFiletype::PEM)
                    .context("load inbound TLS private key")?;
                b.check_private_key()
                    .context("inbound TLS certificate/private key mismatch")?;
                if let Some(ca) = &c.client_ca {
                    b.set_ca_file(ca).context("load client CA")?;
                    b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                } else {
                    b.set_verify(SslVerifyMode::NONE);
                }
                Some(Arc::new(b.build()))
            } else {
                None
            };
            let client = if let Some(c) = outbound {
                c.validate()?;
                let mut b = SslConnector::builder(SslMethod::tls_client())?;
                setup(&mut b, c.mode, c.gost_cipher.unwrap_or_default())?;
                let pem = std::fs::read(&c.ca_file).context("read outbound CA bundle")?;
                let certificates = openssl::x509::X509::stack_from_pem(&pem)
                    .context("parse outbound CA bundle")?;
                if certificates.is_empty() {
                    bail!("outbound CA bundle is empty");
                }
                let mut store = openssl::x509::store::X509StoreBuilder::new()?;
                for certificate in certificates {
                    store.add_cert(certificate)?;
                }
                b.set_cert_store(store.build());
                b.set_verify(SslVerifyMode::PEER);
                if let (Some(cert), Some(key)) = (&c.certificate, &c.private_key) {
                    b.set_certificate_chain_file(cert)
                        .context("load outbound client certificate")?;
                    b.set_private_key_file(key, SslFiletype::PEM)
                        .context("load outbound client private key")?;
                    b.check_private_key()
                        .context("outbound client certificate/private key mismatch")?;
                }
                Some(Arc::new(b.build()))
            } else {
                None
            };
            Ok(Self {
                server,
                client,
                inbound: inbound.cloned(),
                outbound: outbound.cloned(),
            })
        }

        pub async fn accept(&self, stream: TcpStream) -> Result<Stream> {
            let Some(server) = &self.server else {
                return Ok(Box::new(stream));
            };
            let c = self.inbound.as_ref().expect("server configuration");
            let ssl = Ssl::new(server.context())?;
            let mut stream = SslStream::new(ssl, stream)?;
            timeout(
                Duration::from_secs(c.handshake_timeout_seconds),
                Pin::new(&mut stream).accept(),
            )
            .await
            .context("inbound TLS handshake timeout")?
            .context("inbound TLS handshake/authentication failed")?;
            if let Some(cipher) = stream.ssl().current_cipher() {
                tracing::info!(
                    protocol = stream.ssl().version_str(),
                    cipher = cipher.name(),
                    "inbound TLS established"
                );
            }
            Ok(Box::new(stream))
        }

        pub async fn connect(&self, stream: TcpStream) -> Result<Stream> {
            let Some(client) = &self.client else {
                return Ok(Box::new(stream));
            };
            let c = self.outbound.as_ref().expect("client configuration");
            // into_ssl verifies DNS SAN/IP SAN and uses SNI for DNS names.
            let ssl = client.configure()?.into_ssl(&c.server_name)?;
            let mut stream = SslStream::new(ssl, stream)?;
            timeout(
                Duration::from_secs(c.handshake_timeout_seconds),
                Pin::new(&mut stream).connect(),
            )
            .await
            .context("outbound TLS handshake timeout")?
            .context("outbound TLS certificate/handshake verification failed")?;
            if let Some(cipher) = stream.ssl().current_cipher() {
                tracing::info!(
                    protocol = stream.ssl().version_str(),
                    cipher = cipher.name(),
                    "outbound TLS established"
                );
            }
            Ok(Box::new(stream))
        }
    }

    #[cfg(feature = "tls-gost")]
    pub fn initialize_gost() -> Result<()> {
        use std::{
            ffi::{c_char, c_int, c_uint, c_void},
            sync::OnceLock,
        };
        // Only the library-form engine is linked. Never load a path from an
        // OpenSSL configuration file, OPENSSL_ENGINES or an external gost.so.
        unsafe extern "C" {
            fn ENGINE_load_gost();
            fn ENGINE_by_id(id: *const c_char) -> *mut c_void;
            fn ENGINE_init(engine: *mut c_void) -> c_int;
            fn ENGINE_set_default(engine: *mut c_void, flags: c_uint) -> c_int;
            fn ENGINE_finish(engine: *mut c_void) -> c_int;
            fn ENGINE_free(engine: *mut c_void) -> c_int;
        }
        static LOADED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
        let result = LOADED.get_or_init(|| {
            openssl::init();
            // SAFETY: OpenSSL is initialized; engine registration occurs once.
            // ENGINE references are owned locally and released after registration.
            unsafe {
                ENGINE_load_gost();
                let engine = ENGINE_by_id(c"gost".as_ptr());
                if engine.is_null() {
                    return Err(format!(
                        "static GOST engine unavailable: {}",
                        openssl::error::ErrorStack::get()
                    ));
                }
                if ENGINE_init(engine) != 1 {
                    ENGINE_free(engine);
                    return Err(format!(
                        "initialize static GOST engine: {}",
                        openssl::error::ErrorStack::get()
                    ));
                }
                let status = ENGINE_set_default(engine, 0xffff);
                ENGINE_finish(engine);
                ENGINE_free(engine);
                if status != 1 {
                    return Err(format!(
                        "register static GOST algorithms: {}",
                        openssl::error::ErrorStack::get()
                    ));
                }
            }
            Ok(())
        });
        result.as_ref().map_err(|e| anyhow!("{e}"))?;
        Ok(())
    }
    #[cfg(not(feature = "tls-gost"))]
    fn initialize_gost() -> Result<()> {
        bail!("GOST is not compiled in");
    }
}

#[cfg(feature = "tls")]
pub use enabled::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_insecure_tls_switch_is_rejected() {
        let raw = "ca_file = 'ca.pem'\nserver_name = 'localhost'\nverify = false";
        assert!(toml::from_str::<OutboundTls>(raw).is_err());
    }

    #[test]
    fn rejects_zero_and_unbounded_handshake_timeout() {
        for seconds in [0, 121, u64::MAX] {
            assert!(validate_mode(Mode::Tls, seconds).is_err());
        }
    }

    #[test]
    fn plain_or_legacy_binary_rejects_tls_configuration() {
        let tls: OutboundTls =
            toml::from_str("ca_file = 'ca.pem'\nserver_name = 'localhost'").unwrap();
        assert_eq!(
            tls.validate().is_ok(),
            cfg!(feature = "tls") && !cfg!(feature = "legacy-kernel")
        );
    }

    #[test]
    fn rejects_partial_client_identity_and_empty_server_name() {
        for raw in [
            "ca_file = 'ca.pem'\nserver_name = ''",
            "ca_file = 'ca.pem'\nserver_name = 'localhost'\ncertificate = 'client.pem'",
            "ca_file = 'ca.pem'\nserver_name = 'localhost'\nprivate_key = 'client.key'",
            "ca_file = ''\nserver_name = 'localhost'",
            "ca_file = 'ca.pem'\nserver_name = 'localhost'\ngost_cipher = 'magma'",
        ] {
            let tls: OutboundTls = toml::from_str(raw).unwrap();
            assert!(tls.validate().is_err());
        }
    }

    #[test]
    fn gost_requires_explicitly_compiled_backend() {
        let tls: OutboundTls =
            toml::from_str("mode = 'gost'\nca_file = 'ca.pem'\nserver_name = 'localhost'").unwrap();
        assert_eq!(
            tls.validate().is_ok(),
            cfg!(feature = "tls-gost") && !cfg!(feature = "legacy-kernel")
        );
    }
}
