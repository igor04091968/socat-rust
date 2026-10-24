//! Offline PEM generation. No relay config, shell, network or certificate installation.
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Algorithm {
    Rsa3072,
    EcdsaP256,
    Gost2012_256,
    Gost2012_512,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Usage {
    Server,
    Client,
    Both,
}

#[derive(Debug, Args)]
pub struct Identity {
    /// Subject common name (1..64 UTF-8 bytes).
    #[arg(long)]
    cn: String,
    /// DNS SAN, repeat for multiple names. ASCII/punycode, optional leading *.
    #[arg(long)]
    dns: Vec<String>,
    /// IP SAN, repeat for multiple addresses.
    #[arg(long)]
    ip: Vec<IpAddr>,
    #[arg(long, value_enum, default_value = "server")]
    usage: Usage,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new unencrypted PKCS#8 PEM private key (0600, never overwrite).
    Keygen {
        #[arg(long, value_enum, default_value = "rsa3072")]
        algorithm: Algorithm,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a PKCS#10 CSR with an existing PEM key; send only the CSR to your CA.
    Csr {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[command(flatten)]
        identity: Identity,
    },
    /// Create a self-signed end-entity certificate (CA:FALSE) from an existing key.
    SelfSigned {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 365, value_parser = clap::value_parser!(u32).range(1..=3650))]
        days: u32,
        #[command(flatten)]
        identity: Identity,
    },
}

pub fn run(command: &Command) -> Result<()> {
    #[cfg(all(feature = "tls", not(feature = "legacy-kernel")))]
    {
        enabled::run(command)
    }
    #[cfg(any(not(feature = "tls"), feature = "legacy-kernel"))]
    {
        let _ = command;
        anyhow::bail!("PKI generation requires a modern binary built with tls or tls-gost");
    }
}

#[cfg(all(feature = "tls", not(feature = "legacy-kernel")))]
mod enabled {
    use super::*;
    use anyhow::{Context, bail, ensure};
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{Id, PKey, Private},
        rsa::Rsa,
        stack::Stack,
        x509::{
            X509, X509Extension, X509Name, X509Req,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };
    use std::os::unix::fs::OpenOptionsExt;
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        path::Path,
    };

    fn initialize() -> Result<()> {
        openssl::init();
        #[cfg(feature = "tls-gost")]
        crate::transport::initialize_gost()?;
        Ok(())
    }

    #[cfg(feature = "tls-gost")]
    fn gost_id(bits: u32) -> Result<Id> {
        unsafe extern "C" {
            fn OBJ_txt2nid(name: *const std::ffi::c_char) -> std::ffi::c_int;
        }
        let name = if bits == 256 {
            c"gost2012_256"
        } else {
            c"gost2012_512"
        };
        // SAFETY: static NUL-terminated names; OpenSSL is initialized by run().
        let nid = unsafe { OBJ_txt2nid(name.as_ptr()) };
        ensure!(nid > 0, "GOST key algorithm is unavailable");
        Ok(Id::from_raw(nid))
    }

    #[cfg(feature = "tls-gost")]
    fn gost_key(bits: u32) -> Result<PKey<Private>> {
        use foreign_types::ForeignType;
        use openssl::pkey_ctx::PkeyCtx;
        unsafe extern "C" {
            fn EVP_PKEY_CTX_ctrl_str(
                ctx: *mut std::ffi::c_void,
                name: *const std::ffi::c_char,
                value: *const std::ffi::c_char,
            ) -> std::ffi::c_int;
        }
        let mut ctx = PkeyCtx::new_id(gost_id(bits)?)?;
        ctx.keygen_init()?;
        // SAFETY: ctx owns a live OpenSSL EVP_PKEY_CTX; strings are static.
        let status = unsafe {
            EVP_PKEY_CTX_ctrl_str(ctx.as_ptr().cast(), c"paramset".as_ptr(), c"A".as_ptr())
        };
        ensure!(
            status > 0,
            "set GOST parameter set A: {}",
            openssl::error::ErrorStack::get()
        );
        Ok(ctx.keygen()?)
    }

    fn generate(algorithm: Algorithm) -> Result<PKey<Private>> {
        Ok(match algorithm {
            Algorithm::Rsa3072 => PKey::from_rsa(Rsa::generate(3072)?)?,
            Algorithm::EcdsaP256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                PKey::from_ec_key(EcKey::generate(&group)?)?
            }
            Algorithm::Gost2012_256 | Algorithm::Gost2012_512 => {
                #[cfg(feature = "tls-gost")]
                {
                    gost_key(if matches!(algorithm, Algorithm::Gost2012_256) {
                        256
                    } else {
                        512
                    })?
                }
                #[cfg(not(feature = "tls-gost"))]
                bail!("GOST key generation requires a tls-gost binary");
            }
        })
    }

    fn digest(key: &PKey<Private>) -> Result<MessageDigest> {
        if key.id() == Id::RSA || key.id() == Id::EC {
            return Ok(MessageDigest::sha256());
        }
        #[cfg(feature = "tls-gost")]
        for bits in [256, 512] {
            if key.id() == gost_id(bits)? {
                return MessageDigest::from_name(if bits == 256 {
                    "md_gost12_256"
                } else {
                    "md_gost12_512"
                })
                .context("GOST signing digest unavailable");
            }
        }
        bail!("unsupported signing key: use RSA, ECDSA or GOST-2012");
    }

    fn load_key(path: &Path) -> Result<PKey<Private>> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .with_context(|| format!("open key {}", path.display()))?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "key file exceeds 1 MiB");
        // Never invoke OpenSSL's interactive password prompt.
        PKey::private_key_from_pem_callback(&bytes, |_| Err(openssl::error::ErrorStack::get()))
            .context("read unencrypted PEM private key (encrypted keys are unsupported)")
    }

    fn validate_identity(identity: &Identity) -> Result<()> {
        ensure!(
            !identity.cn.trim().is_empty()
                && identity.cn.len() <= 64
                && !identity.cn.chars().any(char::is_control),
            "CN must contain 1..64 UTF-8 bytes and no control characters"
        );
        ensure!(
            identity.dns.len() + identity.ip.len() <= 100,
            "at most 100 SANs are allowed"
        );
        if matches!(identity.usage, Usage::Server | Usage::Both) {
            ensure!(
                !identity.dns.is_empty() || !identity.ip.is_empty(),
                "server certificates/CSRs require at least one --dns or --ip SAN"
            );
        }
        for name in &identity.dns {
            let host = name.strip_prefix("*.").unwrap_or(name);
            ensure!(
                name.is_ascii()
                    && name.len() <= 253
                    && host.parse::<IpAddr>().is_err()
                    && host.split('.').all(|label| !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')),
                "invalid DNS SAN {name:?}; use ASCII/punycode names or --ip for IP addresses"
            );
        }
        Ok(())
    }

    fn subject(identity: &Identity) -> Result<X509Name> {
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", &identity.cn)?;
        Ok(name.build())
    }

    fn extensions(identity: &Identity, key: &PKey<Private>) -> Result<Stack<X509Extension>> {
        let mut extensions = Stack::new()?;
        extensions.push(BasicConstraints::new().critical().build()?)?; // CA:FALSE
        let mut usage = KeyUsage::new();
        usage.critical().digital_signature();
        if key.id() == Id::RSA {
            usage.key_encipherment();
        } else if key.id() != Id::EC {
            usage.key_agreement();
        }
        extensions.push(usage.build()?)?;
        let mut eku = ExtendedKeyUsage::new();
        if matches!(identity.usage, Usage::Server | Usage::Both) {
            eku.server_auth();
        }
        if matches!(identity.usage, Usage::Client | Usage::Both) {
            eku.client_auth();
        }
        extensions.push(eku.build()?)?;
        if !identity.dns.is_empty() || !identity.ip.is_empty() {
            let req = X509Req::builder()?;
            let mut san = SubjectAlternativeName::new();
            for dns in &identity.dns {
                san.dns(dns);
            }
            for ip in &identity.ip {
                san.ip(&ip.to_string());
            }
            extensions.push(san.build(&req.x509v3_context(None))?)?;
        }
        Ok(extensions)
    }

    /// Single output per invocation: reserve exclusively before writing any bytes.
    fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| {
                format!(
                    "create {} (existing files are never overwritten)",
                    path.display()
                )
            })?;
        // On IO failure retain the reserved file; a later invocation must not
        // overwrite a potentially partial key without explicit operator action.
        output.write_all(bytes).context("write PEM output")?;
        output.sync_all().context("sync PEM output")?;
        println!("Created {}", path.display());
        Ok(())
    }

    pub fn run(command: &Command) -> Result<()> {
        initialize()?;
        match command {
            Command::Keygen { algorithm, out } => {
                let key = generate(*algorithm).context("generate private key")?;
                save_new(out, &key.private_key_to_pem_pkcs8()?)
            }
            Command::Csr { key, out, identity } => {
                validate_identity(identity)?;
                let key = load_key(key)?;
                let mut csr = X509Req::builder()?;
                csr.set_version(0)?;
                let name = subject(identity)?;
                csr.set_subject_name(&name)?;
                csr.set_pubkey(&key)?;
                let requested = extensions(identity, &key)?;
                csr.add_extensions(&requested)?;
                csr.sign(&key, digest(&key)?)?;
                let csr = csr.build();
                ensure!(
                    csr.verify(&key)?,
                    "generated CSR signature verification failed"
                );
                save_new(out, &csr.to_pem()?)
            }
            Command::SelfSigned {
                key,
                out,
                days,
                identity,
            } => {
                validate_identity(identity)?;
                let key = load_key(key)?;
                let mut cert = X509::builder()?;
                cert.set_version(2)?;
                let mut serial = BigNum::new()?;
                serial.rand(159, MsbOption::ONE, false)?;
                let serial = serial.to_asn1_integer()?;
                cert.set_serial_number(&serial)?;
                let name = subject(identity)?;
                cert.set_subject_name(&name)?;
                cert.set_issuer_name(&name)?;
                cert.set_pubkey(&key)?;
                let not_before = Asn1Time::days_from_now(0)?;
                let not_after = Asn1Time::days_from_now(*days)?;
                cert.set_not_before(&not_before)?;
                cert.set_not_after(&not_after)?;
                for extension in extensions(identity, &key)? {
                    cert.append_extension(extension)?;
                }
                cert.sign(&key, digest(&key)?)?;
                let cert = cert.build();
                ensure!(
                    cert.verify(&key)?,
                    "generated certificate signature verification failed"
                );
                save_new(out, &cert.to_pem()?)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn identity(dns: &[&str], ip: &[&str], usage: Usage) -> Identity {
            Identity {
                cn: "test".into(),
                dns: dns.iter().map(|s| (*s).into()).collect(),
                ip: ip.iter().map(|s| s.parse().unwrap()).collect(),
                usage,
            }
        }
        #[test]
        fn rejects_extension_injection_and_invalid_dns() {
            for name in [
                "example.org,IP:1.2.3.4",
                "bad\nname",
                "a..b",
                "-bad",
                "bad-",
                "127.0.0.1",
                "@section",
                "a_b",
                "é.fr",
                "*.*.org",
            ] {
                assert!(
                    validate_identity(&identity(&[name], &[], Usage::Server)).is_err(),
                    "{name:?}"
                );
            }
            assert!(
                validate_identity(&identity(
                    &["*.example.org", "localhost", "xn--e1afmkfd.xn--p1ai"],
                    &["::1"],
                    Usage::Server
                ))
                .is_ok()
            );
        }
        #[test]
        fn server_requires_san_but_client_can_use_subject() {
            assert!(validate_identity(&identity(&[], &[], Usage::Server)).is_err());
            assert!(validate_identity(&identity(&[], &[], Usage::Both)).is_err());
            assert!(validate_identity(&identity(&[], &[], Usage::Client)).is_ok());
        }
    }
}
