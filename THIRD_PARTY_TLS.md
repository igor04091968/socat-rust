# TLS dependencies

Optional TLS support uses the Rust openssl crate (Apache-2.0) and tokio-openssl (MIT/Apache-2.0)
and OpenSSL 3.5.9 (Apache-2.0). Optional GOST support statically links
https://github.com/gost-engine/engine at af2b7e69e855572202420ffc36bae06ccd70796b
(Apache-2.0, upstream copyright notices apply).

Release bundles include the upstream OpenSSL and GOST license texts.
Linux UAPI headers are build inputs from linux-libc-dev and retain their
upstream licensing/syscall exception; they are not a runtime dependency.
No CryptoPro CSP code, license or certification is included.
