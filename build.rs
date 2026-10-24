fn main() {
    println!("cargo:rerun-if-env-changed=GOST_STATIC_LIB_DIR");
    if std::env::var_os("CARGO_FEATURE_TLS_GOST").is_some() {
        let dir = std::env::var("GOST_STATIC_LIB_DIR")
            .expect("tls-gost requires GOST_STATIC_LIB_DIR containing a static libgost.a; external engine loading is unsupported");
        assert!(
            std::path::Path::new(&dir).join("libgost.a").is_file(),
            "GOST_STATIC_LIB_DIR/libgost.a not found"
        );
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=static=gost");
    }
}
