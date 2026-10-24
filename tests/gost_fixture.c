/* Synthetic GOST PKI fixture generator; never accepts production key material. */
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
extern void ENGINE_load_gost(void);

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}
static void initialize_engine(void) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    ENGINE_load_gost();
    ENGINE *e = ENGINE_by_id("gost");
    if (e == NULL || ENGINE_init(e) != 1 || ENGINE_set_default(e, ENGINE_METHOD_ALL) != 1)
        fail("static GOST initialization failed");
    ENGINE_finish(e);
    ENGINE_free(e);
}
static EVP_PKEY *new_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2012_256, NULL);
    EVP_PKEY *key = NULL;
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "A") != 1 || EVP_PKEY_keygen(ctx, &key) != 1)
        fail("generate GOST2012 key");
    EVP_PKEY_CTX_free(ctx);
    return key;
}
static void extension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (ext == NULL || X509_add_ext(cert, ext, -1) != 1) fail("add X509 extension");
    X509_EXTENSION_free(ext);
}
static X509 *certificate(EVP_PKEY *key, const char *name, X509 *issuer,
                         EVP_PKEY *issuer_key, int ca, int expired, long serial) {
    X509 *cert = X509_new();
    if (cert == NULL || X509_set_version(cert, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1 ||
        X509_set_pubkey(cert, key) != 1) fail("create X509 certificate");
    X509_gmtime_adj(X509_getm_notBefore(cert), -3600L * 48);
    X509_gmtime_adj(X509_getm_notAfter(cert), expired ? -3600L : 3600L * 48);
    X509_NAME *subject = X509_get_subject_name(cert);
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                 (const unsigned char *)name, -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert, issuer ? X509_get_subject_name(issuer) : subject) != 1)
        fail("set X509 names");
    extension(cert, issuer ? issuer : cert, NID_basic_constraints,
              ca ? "critical,CA:TRUE,pathlen:0" : "critical,CA:FALSE");
    extension(cert, issuer ? issuer : cert, NID_key_usage,
              ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyAgreement");
    if (!ca) {
        extension(cert, issuer, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
        extension(cert, issuer, NID_ext_key_usage, "serverAuth,clientAuth");
    }
    const EVP_MD *md = EVP_get_digestbyname("md_gost12_256");
    if (!md || X509_sign(cert, issuer_key ? issuer_key : key, md) <= 0) fail("GOST sign X509");
    return cert;
}
static void save(const char *dir, const char *name, EVP_PKEY *key, X509 *cert) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s.key", dir, name);
    FILE *fp = fopen(path, "w");
    if (!fp || PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1) fail("save synthetic private key");
    fclose(fp);
    chmod(path, 0600);
    snprintf(path, sizeof(path), "%s/%s.pem", dir, name);
    fp = fopen(path, "w");
    if (!fp || PEM_write_X509(fp, cert) != 1) fail("save synthetic certificate");
    fclose(fp);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    initialize_engine();
    EVP_PKEY *ca_key = new_key();
    X509 *ca = certificate(ca_key, "Synthetic GOST CA", NULL, NULL, 1, 0, 1);
    save(argv[1], "ca", ca_key, ca);
    const char *names[] = {"server", "client", "expired"};
    for (int i = 0; i < 3; ++i) {
        EVP_PKEY *key = new_key();
        X509 *cert = certificate(key, names[i], ca, ca_key, 0, i == 2, i + 2);
        save(argv[1], names[i], key, cert);
        X509_free(cert); EVP_PKEY_free(key);
    }
    X509_free(ca); EVP_PKEY_free(ca_key);
    puts("synthetic GOST PKI generated");
    return 0;
}
