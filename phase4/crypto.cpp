#include "crypto.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

const char* RFC3526_MODP_2048_PRIME = 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF95ADDF83B377402D3B938D879FE120B4450E72C4119047"
    "94C01C9A149171C941D683A3C08985172C9B90D85A7E97B4"
    "812836262B51F808791054E6D24A2ED84DF12B0053E7350A"
    "25A0F5B73142277CF79A52A084EBE89F172289658E1B73F5"
    "DA6554D8C4301B5D2A57DFAC6AC412356B24E7989C82A2E6"
    "886B8FA2186536F76E5EC2F2698D0B75878CA58A46B5D708"
    "B9F150041231644A143922D774CB07289EC1CE782F485B07"
    "3F8A6498F4F507F54B0EE5B64E8C96578C0084323E73E77E"
    "312B104F34A61159C247B62A4CD480F25A07DC034C08D639"
    "58737D8D905A6916B82811A1B437B4C8360662A62C6A9280"
    "F358C895C274E865F375F11F1C18B6327663A0F5A13AC849"
    "2B94A97240E8160B5B11B283E71630132BFBFD938720892B"
    "0F97DD839D688279D20A102D71A8E300EF070D7C9862804A"
    "A567D0B702DF4FEA48135832C3A8242A580DFB1A1267469B"
    "147C85ED66B08630A7B0CD8E832049A4C03B0D2D252277B5"
    "F6675B8B14545550A4E3DE8BFEF90E1F46A9260451AEFA4E"
    "11762CD6BE2709A979B64DDDE7DDDF9CB551F0D44AE1E8B8"
    "FB9C0D30438FDFE8B42867FDD4B8133527D72E1AE2160DE5"
    "CD1C15EE0C8E192994B62FA60D04875D35C7A9F438640C3B"
    "3A65F5E4E302FB82";

const char* RFC3526_MODP_2048_GEN = "2";

DHExchange::DHExchange() {
    ctx = BN_CTX_new();
    p = BN_new();
    g = BN_new();
    priv_key = BN_new();
    pub_key = BN_new();
    BN_hex2bn(&p, RFC3526_MODP_2048_PRIME);
    BN_dec2bn(&g, RFC3526_MODP_2048_GEN);
}

DHExchange::~DHExchange() {
    BN_free(p);
    BN_free(g);
    BN_free(priv_key);
    BN_free(pub_key);
    BN_CTX_free(ctx);
}

bool DHExchange::generate_keypair() {
    if (!BN_rand(priv_key, 2048, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) return false;
    if (!BN_mod_exp(pub_key, g, priv_key, p, ctx)) return false;
    return true;
}

std::string DHExchange::get_public_key_hex() const {
    char* hex = BN_bn2hex(pub_key);
    std::string res(hex);
    OPENSSL_free(hex);
    return res;
}

bool DHExchange::compute_shared_key(const std::string& peer_pub_hex, std::vector<unsigned char>& out_aes_key) {
    BIGNUM* peer_pub = BN_new();
    if (!BN_hex2bn(&peer_pub, peer_pub_hex.c_str())) {
        BN_free(peer_pub);
        return false;
    }

    BIGNUM* shared_secret = BN_new();
    if (!BN_mod_exp(shared_secret, peer_pub, priv_key, p, ctx)) {
        BN_free(peer_pub);
        BN_free(shared_secret);
        return false;
    }

    int secret_len = BN_num_bytes(shared_secret);
    std::vector<unsigned char> secret_bytes(secret_len);
    BN_bn2bin(shared_secret, secret_bytes.data());

    out_aes_key.resize(SHA256_DIGEST_LENGTH);
    SHA256(secret_bytes.data(), secret_bytes.size(), out_aes_key.data());

    BN_free(peer_pub);
    BN_free(shared_secret);
    return true;
}

std::string DHExchange::get_fingerprint_hex(const std::vector<unsigned char>& key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(key.data(), key.size(), hash);
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string generate_random_nonce(size_t len) {
    std::vector<unsigned char> buf(len);
    RAND_bytes(buf.data(), len);
    return to_hex(buf.data(), len);
}

std::string read_file_to_string(const std::string& filepath) {
    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs.is_open()) return "";
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

bool aes_gcm_encrypt(const std::string& plaintext, 
                     const std::vector<unsigned char>& key,
                     std::vector<unsigned char>& out_packet) {
    const int IV_LEN = 12;
    const int TAG_LEN = 16;

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen = 0;
    std::vector<unsigned char> ciphertext(plaintext.length() + 16);
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, 
                          (const unsigned char*)plaintext.data(), plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_ciphertext_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_ciphertext_len += outlen;
    ciphertext.resize(total_ciphertext_len);

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    out_packet.clear();
    out_packet.insert(out_packet.end(), iv, iv + IV_LEN);
    out_packet.insert(out_packet.end(), tag, tag + TAG_LEN);
    out_packet.insert(out_packet.end(), ciphertext.begin(), ciphertext.end());
    return true;
}

bool aes_gcm_decrypt(const std::vector<unsigned char>& packet, 
                     const std::vector<unsigned char>& key,
                     std::string& out_plaintext) {
    const int IV_LEN = 12;
    const int TAG_LEN = 16;
    if (packet.size() < (size_t)(IV_LEN + TAG_LEN)) return false;

    const unsigned char* iv = packet.data();
    const unsigned char* tag = packet.data() + IV_LEN;
    const unsigned char* ciphertext = packet.data() + IV_LEN + TAG_LEN;
    int ciphertext_len = packet.size() - IV_LEN - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen = 0;
    std::vector<unsigned char> plaintext(ciphertext_len + 16);
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_plain_len = outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return false;

    total_plain_len += outlen;
    out_plaintext.assign((char*)plaintext.data(), total_plain_len);
    return true;
}

bool send_encrypted_packet(int sock, const std::string& plaintext, const std::vector<unsigned char>& key, bool tamper) {
    std::vector<unsigned char> packet;
    if (!aes_gcm_encrypt(plaintext, key, packet)) return false;

    if (tamper && packet.size() > 28) {
        packet.back() ^= 0xFF;
    }

    uint32_t len = htonl(packet.size());
    if (send(sock, &len, sizeof(len), 0) != sizeof(len)) return false;
    if (send(sock, packet.data(), packet.size(), 0) != (ssize_t)packet.size()) return false;
    return true;
}

bool recv_encrypted_packet(int sock, std::string& out_plaintext, const std::vector<unsigned char>& key) {
    uint32_t net_len = 0;
    ssize_t r = recv(sock, &net_len, sizeof(net_len), MSG_WAITALL);
    if (r <= 0) return false;

    uint32_t len = ntohl(net_len);
    std::vector<unsigned char> packet(len);
    r = recv(sock, packet.data(), len, MSG_WAITALL);
    if (r <= 0 || (size_t)r != len) return false;

    return aes_gcm_decrypt(packet, key, out_plaintext);
}

bool validate_certificate(const std::string& cert_pem, const std::string& ca_file, const std::string& expected_cn, std::string& out_error) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.length());
    if (!bio) return false;

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        out_error = "Failed to parse PEM certificate.";
        return false;
    }

    X509_STORE* store = X509_STORE_new();
    if (!store || X509_STORE_load_locations(store, ca_file.c_str(), NULL) != 1) {
        X509_free(cert);
        if (store) X509_STORE_free(store);
        out_error = "Could not load CA file: " + ca_file;
        return false;
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx || X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        X509_free(cert);
        X509_STORE_free(store);
        if (ctx) X509_STORE_CTX_free(ctx);
        return false;
    }

    if (X509_verify_cert(ctx) != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        out_error = X509_verify_cert_error_string(err);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        return false;
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    X509_NAME* subj = X509_get_subject_name(cert);
    char cn_buf[256] = {0};
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn_buf, sizeof(cn_buf) - 1);

    if (!expected_cn.empty() && std::string(cn_buf) != expected_cn) {
        out_error = "CN mismatch! Expected '" + expected_cn + "', got '" + std::string(cn_buf) + "'";
        X509_free(cert);
        return false;
    }

    X509_free(cert);
    return true;
}

bool rsa_sign_data(const std::string& data, const std::string& priv_key_file, std::string& out_sig_hex) {
    FILE* fp = fopen(priv_key_file.c_str(), "r");
    if (!fp) return false;

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return false;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestSignUpdate(mdctx, data.data(), data.size()) != 1) {
        if (mdctx) EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    size_t siglen = 0;
    EVP_DigestSignFinal(mdctx, NULL, &siglen);
    std::vector<unsigned char> sig(siglen);
    EVP_DigestSignFinal(mdctx, sig.data(), &siglen);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    out_sig_hex = to_hex(sig.data(), siglen);
    return true;
}

bool rsa_verify_signature(const std::string& data, const std::string& cert_pem, const std::string& sig_hex) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.length());
    if (!bio) return false;

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return false;

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey) return false;

    std::vector<unsigned char> sig = from_hex(sig_hex);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestVerifyUpdate(mdctx, data.data(), data.size()) != 1) {
        if (mdctx) EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int ret = EVP_DigestVerifyFinal(mdctx, sig.data(), sig.size());
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return (ret == 1);
}
