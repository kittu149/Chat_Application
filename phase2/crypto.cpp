#include "crypto.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// RFC 3526 2048-bit MODP Group 14
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
    // Generate 2048-bit private key
    if (!BN_rand(priv_key, 2048, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        return false;
    }
    // Compute public key A = g^a mod p using modular exponentiation
    if (!BN_mod_exp(pub_key, g, priv_key, p, ctx)) {
        return false;
    }
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
    // Compute s = B^a mod p
    if (!BN_mod_exp(shared_secret, peer_pub, priv_key, p, ctx)) {
        BN_free(peer_pub);
        BN_free(shared_secret);
        return false;
    }

    int secret_len = BN_num_bytes(shared_secret);
    std::vector<unsigned char> secret_bytes(secret_len);
    BN_bn2bin(shared_secret, secret_bytes.data());

    // Derive 256-bit symmetric AES key by hashing the raw shared secret
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

bool aes_gcm_encrypt(const std::string& plaintext, 
                     const std::vector<unsigned char>& key,
                     std::vector<unsigned char>& out_packet) {
    const int IV_LEN = 12;
    const int TAG_LEN = 16;

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
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

    // Format: [12-byte IV] + [16-byte Tag] + [Ciphertext]
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

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
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

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Finalize decryption (performs integrity check)
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        // Tag verification failed or payload tampered!
        return false;
    }
    total_plain_len += outlen;
    out_plaintext.assign((char*)plaintext.data(), total_plain_len);
    return true;
}

bool send_encrypted_packet(int sock, const std::string& plaintext, const std::vector<unsigned char>& key, bool tamper) {
    std::vector<unsigned char> packet;
    if (!aes_gcm_encrypt(plaintext, key, packet)) return false;

    if (tamper && packet.size() > 28) {
        // Intentionally tamper with the last byte of ciphertext
        packet.back() ^= 0xFF;
        std::cout << "[SECURITY TEST] Tampered with ciphertext byte before sending!" << std::endl;
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

    if (!aes_gcm_decrypt(packet, key, out_plaintext)) {
        std::cerr << "\n[ALERT] AES-GCM Integrity Check Failed! Packet tampered with or corrupted." << std::endl;
        return false;
    }
    return true;
}
