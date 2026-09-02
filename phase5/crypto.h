#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

extern const char* RFC3526_MODP_2048_PRIME;
extern const char* RFC3526_MODP_2048_GEN;

class DHExchange {
public:
    DHExchange();
    ~DHExchange();

    bool generate_keypair();
    std::string get_public_key_hex() const;
    bool compute_shared_key(const std::string& peer_pub_hex, std::vector<unsigned char>& out_aes_key);
    static std::string get_fingerprint_hex(const std::vector<unsigned char>& key);

private:
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* priv_key;
    BIGNUM* pub_key;
    BN_CTX* ctx;
};

bool aes_gcm_encrypt(const std::string& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& out_packet);
bool aes_gcm_decrypt(const std::vector<unsigned char>& packet, const std::vector<unsigned char>& key, std::string& out_plaintext);
bool send_encrypted_packet(int sock, const std::string& plaintext, const std::vector<unsigned char>& key, bool tamper = false);
bool recv_encrypted_packet(int sock, std::string& out_plaintext, const std::vector<unsigned char>& key);

std::string read_file_to_string(const std::string& filepath);
bool validate_certificate(const std::string& cert_pem, const std::string& ca_file, const std::string& expected_cn, std::string& out_error);
bool rsa_sign_data(const std::string& data, const std::string& priv_key_file, std::string& out_sig_hex);
bool rsa_verify_signature(const std::string& data, const std::string& cert_pem, const std::string& sig_hex);

std::string to_hex(const unsigned char* data, size_t len);
std::vector<unsigned char> from_hex(const std::string& hex);
std::string generate_random_nonce(size_t len = 32);

#endif // CRYPTO_H
