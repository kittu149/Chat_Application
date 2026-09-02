#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// RFC 3526 2048-bit MODP Group (Group 14) Prime and Generator
extern const char* RFC3526_MODP_2048_PRIME;
extern const char* RFC3526_MODP_2048_GEN;

class DHExchange {
public:
    DHExchange();
    ~DHExchange();

    // Generate DH private key and compute public key A = g^a mod p
    bool generate_keypair();
    std::string get_public_key_hex() const;

    // Compute shared secret s = B^a mod p and derive 256-bit AES key via SHA-256
    bool compute_shared_key(const std::string& peer_pub_hex, std::vector<unsigned char>& out_aes_key);

    // Compute SHA-256 fingerprint of the derived key for logging
    static std::string get_fingerprint_hex(const std::vector<unsigned char>& key);

private:
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* priv_key;
    BIGNUM* pub_key;
    BN_CTX* ctx;
};

// AES-256-GCM authenticated encryption/decryption
bool aes_gcm_encrypt(const std::string& plaintext, 
                     const std::vector<unsigned char>& key,
                     std::vector<unsigned char>& out_packet);

bool aes_gcm_decrypt(const std::vector<unsigned char>& packet, 
                     const std::vector<unsigned char>& key,
                     std::string& out_plaintext);

// Network send/receive helpers for length-prefixed encrypted packets
bool send_encrypted_packet(int sock, const std::string& plaintext, const std::vector<unsigned char>& key, bool tamper = false);
bool recv_encrypted_packet(int sock, std::string& out_plaintext, const std::vector<unsigned char>& key);

// Hex encoding utilities
std::string to_hex(const unsigned char* data, size_t len);

#endif // CRYPTO_H
