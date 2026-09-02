#include "crypto.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bool recv_line(int sock, std::string& line) {
    line.clear();
    char ch;
    while (true) {
        ssize_t r = recv(sock, &ch, 1, 0);
        if (r <= 0) return false;
        if (ch == '\n') break;
        if (ch != '\r') line += ch;
    }
    return true;
}

bool send_line(int sock, const std::string& line) {
    std::string data = line + "\n";
    return send(sock, data.c_str(), data.length(), 0) == (ssize_t)data.length();
}

void handle_mitm_attempt(int client_sock, std::string cert_file, std::string key_file, bool stolen_cert_mode) {
    std::cout << "\n\033[1;33m[MALLORY] Victim client connected! Attempting Phase 3 MITM bypass...\033[0m" << std::endl;
    if (stolen_cert_mode) {
        std::cout << "[MALLORY] Attack Strategy: Using STOLEN legitimate 'server.crt' but Mallory's own private key (Testing Proof-of-Possession defense)" << std::endl;
    } else {
        std::cout << "[MALLORY] Attack Strategy: Using Mallory's self-signed fake certificate (Testing Root CA validation defense)" << std::endl;
    }

    // 1. Receive client challenge nonce
    std::string nonce_line;
    if (!recv_line(client_sock, nonce_line) || nonce_line.rfind("NONCE ", 0) != 0) {
        close(client_sock);
        return;
    }
    std::string nonce = nonce_line.substr(6);

    // 2. Generate Mallory DH keypair
    DHExchange dh;
    dh.generate_keypair();
    std::string mallory_dh_pub = dh.get_public_key_hex();

    // 3. Mallory signs challenge with Mallory's key (since Mallory does not have real server.key)
    std::string sig_hex;
    rsa_sign_data(nonce + mallory_dh_pub, key_file, sig_hex);

    // 4. Send certificate (fake or stolen), signature, and DH public key to victim client
    std::string cert_pem = read_file_to_string(cert_file);
    send_line(client_sock, "CERT_BEGIN");
    send(client_sock, cert_pem.c_str(), cert_pem.length(), 0);
    send_line(client_sock, "CERT_END");
    send_line(client_sock, "SIG " + sig_hex);
    send_line(client_sock, "DH_PUB " + mallory_dh_pub);

    // 5. Wait for client response
    std::string client_resp;
    if (!recv_line(client_sock, client_resp) || client_resp.empty()) {
        std::cout << "\033[1;32m[MITM ATTACK DEFEATED] Client rejected Mallory's certificate/PoP and closed the socket immediately!\033[0m" << std::endl;
        std::cout << "[MALLORY] Attack failed. No keys derived, zero plaintext intercepted.\n" << std::endl;
    } else {
        std::cout << "[MALLORY] Client unexpectedly sent data: " << client_resp << std::endl;
    }
    close(client_sock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <listen_port> [--stolen-cert]" << std::endl;
        std::cerr << "  (Default): Tests fake certificate rejection (CA validation)." << std::endl;
        std::cerr << "  --stolen-cert: Tests Proof-of-Possession rejection using real server.crt + Mallory key." << std::endl;
        return 1;
    }

    int listen_port = std::atoi(argv[1]);
    bool stolen_cert_mode = (argc >= 3 && std::string(argv[2]) == "--stolen-cert");

    std::string cert_file = stolen_cert_mode ? "server.crt" : "fake_server.crt";
    std::string key_file = "fake_server.key";

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_sock, 5);

    std::cout << "==================================================" << std::endl;
    std::cout << "   CS6008 Phase 3 Attack Test Tool (Mallory)" << std::endl;
    std::cout << "   Listening on port: " << listen_port << std::endl;
    std::cout << "   Mode: " << (stolen_cert_mode ? "Proof-of-Possession Bypass Attempt" : "Fake CA Certificate Attack") << std::endl;
    std::cout << "==================================================" << std::endl;

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &len);
        if (client_sock < 0) continue;

        handle_mitm_attempt(client_sock, cert_file, key_file, stolen_cert_mode);
    }

    close(listen_sock);
    return 0;
}
