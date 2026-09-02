#include "crypto.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

std::atomic<bool> is_running(true);
std::string current_chat_partner = "";
std::vector<unsigned char> session_key;

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

void receive_handler(int sock) {
    while (is_running) {
        std::string msg;
        if (!recv_encrypted_packet(sock, msg, session_key)) {
            if (is_running) {
                std::cout << "\n[INFO] Connection lost or session terminated." << std::endl;
                is_running = false;
            }
            break;
        }

        std::cout << "\n" << msg << std::endl;
        std::cout << "> " << std::flush;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <username> [ca_file=ca.crt] [expected_cn=chat.server.local]" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::atoi(argv[2]);
    std::string username = argv[3];
    std::string ca_file = (argc >= 5) ? argv[4] : "ca.crt";
    std::string expected_cn = (argc >= 6) ? argv[5] : "chat.server.local";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        return 1;
    }

    std::cout << "[INFO] Connected to " << server_ip << ":" << port << std::endl;
    std::cout << "[PKI] Initiating Certificate Exchange & Proof-of-Possession validation..." << std::endl;

    // 1. Send Fresh Challenge Nonce
    std::string client_nonce = generate_random_nonce(32);
    send_line(sock, "NONCE " + client_nonce);

    // 2. Receive Server Certificate PEM
    std::string header_line;
    if (!recv_line(sock, header_line) || header_line != "CERT_BEGIN") {
        std::cerr << "[SECURITY ERROR] Failed to receive server certificate header." << std::endl;
        close(sock);
        return 1;
    }

    std::string cert_pem = "";
    while (true) {
        std::string line;
        if (!recv_line(sock, line)) {
            std::cerr << "[SECURITY ERROR] Truncated certificate received." << std::endl;
            close(sock);
            return 1;
        }
        if (line == "CERT_END") break;
        cert_pem += line + "\n";
    }

    // 3. Receive Server PoP Signature and DH Public Key
    std::string sig_line, dh_pub_line;
    if (!recv_line(sock, sig_line) || sig_line.rfind("SIG ", 0) != 0 ||
        !recv_line(sock, dh_pub_line) || dh_pub_line.rfind("DH_PUB ", 0) != 0) {
        std::cerr << "[SECURITY ERROR] Malformed signature or DH public key from server." << std::endl;
        close(sock);
        return 1;
    }
    std::string server_sig_hex = sig_line.substr(4);
    std::string server_dh_pub = dh_pub_line.substr(7);

    // 4. Validate Certificate against Trusted CA and Expected CN
    std::string pki_error;
    if (!validate_certificate(cert_pem, ca_file, expected_cn, pki_error)) {
        std::cerr << "\n\033[1;31m[PKI VALIDATION FAILED] " << pki_error << "\033[0m" << std::endl;
        std::cerr << "\033[1;31m[ABORT] Terminating connection immediately without proceeding to DH!\033[0m\n" << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "\033[1;32m[PKI VALIDATION PASSED] Server certificate signed by trusted Root CA for CN='" << expected_cn << "'\033[0m" << std::endl;

    // 5. Verify Proof-of-Possession (PoP) Signature
    std::string data_to_verify = client_nonce + server_dh_pub;
    if (!rsa_verify_signature(data_to_verify, cert_pem, server_sig_hex)) {
        std::cerr << "\n\033[1;31m[PoP VERIFICATION FAILED] Server could not prove possession of the certificate's private key!\033[0m" << std::endl;
        std::cerr << "\033[1;31m[ABORT] Potential impostor/replay attack. Terminating connection.\033[0m\n" << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "\033[1;32m[PoP VERIFICATION PASSED] Server proved possession of private key matching certificate!\033[0m" << std::endl;

    // 6. Proceed to Diffie-Hellman Key Exchange
    DHExchange dh;
    if (!dh.generate_keypair()) {
        std::cerr << "[ERROR] Failed to generate client DH keypair." << std::endl;
        close(sock);
        return 1;
    }

    send_line(sock, "DH_PUB " + dh.get_public_key_hex());

    if (!dh.compute_shared_key(server_dh_pub, session_key)) {
        std::cerr << "[ERROR] Failed to compute DH shared key." << std::endl;
        close(sock);
        return 1;
    }

    std::string key_fp = DHExchange::get_fingerprint_hex(session_key);
    std::cout << "[CRYPTO] DH Session Key Established! Fingerprint: " << key_fp << std::endl;

    // 7. Secure Registration & Chat CLI
    send_encrypted_packet(sock, "REGISTER " + username, session_key);

    std::thread receiver_thread(receive_handler, sock);

    std::cout << "==================================================" << std::endl;
    std::cout << "  Commands:" << std::endl;
    std::cout << "    @username <msg>  - Send encrypted message to user" << std::endl;
    std::cout << "    /chat <username> - Switch active chat partner" << std::endl;
    std::cout << "    /who             - List online users" << std::endl;
    std::cout << "    /quit            - Disconnect and exit" << std::endl;
    std::cout << "==================================================" << std::endl;

    std::string input;
    while (is_running) {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, input)) break;
        if (input.empty()) continue;

        if (input == "/quit") {
            send_encrypted_packet(sock, "/quit", session_key);
            is_running = false;
            break;
        } else if (input == "/who") {
            send_encrypted_packet(sock, "/who", session_key);
        } else if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);
            size_t first = target.find_first_not_of(" \t");
            if (first != std::string::npos) {
                current_chat_partner = target.substr(first);
                std::cout << "[INFO] Active chat partner switched to @" << current_chat_partner << std::endl;
            }
        } else if (input.rfind("@", 0) == 0) {
            size_t space_pos = input.find(' ');
            if (space_pos != std::string::npos) {
                current_chat_partner = input.substr(1, space_pos - 1);
                send_encrypted_packet(sock, input, session_key);
            } else {
                std::cout << "[ERROR] Format: @username <message>" << std::endl;
            }
        } else {
            if (current_chat_partner.empty()) {
                std::cout << "[ERROR] No active chat partner. Use @username <msg> or /chat <username>" << std::endl;
            } else {
                std::string framed_msg = "@" + current_chat_partner + " " + input;
                send_encrypted_packet(sock, framed_msg, session_key);
            }
        }
    }

    is_running = false;
    close(sock);
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }

    std::cout << "[INFO] Client exited cleanly." << std::endl;
    return 0;
}
