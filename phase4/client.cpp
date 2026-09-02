#include "crypto.h"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>

std::atomic<bool> is_running(true);
std::string current_chat_partner = "";
std::vector<unsigned char> link_session_key; // Client <-> Server AES key

// Active End-to-End Keys: peer_username -> 256-bit AES Key
std::mutex e2e_mutex;
std::map<std::string, std::vector<unsigned char>> e2e_keys;
std::map<std::string, std::shared_ptr<DHExchange>> pending_e2e_dh;

int g_sock = -1;

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

void handle_incoming_relayed_message(const std::string& sender, const std::string& payload) {
    const std::string TAG_INIT = "__E2E_INIT__";
    const std::string TAG_ACK  = "__E2E_ACK__";
    const std::string TAG_MSG  = "__E2E_MSG__";

    // 1. Handshake Init from peer
    if (payload.rfind(TAG_INIT, 0) == 0) {
        std::string peer_pub_hex = payload.substr(TAG_INIT.length());
        auto dh = std::make_shared<DHExchange>();
        if (!dh->generate_keypair()) return;

        std::vector<unsigned char> derived_e2e_key;
        if (!dh->compute_shared_key(peer_pub_hex, derived_e2e_key)) return;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            e2e_keys[sender] = derived_e2e_key;
        }

        std::string fp = DHExchange::get_fingerprint_hex(derived_e2e_key);
        std::cout << "\n\033[1;32m[E2E] Established End-to-End session with @" << sender << "!\033[0m" << std::endl;
        std::cout << "\033[1;32m      E2E Key Fingerprint: " << fp << "\033[0m" << std::endl;
        std::cout << "> " << std::flush;

        // Reply with ACK containing our DH public key
        std::string ack_payload = "@" + sender + " " + TAG_ACK + dh->get_public_key_hex();
        send_encrypted_packet(g_sock, ack_payload, link_session_key);
        return;
    }

    // 2. Handshake ACK from peer
    if (payload.rfind(TAG_ACK, 0) == 0) {
        std::string peer_pub_hex = payload.substr(TAG_ACK.length());
        std::shared_ptr<DHExchange> dh = nullptr;
        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = pending_e2e_dh.find(sender);
            if (it != pending_e2e_dh.end()) {
                dh = it->second;
                pending_e2e_dh.erase(it);
            }
        }

        if (dh) {
            std::vector<unsigned char> derived_e2e_key;
            if (dh->compute_shared_key(peer_pub_hex, derived_e2e_key)) {
                {
                    std::lock_guard<std::mutex> lock(e2e_mutex);
                    e2e_keys[sender] = derived_e2e_key;
                }
                std::string fp = DHExchange::get_fingerprint_hex(derived_e2e_key);
                std::cout << "\n\033[1;32m[E2E] Established End-to-End session with @" << sender << "!\033[0m" << std::endl;
                std::cout << "\033[1;32m      E2E Key Fingerprint: " << fp << "\033[0m" << std::endl;
                std::cout << "> " << std::flush;
            }
        }
        return;
    }

    // 3. E2E Encrypted Chat Message
    if (payload.rfind(TAG_MSG, 0) == 0) {
        std::string hex_cipher = payload.substr(TAG_MSG.length());
        std::vector<unsigned char> cipher_packet = from_hex(hex_cipher);
        std::vector<unsigned char> key;
        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = e2e_keys.find(sender);
            if (it != e2e_keys.end()) key = it->second;
        }

        if (!key.empty()) {
            std::string decrypted_msg;
            if (aes_gcm_decrypt(cipher_packet, key, decrypted_msg)) {
                std::cout << "\n\033[1;36m[E2E ENCRYPTED] FROM @" << sender << ": " << decrypted_msg << "\033[0m" << std::endl;
            } else {
                std::cout << "\n\033[1;31m[E2E ALERT] Failed to decrypt E2E message from @" << sender << " (Tamper or key mismatch)\033[0m" << std::endl;
            }
        } else {
            std::cout << "\n[E2E ERROR] Received E2E message from @" << sender << " but no E2E key is established. Run /e2e " << sender << std::endl;
        }
        std::cout << "> " << std::flush;
        return;
    }

    // 4. Plain / Hop-by-Hop Message (Before E2E)
    std::cout << "\nFROM @" << sender << ": " << payload << std::endl;
    std::cout << "> " << std::flush;
}

void receive_handler(int sock) {
    while (is_running) {
        std::string raw_msg;
        if (!recv_encrypted_packet(sock, raw_msg, link_session_key)) {
            if (is_running) {
                std::cout << "\n[INFO] Disconnected from server." << std::endl;
                is_running = false;
            }
            break;
        }

        if (raw_msg.rfind("FROM @", 0) == 0) {
            size_t colon_pos = raw_msg.find(": ");
            if (colon_pos != std::string::npos) {
                std::string sender = raw_msg.substr(6, colon_pos - 6);
                std::string payload = raw_msg.substr(colon_pos + 2);
                handle_incoming_relayed_message(sender, payload);
                continue;
            }
        }

        // Server control messages / online list
        std::cout << "\n" << raw_msg << std::endl;
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

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    if (connect(g_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(g_sock);
        return 1;
    }

    std::cout << "[INFO] Connected to " << server_ip << ":" << port << std::endl;

    // 1. Certificate & PoP Exchange (Phase 3 Authentication)
    std::string client_nonce = generate_random_nonce(32);
    send_line(g_sock, "NONCE " + client_nonce);

    std::string header_line;
    if (!recv_line(g_sock, header_line) || header_line != "CERT_BEGIN") {
        close(g_sock);
        return 1;
    }

    std::string cert_pem = "";
    while (true) {
        std::string line;
        if (!recv_line(g_sock, line) || line == "CERT_END") break;
        cert_pem += line + "\n";
    }

    std::string sig_line, dh_pub_line;
    if (!recv_line(g_sock, sig_line) || sig_line.rfind("SIG ", 0) != 0 ||
        !recv_line(g_sock, dh_pub_line) || dh_pub_line.rfind("DH_PUB ", 0) != 0) {
        close(g_sock);
        return 1;
    }
    std::string server_sig_hex = sig_line.substr(4);
    std::string server_dh_pub = dh_pub_line.substr(7);

    std::string pki_err;
    if (!validate_certificate(cert_pem, ca_file, expected_cn, pki_err) ||
        !rsa_verify_signature(client_nonce + server_dh_pub, cert_pem, server_sig_hex)) {
        std::cerr << "[PKI / PoP ERROR] Server authentication failed!" << std::endl;
        close(g_sock);
        return 1;
    }
    std::cout << "[PKI] Server authenticated via PKI & Proof-of-Possession!" << std::endl;

    // 2. Client-Server DH Link Key Establishment
    DHExchange link_dh;
    link_dh.generate_keypair();
    send_line(g_sock, "DH_PUB " + link_dh.get_public_key_hex());
    link_dh.compute_shared_key(server_dh_pub, link_session_key);
    std::cout << "[CRYPTO] Link Key Fingerprint: " << DHExchange::get_fingerprint_hex(link_session_key) << std::endl;

    // 3. Register
    send_encrypted_packet(g_sock, "REGISTER " + username, link_session_key);

    std::thread receiver_thread(receive_handler, g_sock);

    std::cout << "==================================================" << std::endl;
    std::cout << "  Phase 4 Commands:" << std::endl;
    std::cout << "    /e2e <username>  - Start End-to-End Encryption with user" << std::endl;
    std::cout << "    @username <msg>  - Send message to user" << std::endl;
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
            send_encrypted_packet(g_sock, "/quit", link_session_key);
            is_running = false;
            break;
        } else if (input == "/who") {
            send_encrypted_packet(g_sock, "/who", link_session_key);
        } else if (input.rfind("/e2e ", 0) == 0) {
            std::string target = input.substr(5);
            size_t first = target.find_first_not_of(" \t");
            if (first != std::string::npos) target = target.substr(first);

            auto dh = std::make_shared<DHExchange>();
            if (!dh->generate_keypair()) {
                std::cout << "[ERROR] Could not generate DH keypair for E2E." << std::endl;
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                pending_e2e_dh[target] = dh;
            }

            current_chat_partner = target;
            std::cout << "[E2E] Initiating End-to-End handshake with @" << target << "..." << std::endl;
            std::string init_msg = "@" + target + " __E2E_INIT__" + dh->get_public_key_hex();
            send_encrypted_packet(g_sock, init_msg, link_session_key);
        } else if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);
            size_t first = target.find_first_not_of(" \t");
            if (first != std::string::npos) {
                current_chat_partner = target.substr(first);
                std::cout << "[INFO] Chat partner switched to @" << current_chat_partner << std::endl;
            }
        } else {
            std::string target = current_chat_partner;
            std::string msg_text = input;

            if (input.rfind("@", 0) == 0) {
                size_t space_pos = input.find(' ');
                if (space_pos != std::string::npos) {
                    target = input.substr(1, space_pos - 1);
                    msg_text = input.substr(space_pos + 1);
                    current_chat_partner = target;
                }
            }

            if (target.empty()) {
                std::cout << "[ERROR] No active chat partner selected. Use /chat <username> or /e2e <username>" << std::endl;
                continue;
            }

            // Check if E2E session exists with target
            std::vector<unsigned char> target_e2e_key;
            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                auto it = e2e_keys.find(target);
                if (it != e2e_keys.end()) target_e2e_key = it->second;
            }

            if (!target_e2e_key.empty()) {
                // Encrypt with E2E key first, then wrap as __E2E_MSG__<hex>
                std::vector<unsigned char> e2e_packet;
                aes_gcm_encrypt(msg_text, target_e2e_key, e2e_packet);
                std::string wire_msg = "@" + target + " __E2E_MSG__" + to_hex(e2e_packet.data(), e2e_packet.size());
                send_encrypted_packet(g_sock, wire_msg, link_session_key);
            } else {
                // Send plain hop-by-hop message
                std::string wire_msg = "@" + target + " " + msg_text;
                send_encrypted_packet(g_sock, wire_msg, link_session_key);
            }
        }
    }

    is_running = false;
    close(g_sock);
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }
    return 0;
}
