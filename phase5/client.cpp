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
#include <chrono>
#include <ctime>
#include <iomanip>

std::atomic<bool> is_running(true);
std::string g_my_username = "";
std::string current_chat_partner = "";
std::vector<unsigned char> link_session_key; // Client <-> Server link key

struct E2ESession {
    std::vector<unsigned char> current_key;
    std::vector<unsigned char> previous_key; // Brief grace period for in-flight messages
    std::chrono::steady_clock::time_point last_rotation_time;
    std::chrono::steady_clock::time_point prev_key_expiry;
};

std::mutex e2e_mutex;
std::map<std::string, E2ESession> e2e_sessions;
std::map<std::string, std::shared_ptr<DHExchange>> pending_e2e_dh;

int g_sock = -1;

std::string get_current_timestamp_str() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void securely_wipe_key(std::vector<unsigned char>& key) {
    if (!key.empty()) {
        OPENSSL_cleanse(key.data(), key.size());
        key.clear();
    }
}

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

void initiate_e2e_rekey(const std::string& target) {
    auto dh = std::make_shared<DHExchange>();
    if (!dh->generate_keypair()) return;

    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        pending_e2e_dh[target] = dh;
    }

    std::string init_msg = "@" + target + " __E2E_INIT__" + dh->get_public_key_hex();
    send_encrypted_packet(g_sock, init_msg, link_session_key);
}

void handle_incoming_relayed_message(const std::string& sender, const std::string& payload) {
    const std::string TAG_INIT = "__E2E_INIT__";
    const std::string TAG_ACK  = "__E2E_ACK__";
    const std::string TAG_MSG  = "__E2E_MSG__";

    // 1. Handshake Init (Key Exchange or 60s Key Rotation)
    if (payload.rfind(TAG_INIT, 0) == 0) {
        std::string peer_pub_hex = payload.substr(TAG_INIT.length());

        // Collision Avoidance Check:
        // If both clients initiated rekey at the same time, tie-break lexicographically.
        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            if (pending_e2e_dh.find(sender) != pending_e2e_dh.end()) {
                if (g_my_username < sender) {
                    // Other user has higher username -> other user wins, we yield and reply with ACK
                    pending_e2e_dh.erase(sender);
                } else {
                    // We win -> Ignore peer's INIT, peer will yield and ACK our INIT
                    return;
                }
            }
        }

        auto dh = std::make_shared<DHExchange>();
        if (!dh->generate_keypair()) return;

        std::vector<unsigned char> new_key;
        if (!dh->compute_shared_key(peer_pub_hex, new_key)) return;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto& session = e2e_sessions[sender];
            if (!session.current_key.empty()) {
                session.previous_key = session.current_key;
                session.prev_key_expiry = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            }
            session.current_key = new_key;
            session.last_rotation_time = std::chrono::steady_clock::now();
        }

        std::string fp = DHExchange::get_fingerprint_hex(new_key);
        std::cout << "\n\033[1;32m[FORWARD SECRECY] [" << get_current_timestamp_str() << "] Key Established / Rotated with @" << sender << "!\033[0m" << std::endl;
        std::cout << "\033[1;32m                  New E2E Fingerprint: " << fp << "\033[0m" << std::endl;
        std::cout << "> " << std::flush;

        // Send ACK with our DH public key
        std::string ack_msg = "@" + sender + " " + TAG_ACK + dh->get_public_key_hex();
        send_encrypted_packet(g_sock, ack_msg, link_session_key);
        return;
    }

    // 2. Handshake ACK
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
            std::vector<unsigned char> new_key;
            if (dh->compute_shared_key(peer_pub_hex, new_key)) {
                {
                    std::lock_guard<std::mutex> lock(e2e_mutex);
                    auto& session = e2e_sessions[sender];
                    if (!session.current_key.empty()) {
                        session.previous_key = session.current_key;
                        session.prev_key_expiry = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                    }
                    session.current_key = new_key;
                    session.last_rotation_time = std::chrono::steady_clock::now();
                }

                std::string fp = DHExchange::get_fingerprint_hex(new_key);
                std::cout << "\n\033[1;32m[FORWARD SECRECY] [" << get_current_timestamp_str() << "] Key Established / Rotated with @" << sender << "!\033[0m" << std::endl;
                std::cout << "\033[1;32m                  New E2E Fingerprint: " << fp << "\033[0m" << std::endl;
                std::cout << "> " << std::flush;
            }
        }
        return;
    }

    // 3. E2E Encrypted Chat Message
    if (payload.rfind(TAG_MSG, 0) == 0) {
        std::string hex_cipher = payload.substr(TAG_MSG.length());
        std::vector<unsigned char> cipher_packet = from_hex(hex_cipher);
        std::vector<unsigned char> cur_key, prev_key;
        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = e2e_sessions.find(sender);
            if (it != e2e_sessions.end()) {
                cur_key = it->second.current_key;
                prev_key = it->second.previous_key;
            }
        }

        std::string decrypted_msg;
        bool success = false;
        if (!cur_key.empty() && aes_gcm_decrypt(cipher_packet, cur_key, decrypted_msg)) {
            success = true;
        } else if (!prev_key.empty() && aes_gcm_decrypt(cipher_packet, prev_key, decrypted_msg)) {
            // Decrypted using key in transit grace period
            success = true;
        }

        if (success) {
            std::cout << "\n\033[1;36m[E2E ENCRYPTED] FROM @" << sender << ": " << decrypted_msg << "\033[0m" << std::endl;
        } else {
            std::cout << "\n\033[1;31m[E2E ALERT] Failed to decrypt message from @" << sender << "\033[0m" << std::endl;
        }
        std::cout << "> " << std::flush;
        return;
    }

    std::cout << "\nFROM @" << sender << ": " << payload << std::endl;
    std::cout << "> " << std::flush;
}

void rekey_timer_thread() {
    while (is_running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (!is_running) break;

        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> sessions_to_rekey;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            for (auto& [user, session] : e2e_sessions) {
                // Wipe expired previous key
                if (!session.previous_key.empty() && now > session.prev_key_expiry) {
                    securely_wipe_key(session.previous_key);
                }

                // Check 60-second rotation interval
                if (std::chrono::duration_cast<std::chrono::seconds>(now - session.last_rotation_time).count() >= 60) {
                    // Only initiate if we don't have a pending DH for this user
                    if (pending_e2e_dh.find(user) == pending_e2e_dh.end()) {
                        sessions_to_rekey.push_back(user);
                    }
                }
            }
        }

        for (const auto& target : sessions_to_rekey) {
            std::cout << "\n[FORWARD SECRECY] 60s timer expired for @" << target << ". Triggering automatic rekey..." << std::endl;
            initiate_e2e_rekey(target);
            std::cout << "> " << std::flush;
        }
    }
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
    g_my_username = argv[3];
    std::string ca_file = (argc >= 5) ? argv[4] : "ca.crt";
    std::string expected_cn = (argc >= 6) ? argv[5] : "chat.server.local";

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    if (connect(g_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(g_sock);
        return 1;
    }

    std::cout << "[INFO] Connected to " << server_ip << ":" << port << std::endl;

    // 1. PKI & Proof-of-Possession Server Authentication
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
        std::cerr << "[PKI ERROR] Authentication failed!" << std::endl;
        close(g_sock);
        return 1;
    }

    // 2. Transport Link Key Establishment
    DHExchange link_dh;
    link_dh.generate_keypair();
    send_line(g_sock, "DH_PUB " + link_dh.get_public_key_hex());
    link_dh.compute_shared_key(server_dh_pub, link_session_key);

    // 3. Register
    send_encrypted_packet(g_sock, "REGISTER " + g_my_username, link_session_key);

    std::thread receiver_thread(receive_handler, g_sock);
    std::thread timer_thread(rekey_timer_thread);

    std::cout << "==================================================" << std::endl;
    std::cout << "  Phase 5 (Forward Secrecy) Commands:" << std::endl;
    std::cout << "    /e2e <username>  - Start E2E session with 60s auto-rekey" << std::endl;
    std::cout << "    /rekey           - Force immediate key rotation (testing)" << std::endl;
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
        } else if (input == "/rekey") {
            if (current_chat_partner.empty()) {
                std::cout << "[ERROR] Select an active E2E partner first." << std::endl;
            } else {
                std::cout << "[FORWARD SECRECY] Manually forcing immediate key rotation with @" << current_chat_partner << "..." << std::endl;
                initiate_e2e_rekey(current_chat_partner);
            }
        } else if (input.rfind("/e2e ", 0) == 0) {
            std::string target = input.substr(5);
            size_t first = target.find_first_not_of(" \t");
            if (first != std::string::npos) target = target.substr(first);
            current_chat_partner = target;
            std::cout << "[E2E] Initiating End-to-End session with @" << target << "..." << std::endl;
            initiate_e2e_rekey(target);
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
                std::cout << "[ERROR] No active chat partner. Use /e2e <username> or /chat <username>" << std::endl;
                continue;
            }

            std::vector<unsigned char> target_key;
            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                auto it = e2e_sessions.find(target);
                if (it != e2e_sessions.end()) target_key = it->second.current_key;
            }

            if (!target_key.empty()) {
                std::vector<unsigned char> e2e_packet;
                aes_gcm_encrypt(msg_text, target_key, e2e_packet);
                std::string wire_msg = "@" + target + " __E2E_MSG__" + to_hex(e2e_packet.data(), e2e_packet.size());
                send_encrypted_packet(g_sock, wire_msg, link_session_key);
            } else {
                std::string wire_msg = "@" + target + " " + msg_text;
                send_encrypted_packet(g_sock, wire_msg, link_session_key);
            }
        }
    }

    is_running = false;
    close(g_sock);
    if (timer_thread.joinable()) timer_thread.join();
    if (receiver_thread.joinable()) receiver_thread.join();
    return 0;
}
