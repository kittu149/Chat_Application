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
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <username>" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::atoi(argv[2]);
    std::string username = argv[3];

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
    std::cout << "[CRYPTO] Initiating Diffie-Hellman Key Exchange..." << std::endl;

    // 1. Perform Diffie-Hellman Key Exchange from scratch
    DHExchange dh;
    if (!dh.generate_keypair()) {
        std::cerr << "[ERROR] Failed to generate DH keypair." << std::endl;
        close(sock);
        return 1;
    }

    // Send Client Public Key A
    if (!send_line(sock, dh.get_public_key_hex())) {
        std::cerr << "[ERROR] Failed to send DH public key." << std::endl;
        close(sock);
        return 1;
    }

    // Receive Server Public Key B
    std::string server_pub_hex;
    if (!recv_line(sock, server_pub_hex)) {
        std::cerr << "[ERROR] Failed to receive server DH public key." << std::endl;
        close(sock);
        return 1;
    }

    // Compute shared secret and AES-256 key
    if (!dh.compute_shared_key(server_pub_hex, session_key)) {
        std::cerr << "[ERROR] Failed to compute DH shared key." << std::endl;
        close(sock);
        return 1;
    }

    std::string key_fp = DHExchange::get_fingerprint_hex(session_key);
    std::cout << "[CRYPTO] Diffie-Hellman Key Exchange Complete!" << std::endl;
    std::cout << "         Session Key Fingerprint: " << key_fp << std::endl;

    // 2. Encrypted Registration
    if (!send_encrypted_packet(sock, "REGISTER " + username, session_key)) {
        std::cerr << "[ERROR] Failed to send registration." << std::endl;
        close(sock);
        return 1;
    }

    // Start background receiver thread
    std::thread receiver_thread(receive_handler, sock);

    std::cout << "==================================================" << std::endl;
    std::cout << "  Commands:" << std::endl;
    std::cout << "    @username <msg>  - Send encrypted message to user" << std::endl;
    std::cout << "    /chat <username> - Switch active chat partner" << std::endl;
    std::cout << "    /who             - List online users" << std::endl;
    std::cout << "    /tamper <msg>    - Send tampered ciphertext (Tamper Test)" << std::endl;
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
        } else if (input.rfind("/tamper ", 0) == 0) {
            std::string msg = input.substr(8);
            if (current_chat_partner.empty()) {
                std::cout << "[ERROR] Select a chat partner first using /chat <username>" << std::endl;
            } else {
                std::string framed_msg = "@" + current_chat_partner + " " + msg;
                std::cout << "[TEST] Sending intentionally tampered ciphertext to test AES-GCM integrity..." << std::endl;
                send_encrypted_packet(sock, framed_msg, session_key, /*tamper=*/true);
            }
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
