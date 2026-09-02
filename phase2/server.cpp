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

struct ClientSession {
    int sock;
    std::string username;
    std::vector<unsigned char> key;
};

std::mutex sessions_mutex;
std::map<std::string, ClientSession> user_sessions;
std::map<int, std::string> socket_to_user;

// Helper to receive a single plain text line during initial DH handshake
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

// Helper to send a plain text line during initial DH handshake
bool send_line(int sock, const std::string& line) {
    std::string data = line + "\n";
    return send(sock, data.c_str(), data.length(), 0) == (ssize_t)data.length();
}

void handle_client(int client_sock, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "\n[INFO] New connection from " << client_ip << ":" << client_port << " (socket " << client_sock << ")" << std::endl;

    // 1. Perform Diffie-Hellman Key Exchange from scratch
    DHExchange dh;
    if (!dh.generate_keypair()) {
        std::cerr << "[ERROR] Failed to generate DH keypair for client." << std::endl;
        close(client_sock);
        return;
    }

    std::string client_pub_hex;
    if (!recv_line(client_sock, client_pub_hex)) {
        close(client_sock);
        return;
    }

    if (!send_line(client_sock, dh.get_public_key_hex())) {
        close(client_sock);
        return;
    }

    std::vector<unsigned char> session_key;
    if (!dh.compute_shared_key(client_pub_hex, session_key)) {
        std::cerr << "[ERROR] Failed to compute DH shared key." << std::endl;
        close(client_sock);
        return;
    }

    std::string key_fp = DHExchange::get_fingerprint_hex(session_key);
    std::cout << "[CRYPTO] DH exchange successful with socket " << client_sock << std::endl;
    std::cout << "         Session Key Fingerprint: " << key_fp << std::endl;

    // 2. Encrypted Registration Loop
    std::string username = "";
    while (username.empty()) {
        std::string req;
        if (!recv_encrypted_packet(client_sock, req, session_key)) {
            close(client_sock);
            return;
        }

        std::istringstream iss(req);
        std::string cmd, req_user;
        iss >> cmd >> req_user;

        if (cmd == "REGISTER" && !req_user.empty()) {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            if (user_sessions.find(req_user) != user_sessions.end()) {
                send_encrypted_packet(client_sock, "ERROR: Username already taken.", session_key);
            } else {
                username = req_user;
                user_sessions[username] = {client_sock, username, session_key};
                socket_to_user[client_sock] = username;
                send_encrypted_packet(client_sock, "OK: Registered as " + username, session_key);
                std::cout << "[REGISTRATION] Client on socket " << client_sock << " registered as '" << username << "'" << std::endl;
            }
        } else {
            send_encrypted_packet(client_sock, "ERROR: Please register first with REGISTER <username>", session_key);
        }
    }

    // 3. Main Encrypted Message and Command Relay Loop
    while (true) {
        std::string msg;
        if (!recv_encrypted_packet(client_sock, msg, session_key)) {
            std::cout << "[DISCONNECT] User '" << username << "' disconnected or session terminated." << std::endl;
            break;
        }

        if (msg == "/who") {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            std::string list_msg = "[ONLINE USERS] ";
            for (auto const& [usr, sess] : user_sessions) {
                list_msg += usr + " ";
            }
            send_encrypted_packet(client_sock, list_msg, session_key);
        } else if (msg == "/quit") {
            send_encrypted_packet(client_sock, "[SERVER] Goodbye!", session_key);
            goto cleanup;
        } else if (msg.rfind("@", 0) == 0) {
            size_t space_pos = msg.find(' ');
            if (space_pos == std::string::npos) {
                send_encrypted_packet(client_sock, "ERROR: Message format should be @username <message>", session_key);
                continue;
            }
            std::string recipient = msg.substr(1, space_pos - 1);
            std::string msg_content = msg.substr(space_pos + 1);

            std::lock_guard<std::mutex> lock(sessions_mutex);
            auto it = user_sessions.find(recipient);
            if (it != user_sessions.end()) {
                // Server decrypts with sender key, logs, and re-encrypts with recipient's independent key
                std::cout << "[RELAY] From [" << username << "] to [" << recipient << "]: " << msg_content << std::endl;
                send_encrypted_packet(it->second.sock, "FROM @" + username + ": " + msg_content, it->second.key);
            } else {
                send_encrypted_packet(client_sock, "ERROR: User @" + recipient + " is not online.", session_key);
            }
        } else {
            send_encrypted_packet(client_sock, "ERROR: Invalid format. Use @username <msg>, /who, /quit", session_key);
        }
    }

cleanup:
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        user_sessions.erase(username);
        socket_to_user.erase(client_sock);
    }
    close(client_sock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    int port = std::atoi(argv[1]);
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 10) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }

    std::cout << "==================================================" << std::endl;
    std::cout << "   CS6008 Phase 2 Secure Chat Server (DH+AES-GCM)" << std::endl;
    std::cout << "   Listening on port: " << port << std::endl;
    std::cout << "==================================================" << std::endl;

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        std::thread(handle_client, client_sock, client_addr).detach();
    }

    close(server_sock);
    return 0;
}
