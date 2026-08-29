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
#include <algorithm>

#define BUFFER_SIZE 4096

std::mutex clients_mutex;
std::map<std::string, int> user_to_socket;
std::map<int, std::string> socket_to_user;

void send_to_socket(int sock, const std::string& msg) {
    std::string data = msg;
    if (data.empty() || data.back() != '\n') {
        data += "\n";
    }
    send(sock, data.c_str(), data.length(), 0);
}

void handle_client(int client_sock, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "[INFO] New connection from " << client_ip << ":" << client_port << " (socket " << client_sock << ")" << std::endl;

    std::string recv_buffer = "";
    char buffer[BUFFER_SIZE];
    std::string username = "";

    // 1. Initial registration: First message must be REGISTER <username>
    while (username.empty()) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            close(client_sock);
            return;
        }

        recv_buffer += std::string(buffer, bytes_read);
        size_t newline_pos = recv_buffer.find('\n');
        if (newline_pos != std::string::npos) {
            std::string line = recv_buffer.substr(0, newline_pos);
            recv_buffer.erase(0, newline_pos + 1);

            // Trim CR if present
            if (!line.empty() && line.back() == '\r') line.pop_back();

            std::istringstream iss(line);
            std::string cmd, req_user;
            iss >> cmd >> req_user;

            if (cmd == "REGISTER" && !req_user.empty()) {
                std::lock_guard<std::mutex> lock(clients_mutex);
                if (user_to_socket.find(req_user) != user_to_socket.end()) {
                    send_to_socket(client_sock, "ERROR: Username already taken.");
                } else {
                    username = req_user;
                    user_to_socket[username] = client_sock;
                    socket_to_user[client_sock] = username;
                    send_to_socket(client_sock, "OK: Registered as " + username);
                    std::cout << "[REGISTRATION] Client on socket " << client_sock << " registered as '" << username << "'" << std::endl;
                }
            } else {
                send_to_socket(client_sock, "ERROR: Please register first with REGISTER <username>");
            }
        }
    }

    // 2. Main message relay and command loop
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            std::cout << "[DISCONNECT] User '" << username << "' disconnected." << std::endl;
            break;
        }

        recv_buffer += std::string(buffer, bytes_read);
        size_t newline_pos;
        while ((newline_pos = recv_buffer.find('\n')) != std::string::npos) {
            std::string line = recv_buffer.substr(0, newline_pos);
            recv_buffer.erase(0, newline_pos + 1);

            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            if (line == "/who") {
                std::lock_guard<std::mutex> lock(clients_mutex);
                std::string list_msg = "[ONLINE USERS] ";
                for (auto const& [usr, sock] : user_to_socket) {
                    list_msg += usr + " ";
                }
                send_to_socket(client_sock, list_msg);
            } else if (line == "/quit") {
                send_to_socket(client_sock, "[SERVER] Goodbye!");
                goto cleanup;
            } else if (line.rfind("@", 0) == 0) {
                // Relayed chat message: @recipient_user message_content
                size_t space_pos = line.find(' ');
                if (space_pos == std::string::npos) {
                    send_to_socket(client_sock, "ERROR: Message format should be @username <message>");
                    continue;
                }
                std::string recipient = line.substr(1, space_pos - 1);
                std::string msg_content = line.substr(space_pos + 1);

                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = user_to_socket.find(recipient);
                if (it != user_to_socket.end()) {
                    int recipient_sock = it->second;
                    // Phase 1 Requirement: Log every relayed message on the server
                    std::cout << "[RELAY] From [" << username << "] to [" << recipient << "]: " << msg_content << std::endl;
                    send_to_socket(recipient_sock, "FROM @" + username + ": " + msg_content);
                } else {
                    send_to_socket(client_sock, "ERROR: User @" + recipient + " is not online.");
                }
            } else {
                send_to_socket(client_sock, "ERROR: Unrecognized command or message format. Use @username <msg>, /who, or /quit");
            }
        }
    }

cleanup:
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        user_to_socket.erase(username);
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

    std::cout << "========================================" << std::endl;
    std::cout << "   CS6008 Phase 1 Plaintext Chat Server" << std::endl;
    std::cout << "   Listening on port: " << port << std::endl;
    std::cout << "========================================" << std::endl;

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
