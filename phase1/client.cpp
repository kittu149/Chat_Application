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

#define BUFFER_SIZE 4096

std::atomic<bool> is_running(true);
std::string current_chat_partner = "";

void send_message(int sock, const std::string& msg) {
    std::string data = msg;
    if (data.empty() || data.back() != '\n') {
        data += "\n";
    }
    send(sock, data.c_str(), data.length(), 0);
}

void receive_handler(int sock) {
    char buffer[BUFFER_SIZE];
    std::string recv_buf = "";

    while (is_running) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            if (is_running) {
                std::cout << "\n[INFO] Disconnected from server." << std::endl;
                is_running = false;
            }
            break;
        }

        recv_buf += std::string(buffer, bytes_read);
        size_t newline_pos;
        while ((newline_pos = recv_buf.find('\n')) != std::string::npos) {
            std::string line = recv_buf.substr(0, newline_pos);
            recv_buf.erase(0, newline_pos + 1);

            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) {
                std::cout << "\n" << line << std::endl;
                std::cout << "> " << std::flush;
            }
        }
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

    std::cout << "[INFO] Connected to server at " << server_ip << ":" << port << std::endl;

    // Send initial registration
    send_message(sock, "REGISTER " + username);

    // Start background receiver thread
    std::thread receiver_thread(receive_handler, sock);

    std::cout << "==================================================" << std::endl;
    std::cout << "  Commands:" << std::endl;
    std::cout << "    @username <msg>  - Send message & set active chat" << std::endl;
    std::cout << "    /chat <username> - Switch active chat partner" << std::endl;
    std::cout << "    /who             - List online users" << std::endl;
    std::cout << "    /quit            - Disconnect and exit" << std::endl;
    std::cout << "==================================================" << std::endl;

    std::string input;
    while (is_running) {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, input)) {
            break;
        }

        if (input.empty()) continue;

        if (input == "/quit") {
            send_message(sock, "/quit");
            is_running = false;
            break;
        } else if (input == "/who") {
            send_message(sock, "/who");
        } else if (input.rfind("/chat ", 0) == 0) {
            std::string target = input.substr(6);
            // Trim leading/trailing whitespace
            size_t first = target.find_first_not_of(" \t");
            if (first != std::string::npos) {
                target = target.substr(first);
                current_chat_partner = target;
                std::cout << "[INFO] Chat partner switched to @" << current_chat_partner << std::endl;
            } else {
                std::cout << "[ERROR] Usage: /chat <username>" << std::endl;
            }
        } else if (input.rfind("@", 0) == 0) {
            // e.g. @bob hello there
            size_t space_pos = input.find(' ');
            if (space_pos != std::string::npos) {
                std::string target = input.substr(1, space_pos - 1);
                current_chat_partner = target;
                send_message(sock, input);
            } else {
                std::cout << "[ERROR] Format: @username <message>" << std::endl;
            }
        } else {
            // Plain chat message to current partner
            if (current_chat_partner.empty()) {
                std::cout << "[ERROR] No active chat partner selected. Use @username <msg> or /chat <username>" << std::endl;
            } else {
                std::string framed_msg = "@" + current_chat_partner + " " + input;
                send_message(sock, framed_msg);
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
