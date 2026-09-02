# CS6008: Network Security --- Secure Chat Application

This repository contains the complete implementation, adversarial attack tools, empirical evidence, and final report for **Assignment 1: Building a Secure Chat Application** in **CS6008: Network Security**.

The project is structured into five evolutionary security phases, built from scratch in **C++17** using low-level POSIX sockets and OpenSSL cryptographic primitives, strictly adhering to course constraints (no high-level `<openssl/ssl.h>` or built-in `<openssl/dh.h>`).

---

## 📁 Repository Structure

```text
Chat_Application/
├── README.md               # Master project documentation (this file)
├── .gitignore              # Ignores compiled binaries, objects, and certs
├── phase1/                 # Phase 1: Baseline Multi-Threaded TCP Plaintext Chat
│   ├── server.cpp          # Central relay server with plaintext logging
│   ├── client.cpp          # Multi-threaded client CLI (@user, /chat, /who, /quit)
│   ├── Makefile            # Builds server and client
│   ├── README.md           # Execution & testing guide
│   └── screenshots/        # Evidence: Server logs, Wireshark packets & TCP stream
├── phase2/                 # Phase 2: Link Confidentiality & MITM Attack
│   ├── crypto.h / .cpp     # From-scratch DH (RFC 3526 Group 14) + SHA-256 KDF + AES-256-GCM
│   ├── server.cpp          # Server with link-level DH key exchange
│   ├── client.cpp          # Client with DH, AES-GCM & /tamper test command
│   ├── mallory_proxy.cpp   # Active dual-handshake MITM attack tool
│   ├── Makefile            # Builds server, client, mallory_proxy
│   ├── README.md           # Execution guide & attack demonstration
│   └── screenshots/        # Evidence: Fingerprint match, Wireshark ciphertext, Tamper alert, MITM intercept
├── phase3/                 # Phase 3: PKI Authentication & Proof-of-Possession
│   ├── generate_certs.sh   # Generates Root CA, Server Cert & CSR, Fake Attacker Cert
│   ├── crypto.h / .cpp     # X.509 certificate parsing/validation & RSA challenge-response PoP
│   ├── server.cpp          # Server presenting CA-signed cert & signing client nonces
│   ├── client.cpp          # Client validating cert chain, CN, validity dates & PoP signature
│   ├── mallory_proxy.cpp   # Tool testing fake cert rejection & stolen cert PoP bypass defeat
│   ├── Makefile            # Builds server, client, mallory_proxy
│   ├── README.md           # Execution guide & PKI setup instructions
│   └── screenshots/        # Evidence: OpenSSL CLI verify, PKI/PoP legit flow, Fake cert defeat, PoP defeat
├── phase4/                 # Phase 4: End-to-End Encryption (E2E)
│   ├── crypto.h / .cpp     # E2E crypto routines & double AES-GCM encapsulation
│   ├── server.cpp          # Zero-knowledge blind relay server
│   ├── client.cpp          # Client with /e2e, wire tags (__E2E_INIT__, __E2E_ACK__, __E2E_MSG__)
│   ├── generate_certs.sh   # Automated cert generation
│   ├── Makefile            # Builds server and client
│   ├── README.md           # Execution & server-blindness verification guide
│   └── screenshots/        # Evidence: Alice E2E, Bob E2E, Server blind relay logs (pre vs post E2E)
├── phase5/                 # Phase 5: Forward Secrecy via Key Rotation
│   ├── crypto.h / .cpp     # Ephemeral DH rekeying & secure memory zeroization (OPENSSL_cleanse)
│   ├── server.cpp          # Blind relay server supporting transparent rekeys
│   ├── client.cpp          # 60s periodic rekey timer, /rekey test, & lexicographical tie-breaker
│   ├── generate_certs.sh   # Automated cert generation
│   ├── Makefile            # Builds server and client
│   ├── README.md           # Execution & multi-rotation verification guide
│   └── screenshots/        # Evidence: Server relay, Alice 3 rotations, Bob 3 rotations + live chat
└── report/                 # Final Report Deliverable
    ├── report.tex          # Master publication-quality LaTeX document
    ├── report.pdf          # Compiled 12-page comprehensive submission PDF
    └── images/             # All 27 standardized screenshot figures embedded in the report
```

---

## 🖥️ Network Topology & Deployment Environment

The system is deployed and verified across four separate virtual machines (Ubuntu Linux) connected over a bridged virtual subnet:

| Node Role | VM IP Address | Port | Function |
| :--- | :--- | :--- | :--- |
| **Chat Server** | `192.168.1.126` | `8080` | Central relay, link-DH peer, and PKI target |
| **Client 1 (Alice)** | `192.168.1.124` | Dynamic | Initiating client node & E2E participant |
| **Client 2 (Bob)** | `192.168.1.123` | Dynamic | Peer client node & E2E participant |
| **Attacker (Mallory)** | `192.168.1.125` | `8080` | Active MITM proxy & attack verification tool |

---

## 🚀 Quick Execution Guide

### Phase 1: Baseline Plaintext Chat
```bash
# On Server:
cd phase1 && make && ./server 8080

# On Clients (Alice / Bob):
cd phase1 && make && ./client 192.168.1.126 8080 <username>
```

### Phase 2: Link Confidentiality & MITM
```bash
# On Server:
cd phase2 && make && ./server 8080

# On Client:
cd phase2 && make && ./client 192.168.1.126 8080 alice
# Test Tamper: /tamper <message>

# On Mallory (MITM Attack):
cd phase2 && make && ./mallory_proxy 8080 192.168.1.126 8080
```

### Phase 3: PKI Authentication & Proof-of-Possession
```bash
# Generate Certs on Server:
cd phase3 && ./generate_certs.sh && make
# (Copy ca.crt to clients; copy fake_server.crt/key and server.crt to Mallory)

# On Server:
./server 8080 server.crt server.key

# On Client:
./client 192.168.1.126 8080 alice ca.crt chat.server.local

# Mallory Defeat Tests:
./mallory_proxy 8080                 # Fake cert attack (defeated by client PKI)
./mallory_proxy 8080 --stolen-cert   # PoP bypass attack (defeated by client RSA verify)
```

### Phase 4: End-to-End Encryption
```bash
# On Server:
cd phase4 && ./generate_certs.sh && make && ./server 8080 server.crt server.key

# On Clients:
./client 192.168.1.126 8080 alice ca.crt chat.server.local
./client 192.168.1.126 8080 bob ca.crt chat.server.local

# In Alice terminal:
/e2e bob                             # Establishes E2E session
@bob Secret E2E message              # Encrypted with zero-knowledge server blindness
```

### Phase 5: Forward Secrecy via Key Rotation
```bash
# On Server:
cd phase5 && ./generate_certs.sh && make && ./server 8080 server.crt server.key

# On Clients:
./client 192.168.1.126 8080 alice ca.crt chat.server.local
./client 192.168.1.126 8080 bob ca.crt chat.server.local

# In Alice terminal:
/e2e bob                             # Auto-rekeys every 60s (or manually via /rekey)
```

---

## 📊 Summary of Deliverables \& Final Report

The final report is generated in LaTeX and compiled into a single comprehensive PDF:
* **LaTeX Source:** [`report/report.tex`](file:///Users/sushanthgunda/Desktop/cs%206008/assignment_1/Chat_Application/report/report.tex)
* **Compiled PDF:** [`report/report.pdf`](file:///Users/sushanthgunda/Desktop/cs%206008/assignment_1/Chat_Application/report/report.pdf)
* **Embedded Figures:** 27 high-resolution screenshots covering all empirical tests, server blindness proofs, tamper alerts, MITM interceptions, and attack defeat logs across all five phases.