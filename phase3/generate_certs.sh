#!/bin/bash
set -e

echo "=== Generating PKI Certificates for CS6008 Phase 3 ==="

# 1. Generate Root CA Private Key and Self-Signed Certificate
echo "[1/4] Generating Root CA (ca.key & ca.crt)..."
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=CS6008/OU=Security/CN=CS6008 Root CA"

# 2. Generate Chat Server Key Pair and CSR
echo "[2/4] Generating Chat Server Key & CSR (server.key & server.csr)..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=CS6008/OU=ChatServer/CN=chat.server.local"

# 3. Sign the Server Certificate using the Root CA
echo "[3/4] Signing Server Certificate with Root CA (server.crt)..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365

# 4. Generate Mallory's Fake Certificate (for MITM attack demonstration)
echo "[4/4] Generating Attacker Fake Certificate (fake_server.key & fake_server.crt)..."
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout fake_server.key -out fake_server.crt \
    -subj "/C=US/ST=State/L=City/O=MalloryCorp/OU=Hacker/CN=chat.server.local"

echo "=== Certificate Generation Complete ==="
echo "Files created:"
echo "  - ca.crt (Distribute to Clients)"
echo "  - server.crt, server.key (Use on Server VM)"
echo "  - fake_server.crt, fake_server.key (Use on Mallory VM)"
