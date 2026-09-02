# Phase 3: Server Authentication via PKI & Proof-of-Possession

This directory implements **Phase 3** of the Secure Chat Application:
* Local **Public Key Infrastructure (PKI)** using OpenSSL: Root Certificate Authority (CA) and CA-signed Server Certificate.
* Client-side **X.509 Certificate Validation** (Signature validity, expiration dates, Common Name verification).
* **Proof-of-Possession (PoP)** mechanism using RSA digital signatures over a dynamic challenge nonce.
* **Defeating the Phase 2 MITM Attack** and verifying PoP bypass rejection.

---

## 🛠️ Step 1: Generate Certificates
Make the generation script executable and run it:

```bash
cd phase3
chmod +x generate_certs.sh
./generate_certs.sh
```

This creates:
* `ca.crt` (Root CA public cert — distribute to Client VMs)
* `server.crt` & `server.key` (Used by the Server VM)
* `fake_server.crt` & `fake_server.key` (Used by Mallory for attack tests)

---

## 🔨 Step 2: Build the Binaries
```bash
make
```

---

## 🚀 Step 3: Legitimate Execution (Authenticated Flow)

### 1. Start Authenticated Server (`VM-Server`):
```bash
./server 8080 server.crt server.key
```

### 2. Connect Client (`VM-Client1`):
```bash
./client <SERVER_IP> 8080 alice ca.crt chat.server.local
```

### Expected Output:
```text
[PKI VALIDATION PASSED] Server certificate signed by trusted Root CA for CN='chat.server.local'
[PoP VERIFICATION PASSED] Server proved possession of private key matching certificate!
[CRYPTO] DH Session Key Established! Fingerprint: 8a7c2b...
```

---

## 🛡️ Step 4: Attack Verification (Defeating MITM)

### Attack Test A: Mallory with Untrusted Certificate
1. Start Mallory on `VM-Mallory`:
   ```bash
   ./mallory_proxy 8080
   ```
2. Point Client to Mallory:
   ```bash
   ./client <MALLORY_IP> 8080 alice ca.crt chat.server.local
   ```
3. **Result:** Client displays `[PKI VALIDATION FAILED] Certificate verification failed: self-signed certificate` and aborts immediately without starting DH. Take a screenshot for the report!

### Attack Test B: Stolen Certificate & Proof-of-Possession Bypass Attempt
1. Start Mallory with the `--stolen-cert` flag:
   ```bash
   ./mallory_proxy 8080 --stolen-cert
   ```
2. Connect Client to Mallory:
   ```bash
   ./client <MALLORY_IP> 8080 alice ca.crt chat.server.local
   ```
3. **Result:** Client validates the CA signature on `server.crt`, BUT detects that the RSA challenge signature does not match the certificate's public key (`[PoP VERIFICATION FAILED]`). Connection is terminated immediately.
