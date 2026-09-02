# Phase 2: Client–Server Confidentiality via Diffie–Hellman & AES-GCM

This directory implements **Phase 2** of the Secure Chat Application:
* **From-scratch Diffie–Hellman** key exchange using OpenSSL `BIGNUM` modular exponentiation ($g^a \bmod p$) on **RFC 3526 Group 14** (2048-bit prime).
* **Key Derivation** using SHA-256 (`SHA256(raw_shared_secret)`).
* **Authenticated Encryption** using **AES-256-GCM** with 12-byte random IVs and 16-byte authentication tags.
* **Tamper Detection** testing.
* **Man-in-the-Middle (MITM) Attack Proxy (`mallory_proxy`)**.

---

## 🛠️ Build Instructions
```bash
cd phase2
make
```
This produces three binaries:
* `server`
* `client`
* `mallory_proxy`

---

## 🚀 1. Normal Secure Operation (Server + Clients)

### Step 1: Start Server (`VM-Server`)
```bash
./server 8080
```

### Step 2: Start Clients (`VM-Client1` and `VM-Client2`)
```bash
# On VM-Client1:
./client <SERVER_IP> 8080 alice

# On VM-Client2:
./client <SERVER_IP> 8080 bob
```

### Step 3: Verify Key Fingerprints
Upon connection, both the client and the server print:
```text
[CRYPTO] Session Key Fingerprint: 4f8b9e...
```
* **Evidence for Report:** Take a screenshot confirming that the client and server computed the **exact identical fingerprint**.

### Step 4: Verify Wireshark (Ciphertext)
* Run Wireshark with filter `tcp.port == 8080`.
* Use **Follow $\rightarrow$ TCP Stream**.
* Confirm that chat content is now **unreadable encrypted ciphertext** instead of the plaintext from Phase 1.

---

## 🛡️ 2. Tamper-Detection Test (AES-GCM Integrity Verification)
In the client terminal, type:
```text
> /tamper Hello Alice!
```
* **What happens:** The client intentionally modifies/flips a byte in the encrypted ciphertext before sending it over TCP.
* **Expected Result:** The server's AES-GCM integrity tag check fails, OpenSSL returns an error, and the packet is rejected rather than producing corrupted plaintext.
* **Evidence for Report:** Capture the server log showing `[ALERT] AES-GCM Integrity Check Failed!`.

---

## 👿 3. Attack Task: Man-in-the-Middle (MITM) Execution

In this task, Mallory sits on `VM-Mallory` and intercepts the connection between a victim client and the server.

### Step 1: Start Real Server (`VM-Server`)
```bash
./server 8080
```

### Step 2: Start Mallory Proxy (`VM-Mallory`)
Run the proxy specifying: `<listen_port> <real_server_ip> <real_server_port>`
```bash
./mallory_proxy 8080 <SERVER_IP> 8080
```

### Step 3: Connect Victim Client to Mallory (`VM-Client1`)
Point the client to **Mallory's IP address** instead of the real server:
```bash
./client <MALLORY_IP> 8080 alice
```

### Step 4: Observe Intercepted Plaintext on Mallory's Screen
1. On `alice`'s client terminal, send a message: `@bob Top secret assignment info`.
2. Look at **`VM-Mallory`'s terminal**:
   ```text
   [MALLORY INTERCEPT] (Client -> Server): @bob Top secret assignment info
   ```
3. **Evidence for Report:** Capture a screenshot of Mallory's screen displaying the intercepted cleartext message while Alice and the Server believe they are securely communicating!
