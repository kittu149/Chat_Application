# Phase 4: End-to-End (E2E) Encryption Between Clients

This directory implements **Phase 4** of the Secure Chat Application:
* **Client-to-Client Diffie–Hellman** key exchange over an untrusted/semi-trusted relay server.
* **Wire-Level Tagging Protocol:**
  * `__E2E_INIT__<pub_key>` (Handshake initialization triggered by `/e2e <username>`)
  * `__E2E_ACK__<pub_key>` (Handshake acknowledgment)
  * `__E2E_MSG__<ciphertext_hex>` (Direct client-to-client AES-256-GCM encrypted message payload)
* **Double Layer Encryption:** Inner E2E encryption + Outer transport link encryption.
* **Server-Blindness:** The server routes messages by `@username` without being able to read or decrypt the inner plaintext.

---

## 🛠️ Step 1: Generate PKI Certificates & Build
```bash
cd phase4
chmod +x generate_certs.sh
./generate_certs.sh
make
```

---

## 🚀 Step 2: Execution & Verification

### 1. Start Server (`VM-Server`):
```bash
./server 8080 server.crt server.key
```

### 2. Connect Clients:
```bash
# On VM-Client1:
./client <SERVER_IP> 8080 alice ca.crt chat.server.local

# On VM-Client2:
./client <SERVER_IP> 8080 bob ca.crt chat.server.local
```

### 3. Initiate End-to-End Encryption:
Inside `alice`'s client terminal, type:
```text
> /e2e bob
```
* **Client Output:** Both `alice` and `bob` print:
  ```text
  [E2E] Established End-to-End session with @...
        E2E Key Fingerprint: 3e8a9f...
  ```
  Confirm that both clients derived the **exact identical E2E fingerprint** without server involvement.

### 4. Send Messages and Verify Server-Blindness:
1. In `alice`'s terminal, type:
   ```text
   > Top secret confidential message for Bob
   ```
2. In `bob`'s terminal, it decrypts and displays:
   ```text
   [E2E ENCRYPTED] FROM @alice: Top secret confidential message for Bob
   ```
3. Look at the **`VM-Server` terminal logs**:
   ```text
   [RELAY] (alice -> bob): __E2E_MSG__7a9b0c...
   ```
   **Evidence for Report:** Take a screenshot of the server log showing that the server only relays unreadable opaque ciphertext and cannot read the plaintext conversation!
