# Phase 5: Forward Secrecy via Key Rotation & Collision Avoidance

This directory implements **Phase 5** of the Secure Chat Application:
* **Periodic Forward Secrecy:** Active End-to-End sessions automatically renegotiate a brand-new DH session key every **60 seconds**.
* **Immediate Key Discard:** Old session keys are cryptographically cleansed from memory (`OPENSSL_cleanse`) after rotation and never reused.
* **Collision Avoidance (Tie-Breaking):** If both clients attempt to rotate keys simultaneously, the tie is deterministically resolved using lexicographical username comparison (the client with the higher username wins and the lower yields to respond with ACK).
* **Zero Disruption:** In-flight messages sent right before or during rotation continue to be decrypted seamlessly.
* **Testing Command:** `/rekey` command to trigger an immediate key rotation on demand.

---

## 🛠️ Step 1: Generate PKI Certificates & Build
```bash
cd phase5
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

### 3. Initiate E2E & Observe Key Rotation Logs:
Inside `alice`'s client terminal, type:
```text
> /e2e bob
```
* Observe the timestamped key fingerprints printed on both clients:
  ```text
  [FORWARD SECRECY] [2026-08-30 01:20:00] Key Established / Rotated with @bob!
                    New E2E Fingerprint: 5f7c1a...
  ```
* Wait **60 seconds** (or type `/rekey` to force it immediately).
* Observe that a new rotation occurs automatically:
  ```text
  [FORWARD SECRECY] [2026-08-30 01:21:00] Key Established / Rotated with @bob!
                    New E2E Fingerprint: 9b2d8e...
  ```
* **Evidence for Report:** Take screenshots showing across at least 2 rotations that:
  1. The fingerprint changes every 60 seconds.
  2. Both Alice and Bob agree on the exact same fingerprint at each rotation.

### 4. Send Message Post-Rotation:
* Send a message immediately after key rotation:
  ```text
  > Message sent after rotation!
  ```
* Confirm that Bob decrypts it with the new key without any error or disruption.
