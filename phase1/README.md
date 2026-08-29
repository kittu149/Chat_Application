# Phase 1: Baseline Chat Application (No Security)

This directory contains the baseline implementation of the TCP chat server and client application.

---

## 🛠️ Build Instructions
Inside this directory (`phase1/`), run:

```bash
make
```

This will produce two executables:
* `server`
* `client`

To clean build artifacts:
```bash
make clean
```

---

## 🚀 Execution Instructions

### 1. Start the Server (`VM-Server`)
Run the server executable by passing the listening port:
```bash
./server 8080
```

### 2. Connect Client 1 (`VM-Client1`)
Connect by providing the server IP, server port, and desired username:
```bash
./client <SERVER_IP> 8080 alice
```

### 3. Connect Client 2 (`VM-Client2`)
```bash
./client <SERVER_IP> 8080 bob
```

---

## 💬 Chat Commands

| Command | Action |
| :--- | :--- |
| `@bob Hello Bob!` | Sends a message directly to `bob` and sets `bob` as current chat partner. |
| `/chat bob` | Switches active chat partner to `bob` without sending a message. |
| `How are you?` | When active partner is set, plain text is automatically routed to them. |
| `/who` | Requests list of online users from the server. |
| `/quit` | Cleanly disconnects from the server and exits. |

---

## 🔍 Verification (Wireshark Capture)
1. Launch **Wireshark** on `VM-Client1` or `VM-Server`.
2. Filter on the interface (e.g., `eth0` or `enp0s1`) using filter: `tcp.port == 8080`.
3. Send a message between `alice` and `bob`.
4. Right-click on any captured TCP packet $\rightarrow$ select **Follow** $\rightarrow$ **TCP Stream**.
5. Observe that the chat content and username routing metadata are completely visible in plaintext. Take a screenshot for the report.
