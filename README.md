# 🔐 CipherLink

A lightweight, secure VPN implementation written in C++ using TUN/TAP interfaces and ChaCha20-Poly1305 encryption.

## 📋 Overview

**CipherLink** is a custom VPN solution that creates an encrypted tunnel between clients and servers using:
- **TUN devices** for virtual network interfaces
- **ChaCha20-Poly1305 AEAD** encryption for security
- **UDP protocol** for transport
- **Boost.Asio** for asynchronous I/O operations
- **Multi-client support** with connection tracking
- **Web-based dashboard** for real-time monitoring

## ✨ Features

- ✅ **Strong Encryption** - ChaCha20-Poly1305 AEAD cipher
- ✅ **Layer 3 Tunneling** - IP-level tunneling via TUN devices
- ✅ **Asynchronous Processing** - Non-blocking packet handling
- ✅ **Multi-Client Support** - Multiple simultaneous connections
- ✅ **Bidirectional Communication** - Full duplex encrypted traffic
- ✅ **Unique Nonce Generation** - Per-packet nonce for security
- ✅ **REST API** - HTTP endpoint for statistics and monitoring
- ✅ **Real-time Dashboard** - Web interface for visualization

## 🛠️ Prerequisites

### System Requirements
- Linux operating system (tested on Arch Linux, Ubuntu)
- Root/sudo access (required for TUN device creation)
- C++17 compatible compiler (GCC 7+ or Clang 5+)

### Dependencies

**Arch Linux:**
```bash
sudo pacman -S boost libsodium gcc
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libboost-all-dev libsodium-dev build-essential
```

**Fedora/RHEL:**
```bash
sudo dnf install boost-devel libsodium-devel gcc-c++
```

## 📦 Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/cipherlink.git
cd cipherlink
```

2. **Compile the server**
```bash
g++ -o vpn_server server.cpp -lsodium -lpthread -std=c++17
```

3. **Compile the client**
```bash
g++ -o vpn_client client.cpp -lsodium -lpthread -std=c++17
```

Alternatively, use the provided Makefile (if you create one):
```bash
make all
```

## 🚀 Quick Start

### 1. Start the VPN Server

**Terminal 1 - Run server:**
```bash
sudo ./vpn_server
```

Expected output:
```
==========================================
  Multi-Client VPN Server Running
  VPN Port (UDP):        1194
  HTTP API Port (TCP):   8080
  Virtual Interface:     tun0
  API Endpoint: http://localhost:8080/api/clients
  Supports Multiple Clients
  (Press Ctrl+C to stop)
==========================================
```

**Terminal 2 - Configure server interface:**
```bash
sudo ip addr add 10.8.0.1/24 dev tun0
sudo ip link set tun0 up
```

### 2. Start the VPN Client

**Terminal 3 - Run client:**
```bash
sudo ./vpn_client 127.0.0.1
```

**Terminal 4 - Configure client interface:**
```bash
sudo ip addr add 10.8.0.2/24 dev tun1
sudo ip link set tun1 up
```

### 3. Test the Connection

```bash
# Ping the server through the encrypted tunnel
ping 10.8.0.1

# Expected output:
# 64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=0.123 ms
```

```bash
# From server, ping the client
ping 10.8.0.2
```

## 🖥️ Web Dashboard

The server includes a built-in HTTP API that provides real-time client statistics.

**Access the API:**
```bash
curl http://localhost:8080/api/clients
```

**Open the Web Dashboard:**
```bash
firefox frontend.html
# or
xdg-open frontend.html
```

The dashboard provides:
- 📊 Connection status visualization
- 📈 Real-time network statistics (bytes sent/received)
- ⏱️ Connection uptime tracking
- 🔒 Encryption information
- 🌐 Client IP mapping (VPN IP ↔ Real IP)

## 📊 Testing & Verification

### Basic Connectivity Test
```bash
ping -c 4 10.8.0.1
```

### HTTP Traffic Test
```bash
# On server side
cd /tmp
echo '<h1>Hello from CipherLink VPN!</h1>' > index.html
python3 -m http.server 8080 --bind 10.8.0.1

# On client side
curl http://10.8.0.1:8080
# Output: <h1>Hello from CipherLink VPN!</h1>
```

### Verify Encryption with tcpdump

**Monitor encrypted UDP packets:**
```bash
sudo tcpdump -i lo -n port 1194 -X
```
You should see encrypted/binary data (gibberish).

**Monitor decrypted packets on TUN:**
```bash
sudo tcpdump -i tun1 -A -n icmp
```
You should see readable ICMP packets.

This confirms that traffic is encrypted on the wire and decrypted in the tunnel!

## 🗺️ Architecture

### Network Flow Diagram

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│             │                    │             │
│  App Layer  │                    │  App Layer  │
│      ↕      │                    │      ↕      │
│  tun1       │                    │  tun0       │
│ 10.8.0.2    │                    │ 10.8.0.1    │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  ┌────────────────────────────┐  │
       └─→│  Encrypted UDP (Port 1194) │←─┘
          │   ChaCha20-Poly1305 AEAD   │
          └────────────────────────────┘
```

### Data Flow

**Outbound (Client → Server):**
1. Application sends plain IP packet
2. Packet enters TUN interface (tun1)
3. CipherLink client encrypts packet
4. Encrypted packet sent via UDP to server
5. Server decrypts packet
6. Decrypted packet written to server's TUN (tun0)
7. Delivered to server application

**Inbound (Server → Client):**
Process works in reverse with server encrypting and client decrypting.

### Encryption Details

| Component | Specification |
|-----------|---------------|
| **Algorithm** | ChaCha20-Poly1305 AEAD |
| **Key Size** | 256 bits (32 bytes) |
| **Nonce Size** | 96 bits (12 bytes) |
| **MAC Size** | 128 bits (16 bytes) |
| **Transport** | UDP on port 1194 |
| **Authentication** | Built-in with Poly1305 MAC |

### Packet Structure

```
┌──────────┬────────────────┬──────────┐
│  Nonce   │   Ciphertext   │   MAC    │
│(12 bytes)│   (variable)   │(16 bytes)│
└──────────┴────────────────┴──────────┘
```

## 📁 Project Structure

```
cipherlink/
├── server.cpp          # VPN server implementation
├── client.cpp          # VPN client implementation
├── frontend.html       # Web dashboard (optional)
├── README.md           # This file
├── LICENSE             # License file
└── .gitignore          # Git ignore rules
```

## 🔧 Configuration

### Changing Server Port

Edit `server.cpp`:
```cpp
unsigned short vpn_port = 1194;  // Change VPN port
unsigned short http_port = 8080; // Change HTTP API port
```

### Changing Network Range

Modify IP addresses when configuring interfaces:
```bash
sudo ip addr add 10.9.0.1/24 dev tun0  # Custom network
```

### Changing Encryption Key

⚠️ **Security Warning:** The current implementation uses a hardcoded key for demonstration.

To change the key, modify the `static_key` array in **both** `server.cpp` and `client.cpp`:

```cpp
unsigned char static_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    // ... 32 bytes total
};
```

**Critical:** Both client and server MUST use identical keys!

### Remote Server Configuration

For connecting to a remote server:

```bash
# On client
sudo ./vpn_client <server_public_ip>
```

## 🔒 Security Considerations

### Current Limitations

⚠️ **This is an educational/demonstration project. Do NOT use in production without addressing:**

| Issue | Risk Level | Description |
|-------|-----------|-------------|
| Hardcoded Keys | 🔴 Critical | Static encryption keys embedded in source code |
| No Authentication | 🔴 Critical | No client/server identity verification |
| No Key Exchange | 🔴 Critical | No dynamic key negotiation (DHE, ECDHE) |
| No Perfect Forward Secrecy | 🟡 High | Compromised key exposes all sessions |
| Basic Replay Protection | 🟡 High | Only nonce-based, no sequence numbers |
| No Connection Timeouts | 🟢 Medium | Stale connections not cleaned up |

### Production Recommendations

To make CipherLink production-ready, implement:

- [ ] **Public Key Infrastructure** - X.509 certificates for authentication
- [ ] **Key Exchange Protocol** - Diffie-Hellman or ECDHE key agreement
- [ ] **Perfect Forward Secrecy** - Ephemeral keys per session
- [ ] **Replay Protection** - Sequence numbers and sliding window
- [ ] **Connection Management** - Timeouts, keepalives, reconnection logic
- [ ] **Secure Key Storage** - Hardware security modules or encrypted keystores
- [ ] **Logging & Auditing** - Security event logging with rotation
- [ ] **Rate Limiting** - DoS protection and bandwidth management
- [ ] **Configuration Files** - Remove hardcoded values

## 🌍 Remote Deployment Guide

### Deploying to a VPS

1. **Setup server on VPS** (AWS, DigitalOcean, Linode, etc.)
```bash
ssh user@your-vps-ip
git clone https://github.com/yourusername/cipherlink.git
cd cipherlink
g++ -o vpn_server server.cpp -lsodium -lpthread -std=c++17
```

2. **Configure server networking**
```bash
sudo ./vpn_server &

sudo ip addr add 10.8.0.1/24 dev tun0
sudo ip link set tun0 up

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Configure NAT for internet access
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT
```

3. **Open firewall ports**
```bash
sudo ufw allow 1194/udp
sudo ufw allow 8080/tcp  # Optional, for API
```

4. **Connect from local machine**
```bash
sudo ./vpn_client <vps_public_ip>
sudo ip addr add 10.8.0.2/24 dev tun1
sudo ip link set tun1 up

# Route all traffic through VPN (optional)
sudo ip route add default via 10.8.0.1 dev tun1 metric 100
```

## 🐛 Troubleshooting

### TUN Device Not Created

```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module if missing
sudo modprobe tun

# Verify /dev/net/tun exists
ls -l /dev/net/tun
```

### Permission Denied Errors

```bash
# Always run with sudo
sudo ./vpn_server
sudo ./vpn_client 127.0.0.1

# Check file permissions
ls -l vpn_server vpn_client
chmod +x vpn_server vpn_client
```

### Connection Timeout / No Response

- Verify server is running: `ps aux | grep vpn_server`
- Check firewall rules: `sudo iptables -L -n`
- Test UDP port: `nc -u -v server_ip 1194`
- Ensure TUN interfaces are UP: `ip link show tun0`

### Packets Not Routing

```bash
# Check interface status
ip addr show tun0
ip link show tun0

# Verify routing table
ip route show

# Check for IP forwarding (server)
cat /proc/sys/net/ipv4/ip_forward  # Should output: 1
```

### API Not Responding

```bash
# Test API endpoint
curl -v http://localhost:8080/api/clients

# Check if port is listening
sudo netstat -tulpn | grep 8080
```

## 🔬 Development

### Building with Debug Symbols

```bash
g++ -g -o vpn_server server.cpp -lsodium -lpthread -std=c++17
g++ -g -o vpn_client client.cpp -lsodium -lpthread -std=c++17
```

### Running with GDB

```bash
sudo gdb ./vpn_server
(gdb) run
```

### Adding Features

**Ideas for extension:**

1. **Configuration Files** - JSON/YAML config instead of hardcoded values
2. **Dynamic Routing** - Support for custom route tables
3. **Bandwidth Limiting** - QoS and traffic shaping
4. **Connection Logs** - Detailed logging with timestamps
5. **GUI Client** - Qt or GTK-based graphical interface
6. **Mobile Support** - Android/iOS client applications
7. **Protocol Obfuscation** - Make VPN traffic look like HTTPS

### Code Structure

| Component | Purpose |
|-----------|---------|
| `SecureVpnServer` | Server-side tunnel management |
| `SecureVpnClient` | Client-side tunnel management |
| `start_socket_receive()` | UDP packet reception & decryption |
| `start_tun_read()` | TUN packet reading & encryption |
| `open_tun()` | TUN device creation & configuration |
| `ClientInfo` | Per-client connection tracking |

## 📚 References & Resources

- [libsodium Documentation](https://doc.libsodium.org/) - Cryptography library
- [Boost.Asio Documentation](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html) - Async I/O
- [TUN/TAP Interfaces](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) - Linux virtual networking
- [ChaCha20-Poly1305 RFC 8439](https://tools.ietf.org/html/rfc8439) - Cipher specification
- [VPN Protocols Overview](https://en.wikipedia.org/wiki/Virtual_private_network) - VPN technology primer

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

Created as a learning project to understand VPN internals, cryptography, and network programming.

**Contributions welcome!** Feel free to:
- 🐛 Report bugs
- 💡 Suggest features
- 🔧 Submit pull requests
- ⭐ Star the repo if you find it useful

## 🙏 Acknowledgments

- **libsodium** - Making cryptography accessible and secure
- **Boost.Asio** - Powerful asynchronous I/O library
- **Linux TUN/TAP** - Virtual network interface support
- The open-source community for inspiration and resources

---

## ⚠️ Disclaimer

**CipherLink is an educational VPN implementation.** It demonstrates core VPN concepts including:
- Tunnel creation and management
- Symmetric encryption (ChaCha20-Poly1305)
- Network packet routing
- Client-server architecture

**This software lacks security features required for production use.** Do not use CipherLink for:
- Protecting sensitive communications
- Bypassing network restrictions in hostile environments
- Any scenario requiring robust security guarantees

For production VPN needs, use established solutions like WireGuard, OpenVPN, or IPsec.

---

<p align="center">
  <strong>Built with ❤️ for learning and education</strong>
</p>

<p align="center">
  If you found this project helpful, please consider giving it a ⭐ on GitHub!
</p>
