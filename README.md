# 🔒 Namma Gokul VPN

A lightweight, secure VPN implementation written in C++ using TUN/TAP interfaces and ChaCha20-Poly1305 encryption.

## 📋 Overview

Namma Gokul VPN is a custom VPN solution that creates an encrypted tunnel between a client and server using:
- **TUN devices** for virtual network interfaces
- **ChaCha20-Poly1305 AEAD** encryption for security
- **UDP protocol** for transport
- **Boost.Asio** for asynchronous I/O operations

## ✨ Features

- ✅ Strong encryption using ChaCha20-Poly1305
- ✅ Layer 3 (IP) tunneling via TUN devices
- ✅ Asynchronous packet processing
- ✅ Bidirectional encrypted communication
- ✅ Unique nonce generation for each packet
- ✅ Simple client-server architecture
- ✅ Web-based dashboard for monitoring

## 🛠️ Prerequisites

### System Requirements
- Linux operating system (tested on Arch Linux)
- Root/sudo access (required for TUN device creation)
- C++17 compatible compiler

### Dependencies
```bash
# Arch Linux
sudo pacman -S boost libsodium

# Ubuntu/Debian
sudo apt-get install libboost-all-dev libsodium-dev

# Fedora/RHEL
sudo dnf install boost-devel libsodium-devel
```

## 📦 Installation

1. **Clone or download the repository**
```bash
cd ~/namma_gokul_vpn
```

2. **Compile the server**
```bash
g++ -o vpn_server server.cpp -lsodium -lpthread -std=c++17
```

3. **Compile the client**
```bash
g++ -o vpn_client client.cpp -lsodium -lpthread -std=c++17
```

## 🚀 Quick Start

### 1. Start the VPN Server

**Terminal 1 - Run server:**
```bash
sudo ./vpn_server
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

# Ping the client from server
ping 10.8.0.2
```

## 🖥️ Web Dashboard

Open `frontend.html` in any web browser to view the VPN dashboard:

```bash
firefox frontend.html
# or
xdg-open frontend.html
```

The dashboard provides:
- Connection status visualization
- Real-time network statistics
- Connection logs
- Encryption information

**Note:** The web dashboard is a demonstration interface and doesn't control the actual VPN programs.

## 📊 Testing & Verification

### Basic Connectivity Test
```bash
ping 10.8.0.1
```

### HTTP Traffic Test
```bash
# On server side
cd /tmp
echo '<h1>Hello from VPN!</h1>' > index.html
python3 -m http.server 8080 --bind 10.8.0.1

# On client side
curl http://10.8.0.1:8080
```

### Verify Encryption
```bash
# Monitor encrypted UDP packets
sudo tcpdump -i lo -n port 1194 -X

# Monitor decrypted packets on TUN
sudo tcpdump -i tun1 -A -n
```

You should see:
- **Encrypted traffic** on port 1194 (gibberish/binary data)
- **Plain text traffic** on TUN interface (readable ICMP/HTTP)

## 🏗️ Architecture

### Network Flow

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

### Encryption Details

- **Algorithm:** ChaCha20-Poly1305 AEAD
- **Key Size:** 256 bits (32 bytes)
- **Nonce Size:** 96 bits (12 bytes)
- **Transport:** UDP on port 1194
- **Authentication:** Built-in with Poly1305 MAC

### Packet Structure

```
┌──────────┬────────────────┬─────────┐
│  Nonce   │   Ciphertext   │   MAC   │
│ (12 bytes)│   (variable)   │(16 bytes)│
└──────────┴────────────────┴─────────┘
```

## 📁 Project Structure

```
namma_gokul_vpn/
├── server.cpp          # VPN server implementation
├── client.cpp          # VPN client implementation
├── frontend.html       # Web dashboard
├── vpn_server          # Compiled server binary
├── vpn_client          # Compiled client binary
└── README.md           # This file
```

## 🔧 Configuration

### Changing Server IP/Port

Edit the `main()` function in `server.cpp`:
```cpp
unsigned short port = 1194;  // Change port here
```

For client, pass the server IP as an argument:
```bash
sudo ./vpn_client <server_ip>
```

### Changing Network Range

Modify the IP addresses when configuring interfaces:
```bash
sudo ip addr add <your_network>/24 dev tun0
```

### Changing Encryption Key

⚠️ **Security Warning:** The current implementation uses a hardcoded key for demonstration purposes.

To change the key, modify the `static_key` array in both `server.cpp` and `client.cpp`:
```cpp
unsigned char static_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES] = {
    // Your 32 bytes here
};
```

**Important:** Both client and server must use the same key!

## 🔐 Security Considerations

### Current Limitations

⚠️ **This is a demonstration/educational project. Do NOT use in production without addressing these issues:**

1. **Hardcoded Keys:** Static encryption keys are embedded in the code
2. **No Authentication:** No mechanism to verify client/server identity
3. **No Key Exchange:** No dynamic key negotiation (Diffie-Hellman, etc.)
4. **Single Client:** Server only remembers the last client endpoint
5. **No Replay Protection:** Beyond nonce uniqueness
6. **No Perfect Forward Secrecy:** Same key used for all sessions

### Recommendations for Production

To make this production-ready, implement:
- [ ] Public key authentication (X.509 certificates)
- [ ] Diffie-Hellman key exchange
- [ ] Perfect Forward Secrecy (PFS)
- [ ] Multi-client support with connection tracking
- [ ] Replay attack prevention with sequence numbers
- [ ] Connection timeout and keep-alive mechanisms
- [ ] Logging and monitoring
- [ ] Rate limiting and DoS protection

## 🌐 Remote Deployment

To use this VPN for accessing geo-restricted content:

1. Deploy `vpn_server` on a VPS in the desired location (AWS, DigitalOcean, etc.)
2. Configure NAT on the server for internet access:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
   sudo iptables -A FORWARD -i tun0 -j ACCEPT
   ```
3. Connect from your local machine using the server's public IP
4. Route all traffic through the VPN

## 🐛 Troubleshooting

### TUN device not created
```bash
# Check if /dev/net/tun exists
ls -l /dev/net/tun

# Load tun kernel module if needed
sudo modprobe tun
```

### Permission denied errors
```bash
# Ensure you're running with sudo
sudo ./vpn_server
sudo ./vpn_client 127.0.0.1
```

### Connection timeout
- Check if server is running and listening on correct port
- Verify firewall rules allow UDP port 1194
- Ensure both interfaces (tun0, tun1) are properly configured

### Packets not routing
```bash
# Check interface status
ip link show tun0
ip link show tun1

# Verify IP addresses
ip addr show tun0
ip addr show tun1

# Check routing table
ip route
```

## 📝 Development

### Adding Features

To extend this VPN:

1. **Multi-client support:** Maintain a map of client endpoints
2. **Configuration file:** Parse settings from a config file
3. **Better logging:** Add structured logging with timestamps
4. **Metrics:** Track bandwidth, connection duration, errors
5. **GUI client:** Create a native GUI application

### Code Structure

- `SecureVpnServer` class: Handles server-side encryption and tunneling
- `SecureVpnClient` class: Handles client-side encryption and tunneling
- `start_socket_receive()`: Decrypts incoming UDP packets
- `start_tun_read()`: Encrypts outgoing IP packets
- `open_tun()`: Creates and configures TUN device

## 📚 References

- [libsodium Documentation](https://doc.libsodium.org/)
- [Boost.Asio Documentation](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html)
- [TUN/TAP Interface](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
- [ChaCha20-Poly1305 RFC](https://tools.ietf.org/html/rfc8439)

## 📄 License

This project is for educational purposes. Feel free to modify and distribute.

## 👤 Author

Created as a learning project to understand VPN internals, encryption, and network programming.

## 🙏 Acknowledgments

- **libsodium** for easy-to-use cryptography
- **Boost.Asio** for asynchronous I/O
- Linux **TUN/TAP** interface for virtual networking

---

**⚠️ Disclaimer:** This VPN implementation is for educational purposes only. It demonstrates the core concepts of VPN technology but lacks many security features required for production use. Always use established VPN solutions for real-world security needs.
