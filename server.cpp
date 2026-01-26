#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <map>
#include <cstring> 
#include <boost/asio.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <sodium.h>

// Linux specific headers
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

using boost::asio::ip::udp;

class SecureVpnServer {
public:
    SecureVpnServer(boost::asio::io_context& io_context, unsigned short port, const std::string& dev_name)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
          tun_fd_(io_context, open_tun(dev_name)) {
        
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium could not be initialized.");
        }

        // Hardcoded 32-byte key 
        unsigned char static_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
            0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32
        };
        std::copy(std::begin(static_key), std::end(static_key), key_.begin());

        start_socket_receive();
        start_tun_read();
    }

private:
    // Path A: Client (Encrypted Socket) -> Server -> TUN (Decrypted IP Packet)
    void start_socket_receive() {
        socket_.async_receive_from(
            boost::asio::buffer(net_buffer_), remote_endpoint_,
            [this](const boost::system::error_code& ec, std::size_t length) {
                if (!ec && length > crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
                    
                    // Extract Nonce and ciphertext
                    unsigned char* nonce = (unsigned char*)net_buffer_.data();
                    unsigned char* ciphertext = nonce + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
                    unsigned long long ciphertext_len = length - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

                    // Decrypt
                    unsigned long long decrypted_len;
                    if (crypto_aead_chacha20poly1305_ietf_decrypt(
                            decrypted_buffer_.data(), &decrypted_len,
                            NULL, ciphertext, ciphertext_len, NULL, 0,
                            nonce, key_.data()) == 0) {

                        // Extract the client's VPN IP from the packet
                        if(decrypted_len >= 20){
                            std::string client_ip = extract_source_ip(decrypted_buffer_.data());

                            //Save the client in our map
                            clients_[client_ip] = remote_endpoint_;

                            //Log the connection
                            std::cout << "Client " << client_ip << " from " 
                                      << remote_endpoint_.address() << ":" 
                                      << remote_endpoint_.port() << std::endl;
                        }

                        // Write the decrypted IP Packet to TUN device
                        boost::asio::async_write(tun_fd_, 
                            boost::asio::buffer(decrypted_buffer_.data(), decrypted_len),
                            [](const boost::system::error_code& /*ec*/, std::size_t /*bytes*/) {});
                    }
                }
                start_socket_receive(); // Restart the loop
            });
    }

    // Path B: TUN (Plain IP Packet) -> Server -> Client (Encrypted Socket)
    void start_tun_read() {
        tun_fd_.async_read_some(
            boost::asio::buffer(tun_buffer_),
            [this](const boost::system::error_code& ec, std::size_t length) {
                if (!ec && length > 0) {
                    
                    //Extract destination IP from packets
                    std::string dest_ip = extract_dest_ip((unsigned char*)tun_buffer_.data());

                    //Find the client endpoint for this destination
                    auto it = clients_.find(dest_ip);
                    if(it == clients_.end()){
                        //Client was not found, skip this packet
                        start_tun_read();
                        return;
                    }

                    udp::endpoint target_endpoint = it->second;

                    // Generate a random unique nonce
                    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
                    randombytes_buf(nonce, sizeof(nonce));

                    // Encrypt the IP packet
                    unsigned char encrypted_packet[2048];
                    unsigned long long encrypted_len;
                    crypto_aead_chacha20poly1305_ietf_encrypt(
                        encrypted_packet + sizeof(nonce), &encrypted_len,
                        (const unsigned char*)tun_buffer_.data(), length, NULL, 0,
                        NULL, nonce, key_.data());

                    // Prefixing the packet with Nonce so the client can decrypt it
                    std::memcpy(encrypted_packet, nonce, sizeof(nonce));
                    std::size_t total_send_len = encrypted_len + sizeof(nonce);

                    // Send to the last known remote endpoint (client)
                    socket_.async_send_to(
                        boost::asio::buffer(encrypted_packet, total_send_len), target_endpoint,
                        [](const boost::system::error_code& /*ec*/, std::size_t /*bytes*/) {});
                }
                start_tun_read(); // Restart the loop
            });
    }

    //Extract source IP from the IPV4 packet (bytes 12-15);
    std::string extract_source_ip(const unsigned char* packet){
      char ip_str[16];
      snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
          packet[12], packet[13], packet[14], packet[15]);
      return std::string(ip_str);
    }

    //Extract destination IP from the IPV4 packet (bytes 16-19)
    std::string extract_dest_ip(const unsigned char* packet){
      char ip_str[16];
      snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
          packet[16], packet[17], packet[18], packet[19]);
      return std::string(ip_str);
    }

    int open_tun(const std::string& dev) {
        struct ifreq ifr;
        int fd;
        if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
            perror("Opening /dev/net/tun");
            exit(1);
        }
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // Layer 3 IP packets
        strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

        if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
            perror("ioctl(TUNSETIFF)");
            close(fd);
            exit(1);
        }
        return fd;
    }

    udp::socket socket_;
    udp::endpoint remote_endpoint_;
    boost::asio::posix::stream_descriptor tun_fd_;
    std::array<unsigned char, crypto_aead_chacha20poly1305_ietf_KEYBYTES> key_;

    std::map<std::string, udp::endpoint> clients_;

    std::array<char, 2048> net_buffer_;
    std::array<char, 2048> tun_buffer_;
    std::array<unsigned char, 2048> decrypted_buffer_;
};

int main() {
    unsigned short port = 1194;
    std::string device_name = "tun0";

    try {
        boost::asio::io_context io_context;
        SecureVpnServer server(io_context, port, device_name);

        std::cout << "==========================================" << std::endl;
        std::cout << "  Multi-Client VPN Server Running" << std::endl;
        std::cout << "  Listening on UDP Port: " << port << std::endl;
        std::cout << "  Virtual Interface:     " << device_name << std::endl;
        std::cout << "  Supports Multiple Clients" << std::endl;
        std::cout << "  (Press Ctrl+C to stop)" << std::endl;
        std::cout << "==========================================" << std::endl;

        io_context.run();
    }
    catch (const std::exception& e) {
        std::cerr << "CRITICAL ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
