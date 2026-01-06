#include <iostream>
#include <string>
#include <array>
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

class SecureVpnClient {
public:
    SecureVpnClient(boost::asio::io_context& io_context, 
                    const std::string& server_ip, 
                    unsigned short port, 
                    const std::string& dev_name)
        : socket_(io_context, udp::endpoint(udp::v4(), 0)), // Bind to any local port
          server_endpoint_(boost::asio::ip::make_address(server_ip), port),
          tun_fd_(io_context, open_tun(dev_name)) {
        
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium could not be initialized.");
        }

        // MUST match the server's key exactly
        unsigned char static_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
            0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32
        };
        std::copy(std::begin(static_key), std::end(static_key), key_.begin());

        std::cout << "VPN Client connecting to " << server_ip << ":" << port << std::endl;

        //start the loops
        start_socket_receive();
        start_tun_read();
    }

private:
    // Path A: Server (Encrypted Socket) -> Client -> TUN (Decrypted IP Packet)
    void start_socket_receive() {
        socket_.async_receive_from(
            boost::asio::buffer(net_buffer_), from_endpoint_,
            [this](const boost::system::error_code& ec, std::size_t length) {
                if (!ec && length > crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
                    
                    unsigned char* nonce = (unsigned char*)net_buffer_.data();
                    unsigned char* ciphertext = nonce + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
                    unsigned long long ciphertext_len = length - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

                    unsigned long long decrypted_len;
                    if (crypto_aead_chacha20poly1305_ietf_decrypt(
                            decrypted_buffer_.data(), &decrypted_len,
                            NULL, ciphertext, ciphertext_len, NULL, 0,
                            nonce, key_.data()) == 0) {

                        boost::asio::async_write(tun_fd_, 
                            boost::asio::buffer(decrypted_buffer_.data(), decrypted_len),
                            [](const boost::system::error_code&, std::size_t) {});
                    }
                }
                start_socket_receive();
            });
    }

    // Path B: TUN (Plain IP Packet) -> Client -> Server (Encrypted Socket)
    void start_tun_read() {
        tun_fd_.async_read_some(
            boost::asio::buffer(tun_buffer_),
            [this](const boost::system::error_code& ec, std::size_t length) {
                if (!ec && length > 0) {
                    
                    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
                    randombytes_buf(nonce, sizeof(nonce));

                    unsigned char encrypted_packet[2048];
                    unsigned long long encrypted_len;
                    crypto_aead_chacha20poly1305_ietf_encrypt(
                        encrypted_packet + sizeof(nonce), &encrypted_len,
                        (const unsigned char*)tun_buffer_.data(), length, NULL, 0,
                        NULL, nonce, key_.data());

                    std::memcpy(encrypted_packet, nonce, sizeof(nonce));
                    std::size_t total_send_len = encrypted_len + sizeof(nonce);

                    // Send encrypted data to the pre-defined server endpoint
                    socket_.async_send_to(
                        boost::asio::buffer(encrypted_packet, total_send_len), server_endpoint_,
                        [](const boost::system::error_code&, std::size_t) {});
                }
                start_tun_read();
            });
    }

    int open_tun(const std::string& dev) {
        struct ifreq ifr;
        int fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0) { perror("open tun"); exit(1); }
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);
        if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) { perror("ioctl"); close(fd); exit(1); }
        return fd;
    }

    udp::socket socket_;
    udp::endpoint server_endpoint_;
    udp::endpoint from_endpoint_;
    boost::asio::posix::stream_descriptor tun_fd_;
    std::array<unsigned char, crypto_aead_chacha20poly1305_ietf_KEYBYTES> key_;

    std::array<char, 2048> net_buffer_;
    std::array<char, 2048> tun_buffer_;
    std::array<unsigned char, 2048> decrypted_buffer_;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: sudo ./vpn_client <server_ip>" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    unsigned short port = 1194;
    std::string device_name = "tun1";

    try {
        boost::asio::io_context io_context;
        SecureVpnClient client(io_context, server_ip, port, device_name);
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
