#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <map>
#include <cstring> 
#include <boost/asio.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <sodium.h>
#include <sstream>
#include <chrono>

// Linux specific headers
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

using boost::asio::ip::udp;
using boost::asio::ip::tcp;

struct ClientInfo{
  std::string vpn_ip;
  std::string real_ip;
  unsigned short real_port;
  std::chrono::system_clock::time_point connected_time;
  unsigned long long bytes_sent;
  unsigned long long bytes_received;
  udp::endpoint endpoint;
};

class SecureVpnServer {
public:
    SecureVpnServer(boost::asio::io_context& io_context, unsigned short vpn_port, unsigned short http_port, const std::string& dev_name)
        : socket_(io_context, udp::endpoint(udp::v4(), vpn_port)),
          tun_fd_(io_context, open_tun(dev_name)),
          http_acceptor_(io_context, tcp::endpoint(tcp::v4(), http_port)),
          io_context_(io_context){
        
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
        start_http_accept();
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

                            //Store detailed client info
                            auto it = clients_.find(client_ip);
                            if(it == clients_.end()){
                              ClientInfo info;
                              info.vpn_ip = client_ip;
                              info.real_ip = remote_endpoint_.address().to_string();
                              info.real_port = remote_endpoint_.port();
                              info.connected_time = std::chrono::system_clock::now();
                              info.bytes_sent = 0;
                              info.bytes_received = decrypted_len;
                              info.endpoint = remote_endpoint_;
                              clients_[client_ip] = info;

                              std::cout << "NEW Client " << client_ip << " from " 
                                          << remote_endpoint_.address() << ":" 
                                          << remote_endpoint_.port() << std::endl;
                            }
                            else{
                              //Existing client -> update stats
                              it->second.bytes_received += decrypted_len;
                              it->second.endpoint = remote_endpoint_;
                            }
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

                    udp::endpoint target_endpoint = it->second.endpoint;

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

                    //Update bytes_sent stats
                    it->second.bytes_sent += total_send_len;

                    // Send to the last known remote endpoint (client)
                    socket_.async_send_to(
                        boost::asio::buffer(encrypted_packet, total_send_len), target_endpoint,
                        [](const boost::system::error_code& /*ec*/, std::size_t /*bytes*/) {});
                }
                start_tun_read(); // Restart the loop
            });
    }

    //Start accepting HTTP connections
    void start_http_accept(){
      auto socket = std::make_shared<tcp::socket>(io_context_);
      http_acceptor_.async_accept(*socket, [this, socket](const boost::system::error_code& ec){
          if(!ec){
              handle_http_request(socket);
          }
          start_http_accept();
      });
    }

    //Handle http request
    void handle_http_request(std::shared_ptr<tcp::socket> socket){
      auto buffer = std::make_shared<std::array<char, 8192>>();
      socket->async_read_some(boost::asio::buffer(*buffer),
          [this, socket, buffer](const boost::system::error_code& ec, std::size_t bytes){
              if(!ec){
                  std::string request(buffer->data(), bytes);
                  if(request.find("GET /api/clients") != std::string::npos){
                  send_clients_json(socket);
                  }
                  else{
                      send_404(socket);
                  }
              }
          });
    }

    //Send client list as JSON
    void send_clients_json(std::shared_ptr<tcp::socket> socket){
      std::ostringstream json;
      json << "{\n \"clients\": [\n";

      bool first = true;
      for(const auto& pair : clients_){
        if(!first) json << ",\n";
        first = false;

        const ClientInfo& client = pair.second;
        auto now = std::chrono::system_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - client.connected_time).count();

        json << "    {\n"
                 << "      \"vpnIP\": \"" << client.vpn_ip << "\",\n"
                 << "      \"realIP\": \"" << client.real_ip << "\",\n"
                 << "      \"realPort\": " << client.real_port << ",\n"
                 << "      \"bytesSent\": " << client.bytes_sent << ",\n"
                 << "      \"bytesReceived\": " << client.bytes_received << ",\n"
                 << "      \"uptimeSeconds\": " << uptime << "\n"
                 << "    }";
      }

      json << "\n ]\n}";

      std::string json_str = json.str();
      std::ostringstream response;
      response << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: application/json\r\n"
                 << "Access-Control-Allow-Origin: *\r\n"
                 << "Content-Length: " << json_str.length() << "\r\n"
                 << "Connection: close\r\n"
                 << "\r\n"
                 << json_str;

      auto response_str = std::make_shared<std::string>(response.str());
      boost::asio::async_write(*socket, boost::asio::buffer(*response_str),
          [socket, response_str](const boost::system::error_code&, std::size_t){
              socket->close();
          });
    }

    //Send 404 response
    void send_404(std::shared_ptr<tcp::socket> socket){
      std::string response = "HTTP/1.1 404 Not Found\r\n"
                             "Content-Length: 0\r\n"
                             "Connection: close\r\n\r\n";
      auto response_str = std::make_shared<std::string>(response);
      boost::asio::async_write(*socket, boost::asio::buffer(*response_str),
          [socket, response_str](const boost::system::error_code&, std::size_t){
              socket->close();
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

    std::map<std::string, ClientInfo> clients_;

    std::array<char, 2048> net_buffer_;
    std::array<char, 2048> tun_buffer_;
    std::array<unsigned char, 2048> decrypted_buffer_;

    //HTTP server components
    tcp::acceptor http_acceptor_;
    boost::asio::io_context& io_context_;
};

int main() {
    unsigned short vpn_port = 1194;
    unsigned short http_port = 8080;
    std::string device_name = "tun0";

    try {
        boost::asio::io_context io_context;
        SecureVpnServer server(io_context, vpn_port, http_port, device_name);

        std::cout << "==========================================" << std::endl;
        std::cout << "  Multi-Client VPN Server Running" << std::endl;
        std::cout << "  VPN Port (UDP):        " << vpn_port << std::endl;
        std::cout << "  HTTP API Port (TCP):   " << http_port << std::endl;
        std::cout << "  Virtual Interface:     " << device_name << std::endl;
        std::cout << "  API Endpoint: http://localhost:" << http_port << "/api/clients" << std::endl;
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
