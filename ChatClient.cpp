/*
Author: Pavel Horáček
 */

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

#include "ChatClient.h"

#include "Types.h"

#include <algorithm>
#include <cstring>

ChatClient::~ChatClient() { shutdown(); }

void ChatClient::setPort(uint16_t port) {
  _sck = socket(AF_INET, SOCK_STREAM, 0);

  sockaddr_in localAddr{};
  localAddr.sin_family = AF_INET;
  localAddr.sin_port = htons(port);
  localAddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(_sck, reinterpret_cast<sockaddr *>(&localAddr), sizeof(localAddr)) !=
      0) {
    std::cerr << "Couldn't bind local address with port [" << port
              << "], errno: " << strerror(errno) << "\n";
    throw std::runtime_error("Failed to bind in ChatClient::bind");
  }
}

void ChatClient::connect(const char *fulladdr) const {
  std::stringstream ss(fulladdr);
  std::array<std::string, 2> addrarr;
  std::string token;
  uint8_t ctr = 0;
  while (std::getline(ss, token, ':')) {
    if (ctr >= 2) {
      std::cerr << "Address [" << fulladdr
                << "] is not in form of [addr]:[port]\n";
      throw std::invalid_argument("Wrong address given in ChatClient::connect");
    }
    addrarr[ctr] = token;
    ctr++;
  }

  const char *addr = addrarr[0].c_str();
  uint16_t port = std::stoi(addrarr[1]);

  sockaddr_in connAddr{};
  connAddr.sin_family = AF_INET;
  connAddr.sin_port = htons(port);

  if (inet_pton(AF_INET, addr, &connAddr.sin_addr) <= 0) {
    std::cerr << "Failed to convert address [" << addr << "] with inet_pton\n";
    throw std::runtime_error("Failed to convert address with inet_pton");
  }

  std::cout << "Waiting for connection on port [" << port << "]\n";
  while (::connect(_sck, reinterpret_cast<sockaddr *>(&connAddr),
                   sizeof(connAddr)) < 0) {
    if (errno == ECONNREFUSED)
      continue;
    std::cerr << "Connection failed\n";
    throw std::runtime_error("Connection failed");
  }
  std::cout << "Established connection on port [" << port << "]\n";
}

int ChatClient::recvloop() {
  int ret = 0;
  ssize_t n = 0;
  while (true) {
    n = ::recv(_sck, rx_buffer.data(), rx_buffer.size() * sizeof(rx_buffer[0]),
               0);
    if (n < 0) {
      std::cerr << "Error encountered while receiving data: ["
                << strerror(errno) << "]\n";
      ret = 1;
      break;
    }
    if (n == 0) {
      std::cout << "Other side disconnected\n";
      ret = 0;
      break;
    }

    rx_data.insert(std::end(rx_data), std::begin(rx_buffer),
                   std::begin(rx_buffer) + n);

    std::string str(rx_data.begin(), rx_data.end());
    std::cout << "Received: " << str << "\n";
    rx_data.clear();
  }
  return ret;
}

bytes_t ChatClient::recv() {
  ssize_t n = 0;
  n = ::recv(_sck, rx_buffer.data(), rx_buffer.size() * sizeof(rx_buffer[0]),0);
  if (n < 0) {
    std::cerr << "Error encountered while receiving data: ["
              << strerror(errno) << "]\n";
    return {};
  }
  if (n == 0) {
    std::cout << "Other side disconnected\n";
    return {};
  }
  rx_data.resize(n);
  std::copy_n(std::begin(rx_buffer), n, std::begin(rx_data));
  return rx_data;
}

void ChatClient::send(bytes_t data) const {
  ssize_t n = 0;
  size_t size = data.size();
  if ((n = ::send(_sck, data.data(), data.size(), 0)) != size) {
    if (n >= 0) {
      std::cerr << "Failed to send all data";
    } else {
      std::cerr << "Error encountered while receiving data: ["
                << strerror(errno) << "]\n";
      throw std::runtime_error("Error while sending data");
    }
  }
}

void ChatClient::shutdown() const {
  if (_sck != -1) {
    ::shutdown(_sck, SHUT_RDWR);
  }
}