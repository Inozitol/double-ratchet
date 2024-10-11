/*
Author: Pavel Horáček
 */

#pragma once
#include "Types.h"

#include <array>
#include <csignal>
#include <cstdint>
#include <vector>

class ChatClient {
public:
  ChatClient() = default;
  ~ChatClient();
  void setPort(uint16_t port);
  void connect(const char* fulladdr) const;
  int recvloop();
  bytes_t recv();
  void send(bytes_t data) const;
  void shutdown() const;

  std::array<char, 1024> rx_buffer{};
  bytes_t rx_data;

private :
  /// Socket
  int _sck = -1;

};
