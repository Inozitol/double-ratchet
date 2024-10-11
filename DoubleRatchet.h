/*
Author: Pavel Horáček
 */

#pragma once
#include "KDF.h"
#include "KeyManager.h"

#include <map>
#include <mutex>

class DoubleRatchet {
public:
  DoubleRatchet() = default;
  void init(const bytes_span_32_t& sk, const KeyPair& other_key_pair);
  bytes_t encrypt(bytes_span_c_t plaintext);
  bytes_t decrypt(bytes_span_c_t ciphertext);

  static bytes_t make_header(bytes_span_c_t pubkey, uint32_t prev_chain_cnt, uint32_t msg_cnt);
  static std::tuple<bytes_t, uint32_t, uint32_t> parse_header(bytes_span_c_t header);

  size_t MAX_SKIPPED = 256;
  constexpr static size_t HEADER_CONST_SIZE = 12;

private:

  void skip_messages(uint32_t until);
  void dh_ratchet(bytes_span_c_t new_pubkey);

  // Stores skipped keys by their public key and order
  std::map<std::pair<bytes_t, uint32_t>, bytes_32_t> m_skipped;

  KeyPair m_self_key_pair;
  bytes_t m_other_pub_key;

  bytes_32_t m_root_key{};
  KDF m_send_chain;
  KDF m_recv_chain;

  std::mutex m_mutex;
};
