/*
Author: Pavel Horáček
 */

#include "DoubleRatchet.h"

#include <cassert>

void DoubleRatchet::init(const bytes_span_32_t &sk,
                         const KeyPair &key_pair) {
  assert(!sk.empty());

  // We got other side public key
  if (key_pair.priKey.empty()) {
    m_self_key_pair = KeyManager::genDHKeys();
    m_other_pub_key = key_pair.pubKey;
    bytes_32_t derive = KeyManager::deriveDHSecret(m_self_key_pair, key_pair);
    auto [root, send] = KDF::HKDF_pair(sk, derive);
    m_root_key = root;
    m_send_chain.set_key(send);
  } else { // We got our own public private key pair
    m_self_key_pair = key_pair;
    // Other pub key is left empty
    std::copy(std::begin(sk), std::end(sk), std::begin(m_root_key));
  }
}

bytes_t DoubleRatchet::encrypt(bytes_span_c_t plaintext) {
  m_mutex.lock();

  m_send_chain.cycle();
  bytes_32_t mk = m_send_chain.get_mk_key();
  bytes_t header =
      make_header(m_self_key_pair.pubKey, m_send_chain.prev_cycle(),
                  m_send_chain.curr_cycle()-1);

  bytes_t ciphertext = Crypto::encrypt(mk, plaintext, header);

  m_mutex.unlock();

  return concat<uint8_t>(header, ciphertext);
}

bytes_t DoubleRatchet::decrypt(bytes_span_c_t ciphertext_full) {
  m_mutex.lock();

  bytes_32_t mk{};
  auto [pubkey, prev_chain_cnt, msg_cnt] = parse_header(ciphertext_full);
  uint32_t header_size = pubkey.size() + HEADER_CONST_SIZE;
  auto header = ciphertext_full.subspan(0, header_size);
  auto ciphertext = ciphertext_full.subspan(header_size);
  if (m_skipped.contains({pubkey, msg_cnt})) {
    mk = m_skipped.at({pubkey, msg_cnt});
    m_skipped.erase({pubkey, msg_cnt});
    return Crypto::decrypt(mk, ciphertext, header);
  }
  if (!pubkey.empty() && pubkey != m_other_pub_key) {
    skip_messages(prev_chain_cnt);
    dh_ratchet(pubkey);
  }
  skip_messages(msg_cnt);

  m_recv_chain.cycle();
  mk = m_recv_chain.get_mk_key();

  m_mutex.unlock();

  return Crypto::decrypt(mk, ciphertext, header);
}

bytes_t DoubleRatchet::make_header(bytes_span_c_t pubkey,
                                   uint32_t prev_chain_cnt, uint32_t msg_cnt) {

  // + 4 in pubsize + 4 in prev_chain_cnt + 4 in msg_cnt
  bytes_t header(pubkey.size() + HEADER_CONST_SIZE);

  auto [s0, s1, s2, s3] = split(pubkey.size());
  auto [pcc0, pcc1, pcc2, pcc3] = split(prev_chain_cnt);
  auto [mc0, mc1, mc2, mc3] = split(msg_cnt);

  size_t id = 0;

  header[id++] = s0;
  header[id++] = s1;
  header[id++] = s2;
  header[id++] = s3;

  header[id++] = pcc0;
  header[id++] = pcc1;
  header[id++] = pcc2;
  header[id++] = pcc3;

  header[id++] = mc0;
  header[id++] = mc1;
  header[id++] = mc2;
  header[id++] = mc3;

  std::copy(std::begin(pubkey), std::end(pubkey), std::begin(header) + id);

  return header;
}

std::tuple<bytes_t, uint32_t, uint32_t>
DoubleRatchet::parse_header(bytes_span_c_t header) {
  std::array<uint8_t, 4> pubsize_arr{};
  std::array<uint8_t, 4> prevchain_arr{};
  std::array<uint8_t, 4> msgcnt_arr{};

  uint32_t pubsize = 0, prev_chain_cnt = 0, msg_cnt = 0;

  size_t id = 0;

  pubsize_arr[0] = header[id++];
  pubsize_arr[1] = header[id++];
  pubsize_arr[2] = header[id++];
  pubsize_arr[3] = header[id++];
  pubsize = join(pubsize_arr);

  prevchain_arr[0] = header[id++];
  prevchain_arr[1] = header[id++];
  prevchain_arr[2] = header[id++];
  prevchain_arr[3] = header[id++];
  prev_chain_cnt = join(prevchain_arr);

  msgcnt_arr[0] = header[id++];
  msgcnt_arr[1] = header[id++];
  msgcnt_arr[2] = header[id++];
  msgcnt_arr[3] = header[id++];
  msg_cnt = join(msgcnt_arr);

  bytes_t pubkey(pubsize);

  std::copy_n(std::begin(header) + id, pubsize, std::begin(pubkey));

  return {pubkey, prev_chain_cnt, msg_cnt};
}

void DoubleRatchet::skip_messages(uint32_t until) {
  if (m_recv_chain.curr_cycle() + MAX_SKIPPED < until) {
    throw std::runtime_error("Would reach maximum amount of skipped messages");
  }
  while (m_recv_chain.curr_cycle() < until) {
    m_skipped.insert(std::make_pair(
        std::make_pair(m_other_pub_key, m_recv_chain.curr_cycle()),
        m_recv_chain.get_mk_key()));
    m_recv_chain.cycle();
  }
}

void DoubleRatchet::dh_ratchet(bytes_span_c_t new_pubkey) {
  if (m_other_pub_key.empty())
    m_other_pub_key.resize(new_pubkey.size());
  assert(m_other_pub_key.size() == new_pubkey.size());
  std::copy(std::begin(new_pubkey), std::end(new_pubkey),
            std::begin(m_other_pub_key));

  bytes_32_t derive = KeyManager::deriveDHSecret(m_self_key_pair, {m_other_pub_key});
  auto [rootR, recvKey] = KDF::HKDF_pair(m_root_key, derive);
  m_root_key = rootR;
  m_recv_chain.set_key(recvKey);

  m_self_key_pair = KeyManager::genDHKeys();

  derive = KeyManager::deriveDHSecret(m_self_key_pair, {m_other_pub_key});
  auto [rootS, sendKey] = KDF::HKDF_pair(m_root_key, derive);
  m_root_key = rootS;
  m_send_chain.set_key(sendKey);
}