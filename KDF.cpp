/*
Author: Pavel Horáček
 */

#include "KDF.h"
#include "Types.h"
#include "Utils.h"

#include <algorithm>

bytes_32_t KDF::cycle() {
  auto [key, out] = HMAC_pair(m_key);
  m_key = key;
  m_cycle++;
  return out;
}

void KDF::set_key(const bytes_32_t &key) {
  m_key = key;
  m_prev_cycle = m_cycle;
  m_cycle = 0;
}

const bytes_32_t &KDF::get_key() const { return m_key; }
uint32_t KDF::curr_cycle() const {return m_cycle;}
uint32_t KDF::prev_cycle() const {return m_prev_cycle;}

std::pair<bytes_32_t, bytes_32_t>
KDF::HKDF_pair(bytes_span_32_c_t key, bytes_span_c_t input) {

  bytes_t hkdf = HKDF(key, input, key.size() * 2);
  bytes_32_t kdfkey;
  bytes_32_t outkey;
  std::copy_n(std::begin(hkdf), kdfkey.size(), std::begin(kdfkey));
  std::copy_n(std::begin(hkdf)+kdfkey.size(), outkey.size(), std::begin(outkey));

  return {kdfkey, outkey};
}

std::pair<bytes_32_t, bytes_32_t>
KDF::HMAC_pair(const bytes_32_t &key) {
  bytes_t in1 = {'\x1'};
  bytes_t in2 = {'\x2'};

  bytes_32_t hmac1 = HMAC(key, in1);
  bytes_32_t hmac2 = HMAC(key, in2);

  return {hmac1, hmac2};
}
