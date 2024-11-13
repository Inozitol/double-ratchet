/*
Author: Pavel Horáček
 */

#pragma once
#include "Utils.h"

#include <array>
#include <utility>

using namespace Utils::Crypto;

class KDF {
public:
 bytes_32_t cycle();

 void set_key(const bytes_32_t& key);
 [[nodiscard]] const bytes_32_t& get_mk_key() const;

 [[nodiscard]] uint32_t curr_cycle() const;
 [[nodiscard]] uint32_t prev_cycle() const;

 static std::pair<bytes_32_t, bytes_32_t> HKDF_pair(bytes_span_32_c_t key, bytes_span_c_t input);
 static std::pair<bytes_32_t, bytes_32_t> HMAC_pair(const bytes_32_t& key);

private:

 bytes_32_t m_key{};
 bytes_32_t m_out{};
 uint32_t m_cycle = 0;
 uint32_t m_prev_cycle = 0;
};