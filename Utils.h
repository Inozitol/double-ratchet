/*
Author: Pavel Horáček
 */

#pragma once

#include "Types.h"

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <span>
#include <stdexcept>
#include <vector>

namespace Utils {

template <typename T>
std::vector<T> concat(std::span<T const> a, std::span<T const> b) {
  std::vector<T> vec(a.size() + b.size());
  std::copy_n(std::begin(a), a.size(), std::begin(vec));
  std::copy_n(std::begin(b), b.size(), std::begin(vec) + a.size());
  return vec;
}

template <typename T, typename... Args>
std::vector<T> concat(std::span<T const> a, std::span<T const> b,
                      Args... args) {
  std::vector<T> rightVec = concat(b, args...);
  std::vector<T> finalVec(a.size() + rightVec.size());
  std::copy_n(std::begin(a), a.size(), std::begin(finalVec));
  std::copy_n(std::begin(rightVec), rightVec.size(),
              std::begin(finalVec) + rightVec.size());
  return finalVec;
}

inline uint32_t join(std::span<uint8_t const,4> val) {
  return (val[0] | val[1] << 8 | val[2] << 16 | val[3] << 24);
}

inline std::tuple<uint8_t,uint8_t,uint8_t,uint8_t> split(uint32_t val) {
  return {(val & 0xFF), (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF};
}

namespace Crypto {


inline bytes_t HKDF(bytes_span_32_c_t key, bytes_span_c_t input,
                    size_t size) {
  EVP_KDF *kdf = nullptr;
  EVP_KDF_CTX *kctx = nullptr;
  bytes_t derived(size);
  OSSL_PARAM params[5];

  if (nullptr == (kdf = EVP_KDF_fetch(nullptr, "hkdf", nullptr))) {
    throw std::runtime_error("Invalid return value from EVP_KDF_fetch");
  }
  if (nullptr == (kctx = EVP_KDF_CTX_new(kdf))) {
    throw std::runtime_error("Invalid return value from EVP_KDF_CTX_new");
  }

  std::string digest_str = "sha512";
  std::string info_str = "DoubleRatchet";

  params[0] = OSSL_PARAM_construct_utf8_string("digest", digest_str.data(),
                                               digest_str.size());
  params[1] =
      OSSL_PARAM_construct_octet_string("salt", const_cast<unsigned char*>(input.data()), input.size());
  params[2] = OSSL_PARAM_construct_octet_string("key", const_cast<unsigned char*>(key.data()), key.size());
  params[3] = OSSL_PARAM_construct_octet_string("info", info_str.data(),
                                                info_str.size());
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
    throw std::runtime_error(
        "Invalid return value from EVP_KDF_CTX_set_params");
  }

  if (EVP_KDF_derive(kctx, derived.data(), derived.size(), nullptr) <= 0) {
    throw std::runtime_error("Invalid return value from EVP_KDF_derive");
  }

  EVP_KDF_free(kdf);
  EVP_KDF_CTX_free(kctx);

  return derived;
}

inline bytes_32_t HMAC(bytes_span_32_c_t key, const bytes_t &input) {
  EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  std::string digest = "sha256";
  EVP_MAC_CTX *ctx = nullptr;
  size_t size = 0;
  bytes_32_t hmac{};
  unsigned int hmacsize = hmac.size();

  OSSL_PARAM params[3];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", digest.data(), 0);
  params[1] = OSSL_PARAM_construct_uint("size", &hmacsize);
  params[2] = OSSL_PARAM_construct_end();

  if (nullptr == (ctx = EVP_MAC_CTX_new(mac))) {
    throw std::runtime_error("Invalid return value from EVP_MAC_CTX_new");
  }

  if (1 != EVP_MAC_init(ctx, key.data(), key.size(), params)) {
    throw std::runtime_error("Invalid return value from EVP_MAC_init");
  }

  if (1 != EVP_MAC_update(ctx, input.data(), input.size())) {
    throw std::runtime_error("Invalid return value from EVP_MAC_update");
  }

  if (1 != EVP_MAC_final(ctx, hmac.data(), &size, hmac.size())) {
    throw std::runtime_error("Invalid return value from EVP_MAC_final");
  }
  assert(size == hmacsize);

  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);

  return hmac;
}

constexpr size_t HKDF_OUT_ENC_SIZE = 80;

inline bytes_t encrypt(bytes_span_32_c_t key, bytes_span_c_t plaintext, bytes_span_c_t assoc_data) {

  bytes_t ciphertext(plaintext.size()+16); // Add AES256 block size of space for padding
  int ciphersize;
  int paddedsize;

  bytes_t salt(HKDF_OUT_ENC_SIZE); // Initialized with zeros
  bytes_t hkdf = HKDF(key, salt, HKDF_OUT_ENC_SIZE);

  bytes_32_t enc_key{};
  bytes_32_t aut_key{};
  bytes_16_t iv{};

  // HKDF is split into encryption key, authentication key and IV
  std::copy_n(std::begin(hkdf), enc_key.size(), std::begin(enc_key));
  std::copy_n(std::begin(hkdf)+enc_key.size(), aut_key.size(), std::begin(aut_key));
  std::copy_n(std::begin(hkdf)+enc_key.size()+aut_key.size(), iv.size(), std::begin(iv));

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if(1 != EVP_EncryptInit_ex2(ctx, EVP_aes_256_cbc(), enc_key.data(), iv.data(), nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid return value from EVP_EncryptInit_ex2");
  }

  if(1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphersize, plaintext.data(), plaintext.size())) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid return value from EVP_EncryptUpdate");
  }

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext.data()+ciphersize, &paddedsize)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid return value from EVP_EncryptFinal_ex");
  }
  ciphersize += paddedsize;

  EVP_CIPHER_CTX_free(ctx);

  ciphertext.resize(ciphersize);

  // Create HMAC with authentication key and provided association + cipher data
  bytes_t hmac_data = Utils::concat<uint8_t>(assoc_data, ciphertext);
  bytes_32_t hmac = HMAC(aut_key, hmac_data);

  // Append HMAC after the ciphertext
  ciphertext = Utils::concat<uint8_t>(ciphertext, hmac);
  return ciphertext;
}

constexpr size_t HMAC_SIZE = 32;

inline bytes_t decrypt(bytes_span_32_c_t key, bytes_span_c_t ciphertext, bytes_span_c_t assoc_data) {
  bytes_t plaintext(ciphertext.size()-HMAC_SIZE);
  bytes_t ciphertext_copy(ciphertext.size());
  std::copy(std::begin(ciphertext), std::end(ciphertext), std::begin(ciphertext_copy));

  bytes_32_t recv_hmac{};
  bytes_32_t enc_key{};
  bytes_32_t aut_key{};
  bytes_16_t iv{};

  int plainsize;
  int paddedsize;

  std::copy_n(std::begin(ciphertext_copy)+ciphertext_copy.size()-HMAC_SIZE, HMAC_SIZE, std::begin(recv_hmac));
  ciphertext_copy.resize(ciphertext_copy.size()-HMAC_SIZE);

  bytes_t salt(HKDF_OUT_ENC_SIZE); // Initialized with zeros
  bytes_t hkdf = HKDF(key, salt, HKDF_OUT_ENC_SIZE);

  std::copy_n(std::begin(hkdf), enc_key.size(), std::begin(enc_key));
  std::copy_n(std::begin(hkdf)+enc_key.size(), aut_key.size(), std::begin(aut_key));
  std::copy_n(std::begin(hkdf)+enc_key.size()+aut_key.size(), iv.size(), std::begin(iv));

  bytes_t hmac_data = Utils::concat<uint8_t>(assoc_data, ciphertext_copy);
  bytes_32_t calc_hmac = HMAC(aut_key, hmac_data);

  if(calc_hmac != recv_hmac) {
   // throw std::runtime_error("Invalid HMAC encountered");
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if(1 != EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), enc_key.data(), iv.data(), nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid return value from EVP_EncryptInit_ex2");
  }

  if(1 != EVP_DecryptUpdate(ctx, plaintext.data(), &plainsize, ciphertext_copy.data(), ciphertext_copy.size())) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid return value from EVP_EncryptUpdate");
  }

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext.data()+plainsize, &paddedsize)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid return value from EVP_EncryptFinal_ex");
  }
  plainsize += paddedsize;
  EVP_CIPHER_CTX_free(ctx);
  plaintext.resize(plainsize);
  plaintext.shrink_to_fit();

  return plaintext;
}

} // namespace Crypto

}