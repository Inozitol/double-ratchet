/*
Author: Pavel Horáček
 */

#include "KeyManager.h"

#include <cassert>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdexcept>

EVP_PKEY *KeyManager::genDHKeys_EVP() {
  EVP_PKEY_CTX *pctx, *kctx;
  EVP_PKEY *pkey = nullptr, *params = nullptr;

  if (nullptr == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr))) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_CTX_new_id");
  }

  if (1 != EVP_PKEY_paramgen_init(pctx)) {
    throw std::runtime_error(
        "Invalid return value from EVP_PKEY_paramgen_init");
  }

  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X25519)) {
    throw std::runtime_error(
        "Invalid return value from EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
  }

  if (!EVP_PKEY_paramgen(pctx, &params)) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_paramgen");
  }

  if (nullptr == (kctx = EVP_PKEY_CTX_new(params, nullptr))) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_CTX_new");
  }

  if (1 != EVP_PKEY_keygen_init(kctx)) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_keygen_init");
  }

  if (1 != EVP_PKEY_keygen(kctx, &pkey)) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_keygen");
  }

  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(params);

  return pkey;
}

bytes_32_t KeyManager::deriveDHSecret_EVP(EVP_PKEY *pkey, EVP_PKEY *peerkey) {
  assert(peerkey);
  EVP_PKEY_CTX *ctx;
  if(nullptr == (ctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_CTX_new");
  }

  if(1 != EVP_PKEY_derive_init(ctx)) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_derive_init");
  }

  if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_derive_set_peer");
  }

  size_t secretlen;
  bytes_32_t secret;

  if(1 != EVP_PKEY_derive(ctx, nullptr, &secretlen)) {
    throw std::runtime_error("Failed to determine secret size with EVP_PKEY_derive(ctx, nullptr, secretlen)");
  }

  assert(secretlen == secret.size());

  if(1 != EVP_PKEY_derive(ctx, secret.data(), &secretlen)) {
    throw std::runtime_error("Invalid return value from EVP_PKEY_derive");
  }

  EVP_PKEY_CTX_free(ctx);

  return secret;
}

KeyPair KeyManager::genDHKeys() {
  EVP_PKEY* pkey = genDHKeys_EVP();
  KeyPair pair = serializeKeys(pkey, true);
  EVP_PKEY_free(pkey);
  return pair;
}

bytes_32_t KeyManager::deriveDHSecret(const KeyPair &pkey_pair,
                                       const KeyPair &peerkey_pair) {
  EVP_PKEY* pkey = deserializeKeys(pkey_pair);
  EVP_PKEY* peerkey = deserializeKeys(peerkey_pair);
  bytes_32_t derive = deriveDHSecret_EVP(pkey, peerkey);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(peerkey);

  return derive;
}


KeyPair KeyManager::serializeKeys(EVP_PKEY *key, bool hasPrivate) {
  unsigned char* data;
  OSSL_ENCODER_CTX* enc_ctx;

  enc_ctx = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_PUBLIC_KEY, "DER", nullptr, nullptr);
  std::size_t pubSize = 0;
  OSSL_ENCODER_to_data(enc_ctx, nullptr, &pubSize);
  auto pubKey = bytes_t(pubSize);
  data = pubKey.data();
  OSSL_ENCODER_to_data(enc_ctx, &data, &pubSize);
  OPENSSL_free(enc_ctx);
  assert(pubSize == 0);

  if(!hasPrivate) {
    return KeyPair{pubKey};
  }

  enc_ctx = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, "DER", nullptr, nullptr);
  std::size_t priSize = 0;
  OSSL_ENCODER_to_data(enc_ctx, nullptr, &priSize);
  auto priKey = bytes_t(priSize);
  data = priKey.data();
  OSSL_ENCODER_to_data(enc_ctx, &data, &priSize);
  OPENSSL_free(enc_ctx);
  assert(priSize == 0);

  return KeyPair{pubKey, priKey};
}

EVP_PKEY *KeyManager::deserializeKeys(const KeyPair &kPair) {
  assert(!kPair.pubKey.empty());

  EVP_PKEY *pkey = nullptr;
  const unsigned char *data = nullptr;
  OSSL_DECODER_CTX *dec_ctx = nullptr;

  dec_ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", nullptr, nullptr,
                                          OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                          nullptr, nullptr);
  data = kPair.pubKey.data();
  size_t pubSize = kPair.pubKey.size();
  OSSL_DECODER_from_data(dec_ctx, &data, &pubSize);
  OPENSSL_free(dec_ctx);

  // If the private key is empty, return EVP_PKEY with public only
  if(kPair.priKey.empty()) {
    return pkey;
  }

  dec_ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", nullptr, nullptr,
                                          OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                          nullptr, nullptr);
  data = kPair.priKey.data();
  size_t priSize = kPair.priKey.size();
  OSSL_DECODER_from_data(dec_ctx, &data, &priSize);
  OPENSSL_free(dec_ctx);

  return pkey;
}

bytes_t KeyManager::serializePublicKey(bytes_span_c_t pubkey) {
  bytes_t serial(pubkey.size() + 4); // +4 for pubkey size
  auto [s0, s1, s2, s3] = split(pubkey.size());
  size_t id = 0;
  serial[id++] = s0;
  serial[id++] = s1;
  serial[id++] = s2;
  serial[id++] = s3;

  std::copy(std::begin(pubkey), std::end(pubkey), std::begin(serial) + id);
  return serial;
}

KeyPair KeyManager::deserializePublicKey(bytes_span_c_t serial_pubkey) {
  std::array<uint8_t, 4> pubsize_arr{};
  uint32_t pubsize = 0;

  size_t id = 0;

  pubsize_arr[0] = serial_pubkey[id++];
  pubsize_arr[1] = serial_pubkey[id++];
  pubsize_arr[2] = serial_pubkey[id++];
  pubsize_arr[3] = serial_pubkey[id++];
  pubsize = join(pubsize_arr);

  bytes_t pubkey(pubsize);

  std::copy_n(std::begin(serial_pubkey) + id, pubsize, std::begin(pubkey));

  return {pubkey};
}
