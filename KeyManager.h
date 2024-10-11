/*
Author: Pavel Horáček
 */

#pragma once

#define DH_KEY_TYPE EVP_PKEY_X25519

#include "Utils.h"

#include <array>
#include <cstdint>
#include <vector>

#include <openssl/ec.h>

using namespace Utils;

struct KeyPair {
  bytes_t pubKey;
  bytes_t priKey;
};

namespace KeyManager {
EVP_PKEY *genDHKeys_EVP();
bytes_32_t deriveDHSecret_EVP(EVP_PKEY *pkey, EVP_PKEY *peerkey);

KeyPair genDHKeys();
bytes_32_t deriveDHSecret(const KeyPair& pkey_pair, const KeyPair& peerkey_pair);

KeyPair serializeKeys(EVP_PKEY *key, bool hasPrivate);
EVP_PKEY *deserializeKeys(const KeyPair &kPair);

bytes_t serializePublicKey(bytes_span_c_t pubkey);
KeyPair deserializePublicKey(bytes_span_c_t serial_pubkey);
}