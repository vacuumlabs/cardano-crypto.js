#ifndef ED25519_NO_SEED
#define ED25519_NO_SEED value
#endif
#include "vendor/cbits/ed25519/ed25519.h"
#include "vendor/cbits/encrypted_sign.h"
#include <emscripten.h>

EMSCRIPTEN_KEEPALIVE
void sign(const unsigned char *wallet_secret, const unsigned char *message, uint32_t message_len, unsigned char *signature){
  wallet_encrypted_sign((encrypted_key*) wallet_secret, NULL, 0, message, message_len, signature);
}

EMSCRIPTEN_KEEPALIVE
int verify(const unsigned char *message, uint32_t message_len, const unsigned char *public_key, const unsigned char *signature){
  return cardano_crypto_ed25519_sign_open(message, message_len, public_key, signature);
}

EMSCRIPTEN_KEEPALIVE
int wallet_secret_from_seed(const unsigned char *seed, const unsigned char *chain_code, unsigned char *wallet_secret){
  return wallet_encrypted_from_secret(NULL, 0, seed, chain_code, (encrypted_key*) wallet_secret);
}

EMSCRIPTEN_KEEPALIVE
void derive_private(const unsigned char *parent_private_key, uint32_t index, unsigned char *output, uint32_t mode){
  wallet_encrypted_derive_private((encrypted_key*) parent_private_key, NULL, 0, index, (encrypted_key*) output, mode);
}

EMSCRIPTEN_KEEPALIVE
void derive_public(const unsigned char *parent_public_key, const unsigned char *parent_chain_code, uint32_t index, const unsigned char *child_public_key, const unsigned char *child_chain_code, uint32_t mode){
  wallet_encrypted_derive_public((uint8_t*) parent_public_key, (uint8_t*) parent_chain_code, index, (uint8_t*) child_public_key, (uint8_t*) child_chain_code, mode);
}
