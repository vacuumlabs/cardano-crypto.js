#ifndef ED25519_NO_SEED
#define ED25519_NO_SEED value
#endif
#include "vendor/cbits/ed25519/ed25519.h"
#include "vendor/cbits/encrypted_sign.h"
#include "vendor/cbits/cryptonite_cbits/blake2/ref/blake2.h"
//#include "vendor/cbits/c20p1305/chacha20poly1305.h"
#include <emscripten.h>

EMSCRIPTEN_KEEPALIVE
void sign(const unsigned char *wallet_secret, const unsigned char *message, size_t message_len, unsigned char *signature){
  wallet_encrypted_sign((encrypted_key*) wallet_secret, NULL, 0, message, message_len, signature);
}

EMSCRIPTEN_KEEPALIVE
int verify(const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *signature){
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

EMSCRIPTEN_KEEPALIVE
int blake2b256(const unsigned char *in, size_t inlen, unsigned char *out){
  return blake2b(out, 32, in, inlen, NULL, 0);
}

EMSCRIPTEN_KEEPALIVE
void cardano_memory_combine(const uint8_t *pass, const uint32_t pass_len, const uint8_t *source, uint8_t *dest, uint32_t sz){
  memory_combine(pass, pass_len, source, dest, sz);
}
/*
EMSCRIPTEN_KEEPALIVE
void chacha20poly1305_enc(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, const size_t n){
  chacha20poly1305_ctx ctx;
  
  memset(&ctx, 0, sizeof(chacha20poly1305_ctx));
  xchacha20poly1305_init(&ctx, key, nonce);
  chacha20poly1305_encrypt(&ctx, in, out, n);
}

EMSCRIPTEN_KEEPALIVE
void chacha20poly1305_dec(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, const size_t n){
  chacha20poly1305_ctx ctx;
  
  memset(&ctx, 0, sizeof(chacha20poly1305_ctx));
  xchacha20poly1305_init(&ctx, key, nonce);
  chacha20poly1305_decrypt(&ctx, in, out, n);
}
*/