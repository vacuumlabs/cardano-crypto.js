#ifndef ED25519_NO_SEED
#define ED25519_NO_SEED value
#endif
#include "vendor/cbits/ed25519/ed25519.h"
#include "vendor/cbits/encrypted_sign.h"
#include "vendor/cbits/hmac.h"
#include "vendor/cbits/cryptonite_cbits/blake2/ref/blake2.h"
#include "vendor/cbits/chachapoly/chachapoly.h"
#include "vendor/cbits/cryptonite_cbits/cryptonite_sha3.h"
#include <emscripten.h>

EMSCRIPTEN_KEEPALIVE
void emscripten_sign(const unsigned char *wallet_secret, const unsigned char *message, size_t message_len, unsigned char *signature){
  wallet_encrypted_sign((encrypted_key*) wallet_secret, NULL, 0, message, message_len, signature);
}

EMSCRIPTEN_KEEPALIVE
int emscripten_verify(const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *signature){
  return cardano_crypto_ed25519_sign_open(message, message_len, public_key, signature);
}

EMSCRIPTEN_KEEPALIVE
void emscripten_to_public(const unsigned char *secret_key, unsigned char *public_key) {
  cardano_crypto_ed25519_publickey(secret_key, public_key);
}

EMSCRIPTEN_KEEPALIVE
int emscripten_wallet_secret_from_seed(const unsigned char *seed, const unsigned char *chain_code, unsigned char *wallet_secret){
  return wallet_encrypted_from_secret(NULL, 0, seed, chain_code, (encrypted_key*) wallet_secret);
}

EMSCRIPTEN_KEEPALIVE
void emscripten_derive_private(const unsigned char *parent_private_key, uint32_t index, unsigned char *output, uint32_t mode){
  wallet_encrypted_derive_private((encrypted_key*) parent_private_key, NULL, 0, index, (encrypted_key*) output, mode);
}

EMSCRIPTEN_KEEPALIVE
int emscripten_derive_public(const unsigned char *parent_public_key, const unsigned char *parent_chain_code, uint32_t index, const unsigned char *child_public_key, const unsigned char *child_chain_code, uint32_t mode){
  return wallet_encrypted_derive_public((uint8_t*) parent_public_key, (uint8_t*) parent_chain_code, index, (uint8_t*) child_public_key, (uint8_t*) child_chain_code, mode);
}

EMSCRIPTEN_KEEPALIVE
int emscripten_blake2b(const unsigned char *in, size_t inlen, unsigned char *out, size_t out_len){
  return blake2b(out, out_len, in, inlen, NULL, 0);
}

EMSCRIPTEN_KEEPALIVE
void emscripten_sha3_256(const unsigned char *in, size_t inlen, unsigned char *out){
  struct sha3_ctx ctx;
  memset(&ctx, 0, sizeof(struct sha3_ctx));
  cryptonite_sha3_init(&ctx, 256);
  cryptonite_sha3_update(&ctx, in, inlen);
  cryptonite_sha3_finalize(&ctx, 256, out);
}


EMSCRIPTEN_KEEPALIVE
void emscripten_cardano_memory_combine(const uint8_t *pass, const uint32_t pass_len, const uint8_t *source, uint8_t *dest, uint32_t sz){
  memory_combine(pass, pass_len, source, dest, sz);
}

EMSCRIPTEN_KEEPALIVE
int emscripten_chacha20poly1305_enc(const uint8_t *key, const uint8_t *nonce, uint8_t *in, size_t in_len, uint8_t *out, uint8_t *tag, size_t tag_len, int encrypt){
  struct chachapoly_ctx ctx;
  memset(&ctx, 0, sizeof(struct chachapoly_ctx));

  chachapoly_init(&ctx, key, 256);
  return chachapoly_crypt(&ctx, nonce, NULL, 0, in, in_len, out, tag, tag_len, encrypt);
}

EMSCRIPTEN_KEEPALIVE
size_t emscripten_size_of_hmac_sha512_ctx(){
  return sizeof(HMAC_sha512_ctx);
}

EMSCRIPTEN_KEEPALIVE
void emscripten_hmac_sha512_init(HMAC_sha512_ctx *ctx, const uint8_t *in, size_t in_len){
  HMAC_sha512_init(ctx, in, in_len);
}

EMSCRIPTEN_KEEPALIVE
void emscripten_hmac_sha512_update(HMAC_sha512_ctx *ctx, const uint8_t *in, size_t in_len){
  HMAC_sha512_update(ctx, in, in_len);
}

EMSCRIPTEN_KEEPALIVE
void emscripten_hmac_sha512_final(HMAC_sha512_ctx *ctx, uint8_t *out){
  HMAC_sha512_final(ctx, out);
}