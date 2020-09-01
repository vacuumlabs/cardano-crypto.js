const crypto = require('./features/crypto-primitives')
const address = require('./features/address');
const keyDerivation = require('./features/key-derivation')
const signing = require('./features/signing')
const paperWallets = require('./features/paper-wallets')

const base58 = require('./utils/base58')
const bech32 = require('./utils/bech32')
const scrypt = require('./utils/scrypt-async')

const Module = require('./lib.js')

module.exports = {
  ...address,
  ...keyDerivation,
  ...signing,
  ...paperWallets,
  base58,
  bech32,
  scrypt,
  blake2b: crypto.blake2b,
  cardanoMemoryCombine: crypto.cardanoMemoryCombine,
  _sha3_256: crypto.sha3_256,
  _chacha20poly1305Decrypt: crypto.chacha20poly1305Decrypt,
  _chacha20poly1305Encrypt: crypto.chacha20poly1305Encrypt,
}
