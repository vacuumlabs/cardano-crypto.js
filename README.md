# cardano-crypto.js
* [input-output-hk/cardano-crypto](https://github.com/input-output-hk/cardano-crypto/tree/master/cbits)
* [haskell-crypto/cryptonite](https://github.com/haskell-crypto/cryptonite)
* [grigorig/chachapoly](https://github.com/grigorig/chachapoly)

compiled to pure javascript using Emscripten. This is a collection of cryptolibraries useful for doing Cardano cryptography, eliminating the need for many dependencies.

# examples
## signing

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var walletSecret = lib.walletSecretFromMnemonic(mnemonic)
var msg = new Buffer('hello there')
var sig = lib.sign(msg, walletSecret)
```

## deriving child keys (hardened derivation, you can choose either derivation mode 1 or 2)

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var parentWalletSecret = lib.walletSecretFromMnemonic(mnemonic)
var childWalletSecret = lib.derivePrivate(parentWalletSecret, 0x80000001, 1)
```

## deriving child public keys (nonhardened derivation, you can choose either derivation mode 1 or 2)

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var parentWalletSecret = lib.walletSecretFromMnemonic(mnemonic)
var parentWalletPublicKey = parentWalletSecret.slice(64, 128)
var childWalletSecret = lib.derivePublic(parentWalletPublicKey, 1, 1)
```

# available functions

* `Buffer sign(Buffer msg, Buffer walletSecret)`
* `Bool verify(Buffer msg, Buffer publicKey, Buffer sig)`
* `Buffer walletSecretFromMnemonic(String mnemonic)`
* `Buffer derivePrivate(Buffer parentKey, int index, int derivationMode)`
* `Buffer derivePublic(Buffer parentExtPubKey, int index, int derivationMode)`
* `Buffer blake2b(Buffer input, outputLen)`
* `Buffer sha3_256(Buffer input)`
* `Buffer chacha20poly1305Encrypt(Buffer input, Buffer key, Buffer nonce)`
* `Buffer chacha20poly1305Decrypt(Buffer input, Buffer key, Buffer nonce)`
* `Buffer cardanoMemoryCombine(Buffer input, String password)`

We encourage you to take a look `at test/index.js` to see how the functions above should be used.

# development

* Install [emscripten](https://askubuntu.com/questions/891630/how-to-install-the-latest-emscripten-on-ubuntu-using-command-line)
* run `npm install`
* run `npm run build`

# tests

* run `npm run test`