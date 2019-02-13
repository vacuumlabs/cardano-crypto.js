# cardano-crypto.js
* [input-output-hk/cardano-crypto](https://github.com/input-output-hk/cardano-crypto/tree/master/cbits)
* [haskell-crypto/cryptonite](https://github.com/haskell-crypto/cryptonite)
* [grigorig/chachapoly](https://github.com/grigorig/chachapoly)

compiled to pure javascript using Emscripten. This is a collection of cryptolibraries and functions useful for working with Cardano cryptocurrency, eliminating the need for many dependencies.

# examples
## signing

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var walletSecret = await lib.mnemonicToRootKeypair(mnemonic, 1)
var msg = new Buffer('hello there')
var sig = lib.sign(msg, walletSecret)
```

## deriving child keys (hardened derivation, you can choose either derivation scheme 1 or 2)

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var parentWalletSecret = lib.mnemonicToRootKeypair(mnemonic, 1)
var childWalletSecret = lib.derivePrivate(parentWalletSecret, 0x80000001, 1)
```

## deriving child public keys (nonhardened derivation, you can choose either derivation scheme 1 or 2)

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var parentWalletSecret = lib.mnemonicToRootKeypair(mnemonic, 1)
var parentWalletPublicKey = parentWalletSecret.slice(64, 128)
var childWalletSecret = lib.derivePublic(parentWalletPublicKey, 1, 1)
```

# available functions

* `Buffer sign(Buffer msg, Buffer walletSecret)`
* `Bool verify(Buffer msg, Buffer publicKey, Buffer sig)`
* `async Buffer mnemonicToRootKeypair(String mnemonic, int derivationScheme)`
* `Buffer derivePrivate(Buffer parentKey, int index, int derivationScheme)`
* `Buffer derivePublic(Buffer parentExtPubKey, int index, int derivationScheme)`
* `Buffer decodePaperWalletMnemonic(string paperWalletMnemonic)`
* `Buffer xpubToHdPassphrase(Buffer xpub)`
* `string packAddress(Array[int] derivationPath, Buffer xpub, Buffer hdPassphrase, int derivationScheme)`
* `string unpackAddress(string address, Buffer hdPassphrase)`
* `Bool isValidAddress(string address)`
* `Buffer blake2b(Buffer input, outputLen)`
* `Buffer cardanoMemoryCombine(Buffer input, String password)`
* `[base58](https://www.npmjs.com/package/base58)`
* `[scrypt](https://www.npmjs.com/package/scrypt-async)`

We encourage you to take a look `at test/index.js` to see how the functions above should be used.

# development

* Install [emscripten](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html#installation-instructions), recommended version is 1.38.8
* run `npm install`
* run `npm run build`

# tests

* run `npm run test`
