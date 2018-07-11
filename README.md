# cardano-crypto.js
[input-output-hk/cardano-crypto](https://github.com/input-output-hk/cardano-crypto/tree/master/cbits) compiled to pure javascript using Emscripten

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

# development

* Install [emscripten](https://askubuntu.com/questions/891630/how-to-install-the-latest-emscripten-on-ubuntu-using-command-line)
* run `npm install`
* run `npm run build`
