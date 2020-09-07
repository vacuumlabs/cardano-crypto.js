# cardano-crypto.js
* [input-output-hk/cardano-crypto](https://github.com/input-output-hk/cardano-crypto/tree/master/cbits)
* [haskell-crypto/cryptonite](https://github.com/haskell-crypto/cryptonite)
* [grigorig/chachapoly](https://github.com/grigorig/chachapoly)

Compiled to pure javascript using Emscripten. This is a collection of cryptolibraries and functions useful for working with Cardano cryptocurrency, eliminating the need for many dependencies.

# Examples
## Signing

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var walletSecret = await lib.mnemonicToRootKeypair(mnemonic, 1)
var msg = new Buffer('hello there')
var sig = lib.sign(msg, walletSecret)
```

## Deriving child keys (hardened derivation, you can choose either derivation scheme 1 or 2)

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var parentWalletSecret = lib.mnemonicToRootKeypair(mnemonic, 1)
var childWalletSecret = lib.derivePrivate(parentWalletSecret, 0x80000001, 1)
```

## Deriving child public keys (nonhardened derivation, you can choose either derivation scheme 1 or 2)

``` javascript
var lib = require('cardano-crypto.js')

var mnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var parentWalletSecret = lib.mnemonicToRootKeypair(mnemonic, 1)
var parentWalletPublicKey = parentWalletSecret.slice(64, 128)
var childWalletSecret = lib.derivePublic(parentWalletPublicKey, 1, 1)
```

# Available Functions

## Signing/Verification
* `Buffer sign(Buffer msg, Buffer walletSecret)`
* `Bool verify(Buffer msg, Buffer publicKey, Buffer sig)`

## Key derivation
* `async Buffer mnemonicToRootKeypair(String mnemonic, int derivationScheme)`
* `Buffer derivePrivate(Buffer parentKey, int index, int derivationScheme)`
* `Buffer derivePublic(Buffer parentExtPubKey, int index, int derivationScheme)`
* `Buffer toPublic(Buffer privateKey)`

## Address encoding/decoding/validation
* `Buffer packBootstrapAddress(Array[int] derivationPath, Buffer xpub, Buffer hdPassphrase, int derivationScheme, int protocolMagic)`
* `Buffer packBaseAddress(Buffer spendingKeyHash, Buffer stakingPubKey, int networkId)`
* `Buffer packPointerAddress(Buffer pubKeyHash, Object pointer, int networkId)`
* `Buffer packEnterpriseAddress(Buffer spendingKeyHash, int networkId)`
* `Buffer packRewardAddress(Buffer stakingKeyHash, int networkId)`
* `Object getAddressType(Buffer address)`
* `Object getShelleyAddressInfo(Buffer address)`
* `Object AddressTypes`
* `Buffer addressToBuffer(string address) // address can be either bech32 or base58 encoded`
* `Map getBootstrapAddressAttributes(Buffer address)`
* `Array<int>? getBootstrapAddressDerivationPath(Buffer address, Buffer hdPassphrase)`
* `int getBootstrapAddressProtocolMagic(Buffer address)`
* `Bool isValidBootstrapAddress(string address)`
* `Bool isValidShelleyAddress(string address)`
* `Buffer xpubToHdPassphrase(Buffer xpub)`
* `Buffer getPubKeyBlake2b224Hash(Buffer pubKey)`

## Cardano crypto primitives
* `Buffer blake2b(Buffer input, outputLen)`
* `Buffer cardanoMemoryCombine(Buffer input, String password)`
* `string bech32.encode(string prefix, Buffer data)`
* `Object bech32.decode(string address)` 
* `[base58](https://www.npmjs.com/package/base58)`
* `[scrypt](https://www.npmjs.com/package/scrypt-async)`

## Daedalus paper wallets (27-word mnemonics)
* `Buffer decodePaperWalletMnemonic(string paperWalletMnemonic)`

We encourage you to take a look `at test/index.js` to see how the functions above should be used.

# Development

* Install [emscripten](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html#installation-instructions), recommended version is 1.38.8
* run `npm install`
* run `npm run build`

# Emscripten build example

```
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install 1.39.19
./emsdk activate 1.39.19
source ./emsdk_env.sh
cd ../
git clone https://github.com/vacuumlabs/cardano-crypto.js
cd cardano-crypto.js
npm install
npm run build
shasum lib.js # should match shasum of published version of lib.js
```

# known issues

When trying to compile the library with emscripten 1.38.41, the `cardanoMemoryCombine` function slows down significantly. With the 1.38.8 version it runs significantly faster.

# tests

* run `npm run test`

# Removing wordlists from webpack/browserify

* [bitcoinjs/bip39](https://github.com/bitcoinjs/bip39)

Browserify/Webpack bundles can get very large if you include all the wordlists, so you can now exclude wordlists to make your bundle lighter.

For example, if we want to exclude all wordlists besides chinese_simplified, you could build using the browserify command below.

 ```bash
$ browserify -r bip39 -s bip39 \
  --exclude=./wordlists/english.json \
  --exclude=./wordlists/japanese.json \
  --exclude=./wordlists/spanish.json \
  --exclude=./wordlists/italian.json \
  --exclude=./wordlists/french.json \
  --exclude=./wordlists/korean.json \
  --exclude=./wordlists/chinese_traditional.json \
   > bip39.browser.js
```

 This will create a bundle that only contains the chinese_simplified wordlist, and it will be the default wordlist for all calls without explicit wordlists.
 
 You can also do this in Webpack using the `IgnorePlugin`. Here is an example of excluding all non-English wordlists
 
 ```javascript
 ...
 plugins: [
   new webpack.IgnorePlugin(/^\.\/wordlists\/(?!english)/, /bip39\/src$/),
 ],
 ...
 ```
