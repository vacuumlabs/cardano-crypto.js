var bip39 = require('bip39-light')

var Module = require('./lib.js')
var crc32 = require('./utils/crc32')
var base58 = require('./utils/base58')
var scrypt = require('./utils/scrypt-async')


function validateDerivationMode(input) {
  if (input !== 1 && input !== 2) {
    throw new Error('invalid derivation mode!')
  }
}

function validateBuffer(input, expectedLength) {
  if(!Buffer.isBuffer(input)){
    throw new Error('not buffer!')
  }

  if (expectedLength && input.length !== expectedLength) {
    throw new Error('Invalid buffer length')
  }
}

function validateArray(input) {
  if (typeof(input) !== typeof([])) {
    throw new Error('not an array!')
  }
}

function validateDerivationIndex(input) {
  if (!Number.isInteger(input)) {
    throw new Error('invalid derivation index!')
  }
}

function validateBool(input) {
  if (typeof(input) !== typeof(true)) {
    throw new Error('not a boolean!')
  }
}

function validateString(input) {
  if (typeof(input) !== typeof('aa')) {
    throw new Error('not a string!')
  }
}

function cborEncodeBuffer(input) {
  validateBuffer(input)

  var len = input.length
  var cborPrefix = []

  if (len < 24) {
    cborPrefix = [0x40 + len]
  } else if (len < 256) {
    cborPrefix = [0x58, len]
  } else {
    throw Error('CBOR encode for more than 256 bytes not yet implemented')
  }

  return Buffer.concat([Buffer.from(cborPrefix), input])
}

function sign(msg, walletSecret) {
  validateBuffer(msg)
  validateBuffer(walletSecret, 128)

  var msgLen = msg.length
  var msgArrPtr = Module._malloc(msgLen)
  var msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen)
  var walletSecretArrPtr = Module._malloc(128)
  var walletSecretArr = new Uint8Array(Module.HEAPU8.buffer, walletSecretArrPtr, 128)
  var sigPtr = Module._malloc(64)
  var sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64)

  msgArr.set(msg)
  walletSecretArr.set(walletSecret)

  Module._emscripten_sign(walletSecretArrPtr, msgArrPtr, msgLen, sigPtr)
  Module._free(msgArrPtr)
  Module._free(walletSecretArrPtr)
  Module._free(sigPtr)

  return new Buffer(sigArr)
}

function verify(msg, publicKey, sig) {
  validateBuffer(msg)
  validateBuffer(publicKey, 32)
  validateBuffer(sig, 64)

  var msgLen = msg.length
  var msgArrPtr = Module._malloc(msgLen)
  var msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen)
  var publicKeyArrPtr = Module._malloc(32)
  var publicKeyArr = new Uint8Array(Module.HEAPU8.buffer, publicKeyArrPtr, 32)
  var sigPtr = Module._malloc(64)
  var sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64)

  msgArr.set(msg)
  publicKeyArr.set(publicKey)
  sigArr.set(sig)

  var result = Module._emscripten_verify(msgArrPtr, msgLen, publicKeyArrPtr, sigPtr) === 0

  Module._free(msgArrPtr)
  Module._free(publicKeyArrPtr)
  Module._free(sigPtr)

  return result
}

function walletSecretFromSeed(seed, chainCode) {
  validateBuffer(seed, 32)
  validateBuffer(chainCode, 32)

  var seedArrPtr = Module._malloc(32)
  var seedArr = new Uint8Array(Module.HEAPU8.buffer, seedArrPtr, 32)
  var chainCodeArrPtr = Module._malloc(32)
  var chainCodeArr = new Uint8Array(Module.HEAPU8.buffer, chainCodeArrPtr, 32)
  var walletSecretArrPtr = Module._malloc(128)
  var walletSecretArr = new Uint8Array(Module.HEAPU8.buffer, walletSecretArrPtr, 128)

  seedArr.set(seed)
  chainCodeArr.set(chainCode)

  const returnCode = Module._emscripten_wallet_secret_from_seed(seedArrPtr, chainCodeArrPtr, walletSecretArrPtr)

  Module._free(seedArrPtr)
  Module._free(chainCodeArrPtr)
  Module._free(walletSecretArrPtr)

  if (returnCode === 1) {
    const e = new Error('Invalid secret')
    e.name = 'InvalidSecret'

    throw e
  }

  return new Buffer(walletSecretArr)
}

function mnemonicToHashSeed(mnemonic) {
  if (!bip39.validateMnemonic(mnemonic)) {
    const e = new Error('Invalid or unsupported mnemonic format')
    e.name = 'InvalidArgumentException'
    throw e
  }

  const ent = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex')

  return cborEncodeBuffer(blake2b(cborEncodeBuffer(ent), 32))
}

function walletSecretFromMnemonic(mnemonic) {
  var hashSeed = mnemonicToHashSeed(mnemonic)
  var result

  for (var i = 1; result === undefined && i <= 1000; i++) {
    try {
      var digest = hmac_sha512(hashSeed, [Buffer.from(`Root Seed Chain ${i}`, 'ascii')])
      var seed = digest.slice(0, 32)
      var chainCode = digest.slice(32, 64)

      result = walletSecretFromSeed(seed, chainCode)

    } catch (e) {
      if (e.name === 'InvalidSecret') {
        continue
      }

      throw e
    }
  }

  if (result === undefined) {
    var e = new Error('Secret key generation from mnemonic is looping forever')
    e.name = 'RuntimeException'
    throw e
  }

  return result
}



function derivePrivate(parentKey, index, derivationMode) {
  validateBuffer(parentKey, 128)
  validateDerivationIndex(index)
  validateDerivationMode(derivationMode)

  var parentKeyArrPtr = Module._malloc(128)
  var parentKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentKeyArrPtr, 128)
  var childKeyArrPtr = Module._malloc(128)
  var childKeyArr = new Uint8Array(Module.HEAPU8.buffer, childKeyArrPtr, 128)

  parentKeyArr.set(parentKey)

  Module._emscripten_derive_private(parentKeyArrPtr, index, childKeyArrPtr, derivationMode)
  Module._free(parentKeyArrPtr)
  Module._free(childKeyArrPtr)

  return new Buffer(childKeyArr)
}

function derivePublic(parentExtPubKey, index, derivationMode) {
  validateBuffer(parentExtPubKey, 64)
  validateDerivationIndex(index)
  validateDerivationMode(derivationMode)

  var parentPubKey = parentExtPubKey.slice(0, 32)
  var parentChainCode = parentExtPubKey.slice(32, 64)

  var parentPubKeyArrPtr = Module._malloc(32)
  var parentPubKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentPubKeyArrPtr, 32)
  var parentChainCodeArrPtr = Module._malloc(32)
  var parentChainCodeArr = new Uint8Array(Module.HEAPU8.buffer, parentChainCodeArrPtr, 32)

  var childPubKeyArrPtr = Module._malloc(32)
  var childPubKeyArr = new Uint8Array(Module.HEAPU8.buffer, childPubKeyArrPtr, 32)
  var childChainCodeArrPtr = Module._malloc(32)
  var childChainCodeArr = new Uint8Array(Module.HEAPU8.buffer, childChainCodeArrPtr, 32)

  parentPubKeyArr.set(parentPubKey)
  parentChainCodeArr.set(parentChainCode)

  var resultCode = Module._emscripten_derive_public(parentPubKeyArrPtr, parentChainCodeArrPtr, index, childPubKeyArrPtr, childChainCodeArrPtr, derivationMode)

  Module._free(parentPubKeyArrPtr)
  Module._free(parentChainCodeArrPtr)
  Module._free(parentPubKeyArrPtr)
  Module._free(parentChainCodeArrPtr)

  if (resultCode !== 0) {
    throw Error(`derivePublic has exited with code ${resultCode}`)
  }

  return Buffer.concat([new Buffer(childPubKeyArr), new Buffer(childChainCodeArr)])
}

function blake2b(input, outputLen) {
  validateBuffer(input)

  var inputLen = input.length
  var inputArrPtr = Module._malloc(inputLen)
  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)
  var outputArrPtr = Module._malloc(outputLen)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)

  Module._emscripten_blake2b(inputArrPtr, inputLen, outputArrPtr, outputLen)

  Module._free(inputArrPtr)
  Module._free(outputArrPtr)

  return Buffer.from(outputArr)
}

function sha3_256(input) {
  validateBuffer(input)
  var inputLen = input.length
  var inputArrPtr = Module._malloc(inputLen)
  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  var outputLen = 32
  var outputArrPtr = Module._malloc(outputLen)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)

  Module._emscripten_sha3_256(inputArrPtr, inputLen, outputArrPtr)

  Module._free(inputArrPtr)
  Module._free(outputArrPtr)

  return Buffer.from(outputArr)
}

function hmac_sha512(initKey, inputs) {
  validateBuffer(initKey)
  validateArray(inputs)
  inputs.map(validateBuffer)

  var ctxLen = Module._emscripten_size_of_hmac_sha512_ctx()
  var ctxArrPtr = Module._malloc(ctxLen)
  var ctxArr = new Uint8Array(Module.HEAPU8.buffer, ctxArrPtr, ctxLen)

  var initKeyLen = initKey.length
  var initKeyArrPtr = Module._malloc(initKeyLen)
  var initKeyArr = new Uint8Array(Module.HEAPU8.buffer, initKeyArrPtr, initKeyLen)

  var outputLen = 64
  var outputArrPtr = Module._malloc(outputLen)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  initKeyArr.set(initKey)

  Module._emscripten_hmac_sha512_init(ctxArrPtr, initKeyArrPtr, initKeyLen)

  for (var i = 0; i < inputs.length; i++) {
    var inputLen = inputs[i].length
    var inputArrPtr = Module._malloc(inputLen)
    var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

    inputArr.set(inputs[i])

    Module._emscripten_hmac_sha512_update(ctxArrPtr, inputArrPtr, inputLen)

    Module._free(inputArrPtr)
  }

  Module._emscripten_hmac_sha512_final(ctxArrPtr, outputArrPtr)

  Module._free(initKeyArrPtr)
  Module._free(ctxArrPtr)
  Module._free(outputArrPtr)

  return Buffer.from(outputArr)
}

function cardanoMemoryCombine(input, password) {
  validateString(password)
  validateBuffer(input)

  if (password === '') {
    return input
  }

  var transformedPassword = blake2b(Buffer.from(password, 'utf-8'), 32)
  var transformedPasswordLen = transformedPassword.length
  var transformedPasswordArrPtr = Module._malloc(transformedPasswordLen)
  var transformedPasswordArr = new Uint8Array(Module.HEAPU8.buffer, transformedPasswordArrPtr, transformedPasswordLen)

  var inputLen = input.length
  var inputArrPtr = Module._malloc(inputLen)
  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  var outputArrPtr = Module._malloc(inputLen)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, inputLen)

  inputArr.set(input)
  transformedPasswordArr.set(transformedPassword)

  Module._emscripten_cardano_memory_combine(transformedPasswordArrPtr, transformedPasswordLen, inputArrPtr, outputArrPtr, inputLen)

  Module._free(inputArrPtr)
  Module._free(outputArrPtr)
  Module._free(transformedPasswordArrPtr)

  return Buffer.from(outputArr)
}

function chacha20poly1305Encrypt(input, key, nonce) {
  validateBuffer(input)
  validateBuffer(key, 32)
  validateBuffer(nonce, 12)

  var inputLen = input.length
  var inputArrPtr = Module._malloc(inputLen)
  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  var keyLen = key.length
  var keyArrPtr = Module._malloc(keyLen)
  var keyArr = new Uint8Array(Module.HEAPU8.buffer, keyArrPtr, keyLen)

  var nonceLen = nonce.length
  var nonceArrPtr = Module._malloc(nonceLen)
  var nonceArr = new Uint8Array(Module.HEAPU8.buffer, nonceArrPtr, nonceLen)

  var tagLen = 16
  var outputLen = inputLen + tagLen
  var outputArrPtr = Module._malloc(outputLen)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)
  keyArr.set(key)
  nonceArr.set(nonce)

  var resultCode = Module._emscripten_chacha20poly1305_enc(keyArrPtr, nonceArrPtr, inputArrPtr, inputLen, outputArrPtr, outputArrPtr + inputLen, tagLen, 1)

  Module._free(inputArrPtr)
  Module._free(keyArrPtr)
  Module._free(nonceArrPtr)
  Module._free(outputArrPtr)

  if (resultCode !== 0) {
    throw Error('chacha20poly1305 encryption has failed!')
  }

  return Buffer.from(outputArr)
}

function chacha20poly1305Decrypt(input, key, nonce) {
  validateBuffer(input)
  validateBuffer(key, 32)
  validateBuffer(nonce, 12)

  // extract tag from input
  var tagLen = 16
  var tag = input.slice(input.length - tagLen, input.length)
  var input = input.slice(0, input.length - tagLen)

  var inputLen = input.length
  var inputArrPtr = Module._malloc(inputLen)
  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  var tagArrPtr = Module._malloc(tagLen)
  var tagArr = new Uint8Array(Module.HEAPU8.buffer, tagArrPtr, tagLen)

  var keyLen = key.length
  var keyArrPtr = Module._malloc(keyLen)
  var keyArr = new Uint8Array(Module.HEAPU8.buffer, keyArrPtr, keyLen)

  var nonceLen = nonce.length
  var nonceArrPtr = Module._malloc(nonceLen)
  var nonceArr = new Uint8Array(Module.HEAPU8.buffer, nonceArrPtr, nonceLen)

  var outputLen = inputLen
  var outputArrPtr = Module._malloc(outputLen)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)
  tagArr.set(tag)
  keyArr.set(key)
  nonceArr.set(nonce)

  var resultCode = Module._emscripten_chacha20poly1305_enc(keyArrPtr, nonceArrPtr, inputArrPtr, inputLen, outputArrPtr, tagArrPtr, tagLen, 0)

  Module._free(inputArrPtr)
  Module._free(keyArrPtr)
  Module._free(nonceArrPtr)
  Module._free(outputArrPtr)
  Module._free(tagArrPtr)

  if (resultCode !== 0) {
    throw Error('chacha20poly1305 decryption has failed!')
  }

  return Buffer.from(outputArr)
}

module.exports = {
  derivePublic,
  derivePrivate,
  sign,
  verify,
  sha3_256,
  chacha20poly1305Encrypt,
  chacha20poly1305Decrypt,
  blake2b,
  walletSecretFromMnemonic,
  cardanoMemoryCombine,
  base58,
  crc32,
  scrypt,
}
