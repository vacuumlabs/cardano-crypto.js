const bip39 = require('bip39-light')

const Module = require('./lib.js')
const crc32 = require('./utils/crc32')
const base58 = require('./utils/base58')
const scrypt = require('./utils/scrypt-async')
const pbkdf2Sync = require('pbkdf2').pbkdf2Sync


function validateDerivationMode(input) {
  if (input !== 1 && input !== 2) {
    throw new Error('invalid derivation mode!')
  }
}

function validateBuffer(input, expectedLength) {
  if (!Buffer.isBuffer(input)) {
    throw new Error('not buffer!')
  }

  if (expectedLength && input.length !== expectedLength) {
    throw new Error('Invalid buffer length')
  }
}

function validateArray(input) {
  if (typeof input !== typeof []) {
    throw new Error('not an array!')
  }
}

function validateDerivationIndex(input) {
  if (!Number.isInteger(input)) {
    throw new Error('invalid derivation index!')
  }
}

function validateString(input) {
  if (typeof input !== typeof 'aa') {
    throw new Error('not a string!')
  }
}

function validateMnemonic(input) {
  if (!bip39.validateMnemonic(input)) {
    const e = new Error('Invalid or unsupported mnemonic format')
    e.name = 'InvalidArgumentException'
    throw e
  }
}

function cborEncodeBuffer(input) {
  validateBuffer(input)

  const len = input.length
  let cborPrefix = []

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

  const msgLen = msg.length
  const msgArrPtr = Module._malloc(msgLen)
  const msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen)
  const walletSecretArrPtr = Module._malloc(128)
  const walletSecretArr = new Uint8Array(Module.HEAPU8.buffer, walletSecretArrPtr, 128)
  const sigPtr = Module._malloc(64)
  const sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64)

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

  const msgLen = msg.length
  const msgArrPtr = Module._malloc(msgLen)
  const msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen)
  const publicKeyArrPtr = Module._malloc(32)
  const publicKeyArr = new Uint8Array(Module.HEAPU8.buffer, publicKeyArrPtr, 32)
  const sigPtr = Module._malloc(64)
  const sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64)

  msgArr.set(msg)
  publicKeyArr.set(publicKey)
  sigArr.set(sig)

  const result = Module._emscripten_verify(msgArrPtr, msgLen, publicKeyArrPtr, sigPtr) === 0

  Module._free(msgArrPtr)
  Module._free(publicKeyArrPtr)
  Module._free(sigPtr)

  return result
}

function walletSecretFromSeed(seed, chainCode) {
  validateBuffer(seed, 32)
  validateBuffer(chainCode, 32)

  const seedArrPtr = Module._malloc(32)
  const seedArr = new Uint8Array(Module.HEAPU8.buffer, seedArrPtr, 32)
  const chainCodeArrPtr = Module._malloc(32)
  const chainCodeArr = new Uint8Array(Module.HEAPU8.buffer, chainCodeArrPtr, 32)
  const walletSecretArrPtr = Module._malloc(128)
  const walletSecretArr = new Uint8Array(Module.HEAPU8.buffer, walletSecretArrPtr, 128)

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

function walletSecretFromMnemonic(mnemonic, derivationMode) {
  validateDerivationMode(derivationMode)

  if (derivationMode === 1) {
    return walletSecretFromMnemonicV1(mnemonic)
  } else if (derivationMode === 2) {
    return walletSecretFromMnemonicV2(mnemonic, '')
  } else {
    throw Error(`Derivation mode ${derivationMode} not implemented`)
  }
}

function walletSecretFromMnemonicV1(mnemonic) {
  validateMnemonic(mnemonic)

  const entropy = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex')
  const hashSeed = cborEncodeBuffer(blake2b(cborEncodeBuffer(entropy), 32))

  let result
  for (let i = 1; result === undefined && i <= 1000; i++) {
    try {
      const digest = hmac_sha512(hashSeed, [Buffer.from(`Root Seed Chain ${i}`, 'ascii')])
      const seed = digest.slice(0, 32)
      const chainCode = digest.slice(32, 64)

      result = walletSecretFromSeed(seed, chainCode)

    } catch (e) {
      if (e.name === 'InvalidSecret') {
        continue
      }

      throw e
    }
  }

  if (result === undefined) {
    const e = new Error('Secret key generation from mnemonic is looping forever')
    e.name = 'RuntimeException'
    throw e
  }

  return result
}

function walletSecretFromMnemonicV2(mnemonic, password) {
  validateMnemonic(mnemonic)
  const entropy = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex')
  const xprv = pbkdf2Sync(password, entropy, 4096, 96, 'sha512')

  xprv[0] &= 248
  xprv[31] &= 31
  xprv[31] |= 64

  const publicKey = toPublic(xprv.slice(0, 64))

  return Buffer.concat([xprv.slice(0, 64), publicKey, xprv.slice(64, 96)])
}

function toPublic(privateKey) {
  validateBuffer(privateKey, 64)

  const privateKeyArrPtr = Module._malloc(64)
  const privateKeyArr = new Uint8Array(Module.HEAPU8.buffer, privateKeyArrPtr, 64)
  const publicKeyArrPtr = Module._malloc(32)
  const publicKeyArr = new Uint8Array(Module.HEAPU8.buffer, publicKeyArrPtr, 32)

  privateKeyArr.set(privateKey)

  Module._emscripten_to_public(privateKeyArrPtr, publicKeyArrPtr)

  Module._free(privateKeyArrPtr)
  Module._free(publicKeyArrPtr)

  return new Buffer(publicKeyArr)
}

function derivePrivate(parentKey, index, derivationMode) {
  validateBuffer(parentKey, 128)
  validateDerivationIndex(index)
  validateDerivationMode(derivationMode)

  const parentKeyArrPtr = Module._malloc(128)
  const parentKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentKeyArrPtr, 128)
  const childKeyArrPtr = Module._malloc(128)
  const childKeyArr = new Uint8Array(Module.HEAPU8.buffer, childKeyArrPtr, 128)

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

  const parentPubKey = parentExtPubKey.slice(0, 32)
  const parentChainCode = parentExtPubKey.slice(32, 64)

  const parentPubKeyArrPtr = Module._malloc(32)
  const parentPubKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentPubKeyArrPtr, 32)
  const parentChainCodeArrPtr = Module._malloc(32)
  const parentChainCodeArr = new Uint8Array(Module.HEAPU8.buffer, parentChainCodeArrPtr, 32)

  const childPubKeyArrPtr = Module._malloc(32)
  const childPubKeyArr = new Uint8Array(Module.HEAPU8.buffer, childPubKeyArrPtr, 32)
  const childChainCodeArrPtr = Module._malloc(32)
  const childChainCodeArr = new Uint8Array(Module.HEAPU8.buffer, childChainCodeArrPtr, 32)

  parentPubKeyArr.set(parentPubKey)
  parentChainCodeArr.set(parentChainCode)

  const resultCode = Module._emscripten_derive_public(parentPubKeyArrPtr, parentChainCodeArrPtr, index, childPubKeyArrPtr, childChainCodeArrPtr, derivationMode)

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

  const inputLen = input.length
  const inputArrPtr = Module._malloc(inputLen)
  const inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)
  const outputArrPtr = Module._malloc(outputLen)
  const outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)

  Module._emscripten_blake2b(inputArrPtr, inputLen, outputArrPtr, outputLen)

  Module._free(inputArrPtr)
  Module._free(outputArrPtr)

  return Buffer.from(outputArr)
}

function sha3_256(input) {
  validateBuffer(input)
  const inputLen = input.length
  const inputArrPtr = Module._malloc(inputLen)
  const inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  const outputLen = 32
  const outputArrPtr = Module._malloc(outputLen)
  const outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

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

  const ctxLen = Module._emscripten_size_of_hmac_sha512_ctx()
  const ctxArrPtr = Module._malloc(ctxLen)
  const ctxArr = new Uint8Array(Module.HEAPU8.buffer, ctxArrPtr, ctxLen)

  const initKeyLen = initKey.length
  const initKeyArrPtr = Module._malloc(initKeyLen)
  const initKeyArr = new Uint8Array(Module.HEAPU8.buffer, initKeyArrPtr, initKeyLen)

  const outputLen = 64
  const outputArrPtr = Module._malloc(outputLen)
  const outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  initKeyArr.set(initKey)

  Module._emscripten_hmac_sha512_init(ctxArrPtr, initKeyArrPtr, initKeyLen)

  for (let i = 0; i < inputs.length; i++) {
    const inputLen = inputs[i].length
    const inputArrPtr = Module._malloc(inputLen)
    const inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

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

  const transformedPassword = blake2b(Buffer.from(password, 'utf-8'), 32)
  const transformedPasswordLen = transformedPassword.length
  const transformedPasswordArrPtr = Module._malloc(transformedPasswordLen)
  const transformedPasswordArr = new Uint8Array(Module.HEAPU8.buffer, transformedPasswordArrPtr, transformedPasswordLen)

  const inputLen = input.length
  const inputArrPtr = Module._malloc(inputLen)
  const inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  const outputArrPtr = Module._malloc(inputLen)
  const outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, inputLen)

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

  const inputLen = input.length
  const inputArrPtr = Module._malloc(inputLen)
  const inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  const keyLen = key.length
  const keyArrPtr = Module._malloc(keyLen)
  const keyArr = new Uint8Array(Module.HEAPU8.buffer, keyArrPtr, keyLen)

  const nonceLen = nonce.length
  const nonceArrPtr = Module._malloc(nonceLen)
  const nonceArr = new Uint8Array(Module.HEAPU8.buffer, nonceArrPtr, nonceLen)

  const tagLen = 16
  const outputLen = inputLen + tagLen
  const outputArrPtr = Module._malloc(outputLen)
  const outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)
  keyArr.set(key)
  nonceArr.set(nonce)

  const resultCode = Module._emscripten_chacha20poly1305_enc(keyArrPtr, nonceArrPtr, inputArrPtr, inputLen, outputArrPtr, outputArrPtr + inputLen, tagLen, 1)

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
  const tagLen = 16
  const tag = input.slice(input.length - tagLen, input.length)
  input = input.slice(0, input.length - tagLen)

  const inputLen = input.length
  const inputArrPtr = Module._malloc(inputLen)
  const inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)

  const tagArrPtr = Module._malloc(tagLen)
  const tagArr = new Uint8Array(Module.HEAPU8.buffer, tagArrPtr, tagLen)

  const keyLen = key.length
  const keyArrPtr = Module._malloc(keyLen)
  const keyArr = new Uint8Array(Module.HEAPU8.buffer, keyArrPtr, keyLen)

  const nonceLen = nonce.length
  const nonceArrPtr = Module._malloc(nonceLen)
  const nonceArr = new Uint8Array(Module.HEAPU8.buffer, nonceArrPtr, nonceLen)

  const outputLen = inputLen
  const outputArrPtr = Module._malloc(outputLen)
  const outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen)

  inputArr.set(input)
  tagArr.set(tag)
  keyArr.set(key)
  nonceArr.set(nonce)

  const resultCode = Module._emscripten_chacha20poly1305_enc(keyArrPtr, nonceArrPtr, inputArrPtr, inputLen, outputArrPtr, tagArrPtr, tagLen, 0)

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
