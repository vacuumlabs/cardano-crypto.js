const bip39 = require('bip39')

const {validateBuffer, validateDerivationIndex, validateDerivationScheme, validateMnemonic} = require("../utils/validation")
const crypto = require("./crypto-primitives")
const pbkdf2 = require('../utils/pbkdf2')
const Module = require('../lib.js')

async function mnemonicToRootKeypair(mnemonic, derivationScheme) {
  validateDerivationScheme(derivationScheme)

  if (derivationScheme === 1) {
    return mnemonicToRootKeypairV1(mnemonic)
  } else if (derivationScheme === 2) {
    return mnemonicToRootKeypairV2(mnemonic, '')
  } else {
    throw Error(`Derivation scheme ${derivationScheme} not implemented`)
  }
}

function mnemonicToRootKeypairV1(mnemonic) {
  const seed = mnemonicToSeedV1(mnemonic)
  return seedToKeypairV1(seed)
}

function mnemonicToSeedV1(mnemonic) {
  validateMnemonic(mnemonic)
  const entropy = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex')

  return cborEncodeBuffer(crypto.blake2b(cborEncodeBuffer(entropy), 32))
}

function seedToKeypairV1(seed) {
  let result
  for (let i = 1; result === undefined && i <= 1000; i++) {
    try {
      const digest = crypto.hmac_sha512(seed, [Buffer.from(`Root Seed Chain ${i}`, 'ascii')])
      const tempSeed = digest.slice(0, 32)
      const chainCode = digest.slice(32, 64)

      result = trySeedChainCodeToKeypairV1(tempSeed, chainCode)

    } catch (e) {
      if (e.name === 'InvalidKeypair') {
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

function trySeedChainCodeToKeypairV1(seed, chainCode) {
  validateBuffer(seed, 32)
  validateBuffer(chainCode, 32)

  const seedArrPtr = Module._malloc(32)
  const seedArr = new Uint8Array(Module.HEAPU8.buffer, seedArrPtr, 32)
  const chainCodeArrPtr = Module._malloc(32)
  const chainCodeArr = new Uint8Array(Module.HEAPU8.buffer, chainCodeArrPtr, 32)
  const keypairArrPtr = Module._malloc(128)
  const keypairArr = new Uint8Array(Module.HEAPU8.buffer, keypairArrPtr, 128)

  seedArr.set(seed)
  chainCodeArr.set(chainCode)

  const returnCode = Module._emscripten_wallet_secret_from_seed(seedArrPtr, chainCodeArrPtr, keypairArrPtr)

  Module._free(seedArrPtr)
  Module._free(chainCodeArrPtr)
  Module._free(keypairArrPtr)

  if (returnCode === 1) {
    const e = new Error('Invalid keypair')
    e.name = 'InvalidKeypair'

    throw e
  }

  return Buffer.from(keypairArr)
}

async function mnemonicToRootKeypairV2(mnemonic, password) {
  const seed = mnemonicToSeedV2(mnemonic)
  const rootSecret = await seedToKeypairV2(seed, password)

  return seedToKeypairV2(seed, password)
}

function mnemonicToSeedV2(mnemonic) {
  validateMnemonic(mnemonic)
  return Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex')
}

async function seedToKeypairV2(seed, password) {
  const xprv = await pbkdf2(password, seed, 4096, 96, 'sha512')

  xprv[0] &= 248
  xprv[31] &= 31
  xprv[31] |= 64

  const publicKey = toPublic(xprv.slice(0, 64))

  return Buffer.concat([xprv.slice(0, 64), publicKey, xprv.slice(64,)])
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

  return Buffer.from(publicKeyArr)
}

function derivePrivate(parentKey, index, derivationScheme) {
  validateBuffer(parentKey, 128)
  validateDerivationIndex(index)
  validateDerivationScheme(derivationScheme)

  const parentKeyArrPtr = Module._malloc(128)
  const parentKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentKeyArrPtr, 128)
  const childKeyArrPtr = Module._malloc(128)
  const childKeyArr = new Uint8Array(Module.HEAPU8.buffer, childKeyArrPtr, 128)

  parentKeyArr.set(parentKey)

  Module._emscripten_derive_private(parentKeyArrPtr, index, childKeyArrPtr, derivationScheme)
  Module._free(parentKeyArrPtr)
  Module._free(childKeyArrPtr)

  return Buffer.from(childKeyArr)
}

function derivePublic(parentExtPubKey, index, derivationScheme) {
  validateBuffer(parentExtPubKey, 64)
  validateDerivationIndex(index)
  validateDerivationScheme(derivationScheme)

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

  const resultCode = Module._emscripten_derive_public(parentPubKeyArrPtr, parentChainCodeArrPtr, index, childPubKeyArrPtr, childChainCodeArrPtr, derivationScheme)

  Module._free(parentPubKeyArrPtr)
  Module._free(parentChainCodeArrPtr)
  Module._free(parentPubKeyArrPtr)
  Module._free(parentChainCodeArrPtr)

  if (resultCode !== 0) {
    throw Error(`derivePublic has exited with code ${resultCode}`)
  }

  return Buffer.concat([Buffer.from(childPubKeyArr), Buffer.from(childChainCodeArr)])
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

module.exports = {
  mnemonicToRootKeypair,
  derivePublic,
  derivePrivate,
  toPublic,
  _mnemonicToSeedV1: mnemonicToSeedV1,
  _seedToKeypairV1: seedToKeypairV1,
  _seedToKeypairV2: seedToKeypairV2,
  _mnemonicToSeedV2: mnemonicToSeedV2,
}