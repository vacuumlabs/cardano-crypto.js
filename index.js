const {validateBuffer, validateDerivationIndex, validateDerivationScheme, validateMnemonic, validateArray, validateString, validatePaperWalletMnemonic} = require("./utils/validation")
const address = require("./address");
const crypto = require("./crypto-primitives")

const bech32 = require("bech32")
const bip39 = require('bip39')

const Module = require('./lib.js')
const base58 = require('./utils/base58')
const scrypt = require('./utils/scrypt-async')
const pbkdf2 = require('./utils/pbkdf2')

const HARDENED_THRESHOLD = 0x80000000

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

function sign(msg, keypair) {
  validateBuffer(msg)
  validateBuffer(keypair, 128)

  const msgLen = msg.length
  const msgArrPtr = Module._malloc(msgLen)
  const msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen)
  const keypairArrPtr = Module._malloc(128)
  const keypairArr = new Uint8Array(Module.HEAPU8.buffer, keypairArrPtr, 128)
  const sigPtr = Module._malloc(64)
  const sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64)

  msgArr.set(msg)
  keypairArr.set(keypair)

  Module._emscripten_sign(keypairArrPtr, msgArrPtr, msgLen, sigPtr)
  Module._free(msgArrPtr)
  Module._free(keypairArrPtr)
  Module._free(sigPtr)

  return Buffer.from(sigArr)
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

function cardanoMemoryCombine(input, password) {
  validateString(password)
  validateBuffer(input)

  if (password === '') {
    return input
  }

  const transformedPassword = crypto.blake2b(Buffer.from(password, 'utf-8'), 32)
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

async function decodePaperWalletMnemonic(paperWalletMnemonic) {
  validatePaperWalletMnemonic(paperWalletMnemonic)

  const paperWalletMnemonicAsList = paperWalletMnemonic.split(' ')

  const mnemonicScrambledPart = paperWalletMnemonicAsList.slice(0, 18).join(' ')
  const mnemonicPassphrasePart = paperWalletMnemonicAsList.slice(18, 27).join(' ')

  const passphrase = await mnemonicToPaperWalletPassphrase(mnemonicPassphrasePart)
  const unscrambledMnemonic = await paperWalletUnscrambleStrings(passphrase, mnemonicScrambledPart)

  return unscrambledMnemonic
}

async function mnemonicToPaperWalletPassphrase(mnemonic, password) {
  const mnemonicBuffer = Buffer.from(mnemonic, 'utf8')
  const salt = `mnemonic${password || ''}`
  const saltBuffer = Buffer.from(salt, 'utf8')
  return (await pbkdf2(mnemonicBuffer, saltBuffer, 2048, 32, 'sha512')).toString('hex')
}

/* taken from https://github.com/input-output-hk/rust-cardano/blob/08796d9f100f417ff30549b297bd20b249f87809/cardano/src/paperwallet.rs */
async function paperWalletUnscrambleStrings(passphrase, mnemonic) {
  const input = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex')
  const saltLength = 8

  if (saltLength >= input.length) {
    throw Error('unscrambleStrings: Input is too short')
  }

  const outputLength = input.length - saltLength

  const output = await pbkdf2(passphrase, input.slice(0, saltLength), 10000, outputLength, 'sha512')

  for (let i = 0; i < outputLength; i++) {
    output[i] = output[i] ^ input[saltLength + i]
  }

  return bip39.entropyToMnemonic(output)
}

async function xpubToHdPassphrase(xpub) {
  validateBuffer(xpub, 64)

  return pbkdf2(xpub, 'address-hashing', 500, 32, 'sha512')
}

function bech32Encode(prefix, data) {
  const words = bech32.toWords(data)
  // we need longer than default length for privkeys and 1000 should suffice
  return bech32.encode(prefix, words, 1000)
}

function bech32Decode(str){
  const tmp = bech32.decode(str, 1000)
  return {
    prefix: tmp.prefix,
    data: Buffer.from(bech32.fromWords(tmp.words)),
  }
}

module.exports = {
  derivePublic,
  derivePrivate,
  sign,
  verify,
  mnemonicToRootKeypair,
  decodePaperWalletMnemonic,
  xpubToHdPassphrase,
  packBootstrapAddress: address.packBootstrapAddress,
  packBaseAddress: address.packBaseAddress,
  packPointerAddress: address.packPointerAddress,
  packEnterpriseAddress: address.packEnterpriseAddress,
  packRewardsAccountAddress: address.packRewardsAccountAddress,
  getAddressInfo: address.getAddressInfo,
  AddressTypes: address.AddressTypes,
  unpackAddress: address.unpackAddress,
  isValidAddress: address.isValidAddress,
  cardanoMemoryCombine,
  blake2b: crypto.blake2b,
  base58,
  bech32_encode: bech32Encode,
  bech32_decode: bech32Decode,
  scrypt,
  toPublic,
  _mnemonicToSeedV1: mnemonicToSeedV1,
  _seedToKeypairV1: seedToKeypairV1,
  _mnemonicToSeedV2: mnemonicToSeedV2,
  _seedToKeypairV2: seedToKeypairV2,
  _sha3_256: crypto.sha3_256,
  _chacha20poly1305Decrypt: crypto.chacha20poly1305Decrypt,
  _chacha20poly1305Encrypt: crypto.chacha20poly1305Encrypt,
}
