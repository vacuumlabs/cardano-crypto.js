var Module = require('./lib.js')
var bip39 = require('bip39')
var cbor = require('cbor')
var crypto = require('crypto')

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

function validateDerivationIndex(input) {
  if (!Number.isInteger(input)) {
    throw new Error('invalid derivation index!')
  }
}

exports.sign = function(msg, walletSecret){
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

  Module._sign(walletSecretArrPtr, msgArrPtr, msgLen, sigPtr)
  Module._free(msgArrPtr)
  Module._free(walletSecretArrPtr)
  Module._free(sigPtr)

  return new Buffer(sigArr)
}

exports.verify = function(msg, publicKey, sig){
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

  var result = Module._verify(msgArrPtr, msgLen, publicKeyArrPtr, sigPtr) === 0

  Module._free(msgArrPtr)
  Module._free(publicKeyArrPtr)
  Module._free(sigPtr)

  return result
}

function walletSecretFromSeed(seed, chainCode){
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

  const returnCode = Module._wallet_secret_from_seed(seedArrPtr, chainCodeArrPtr, walletSecretArrPtr)

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

  return cbor.encode(exports.blake2b256(cbor.encode(ent)))
}

exports.walletSecretFromMnemonic = function(mnemonic) {
  var hashSeed = mnemonicToHashSeed(mnemonic)
  var result

  for (var i = 1; result === undefined && i <= 1000; i++) {
    try {
      var hmac = crypto.createHmac('sha512', hashSeed)
      hmac.update(`Root Seed Chain ${i}`)

      var digest = hmac.digest('hex')
      var seed = Buffer.from(digest.substr(0, 64), 'hex')
      var chainCode = Buffer.from(digest.substr(64, 64), 'hex')

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

exports.derivePrivate = function(parentKey, index, derivationMode){
  validateBuffer(parentKey, 128)
  validateDerivationIndex(index)
  validateDerivationMode(derivationMode)

  var parentKeyArrPtr = Module._malloc(128)
  var parentKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentKeyArrPtr, 128)
  var childKeyArrPtr = Module._malloc(128)
  var childKeyArr = new Uint8Array(Module.HEAPU8.buffer, childKeyArrPtr, 128)
  parentKeyArr.set(parentKey)
  Module._derive_private(parentKeyArrPtr, index, childKeyArrPtr, derivationMode)
  Module._free(parentKeyArrPtr)
  Module._free(childKeyArrPtr)
  return new Buffer(childKeyArr)
}

exports.derivePublic = function(parentExtPubKey, index, derivationMode){
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
  
  Module._derive_public(parentPubKeyArrPtr, parentChainCodeArrPtr, index, childPubKeyArrPtr, childChainCodeArrPtr, derivationMode)
  
  Module._free(parentPubKeyArrPtr)
  Module._free(parentChainCodeArrPtr)
  Module._free(parentPubKeyArrPtr)
  Module._free(parentChainCodeArrPtr)

  return Buffer.concat([new Buffer(childPubKeyArr), new Buffer(childChainCodeArr)])
}

exports.blake2b256 = function(input){
  validateBuffer(input)

  var inputLen = input.length
  var inputArrPtr = Module._malloc(inputLen)
  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen)
  var outputArrPtr = Module._malloc(32)
  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, 32)

  inputArr.set(input)
  
  Module._blake2b256(inputArrPtr, inputLen, outputArrPtr)
  
  Module._free(inputArrPtr)
  Module._free(outputArrPtr)

  return Buffer.from(outputArr)
}
