const {chacha20poly1305Encrypt, chacha20poly1305Decrypt, blake2b, sha3_256} = require("./crypto-primitives")

const cbor = require('borc')
const crc32 = require('../utils/crc32')
const base58 = require('../utils/base58')
const bech32 = require('../utils/bech32')
const pbkdf2 = require('../utils/pbkdf2')
const variableLengthEncode = require('../utils/variableLengthEncode')
const CborIndefiniteLengthArray = require('../utils/CborIndefiniteLengthArray')
const {validateBuffer, validateDerivationScheme, validateArray, validateString, validateNetworkId, validateUint32} = require("../utils/validation")

const AddressTypes = {
  'BASE': 0b0000,
  'POINTER': 0b0100,
  'ENTERPRISE': 0b0110,
  'BOOTSTRAP': 0b1000,
  'REWARD': 0b1110
}

const shelleyAddressTypes = [AddressTypes.BASE, AddressTypes.POINTER, AddressTypes.ENTERPRISE, AddressTypes.REWARD]

const PUB_KEY_LEN = 32
const KEY_HASH_LEN = 28
const MAINNET_PROTOCOL_MAGIC = 764824073

function validatePointer(input) {
  if (!input.hasOwnProperty('blockIndex')
    || !input.hasOwnProperty('txIndex')
    || !input.hasOwnProperty('certificateIndex')) {
    throw new Error('Invalid pointer! Missing one of blockIndex, txIndex, certificateIndex')
  }
  if (!Number.isInteger(input.blockIndex)
    || !Number.isInteger(input.txIndex)
    || !Number.isInteger(input.certificateIndex)) {
    throw new Error('Invalid pointer! values must be integer')
  }
}

function packBootstrapAddress(derivationPath, xpub, hdPassphrase, derivationScheme, protocolMagic) {
  validateBuffer(xpub, 64)
  validateDerivationScheme(derivationScheme)
  validateUint32(protocolMagic)

  if (derivationScheme === 1) {
    validateArray(derivationPath)
    validateBuffer(hdPassphrase, 32)
  }

  let addressPayload, addressAttributes
  if (derivationScheme === 1 && derivationPath.length > 0) {
    addressPayload = encryptDerivationPath(derivationPath, hdPassphrase)
    addressAttributes = new Map([[1, cbor.encode(addressPayload)]])
  } else {
    addressPayload = Buffer.from([])
    addressAttributes = new Map()
  }

  if (protocolMagic !== MAINNET_PROTOCOL_MAGIC) {
    addressAttributes.set(2, cbor.encode(protocolMagic))
  }

  const getAddressRootHash = (input) => blake2b(sha3_256(cbor.encode(input)), 28)

  const addressRoot = getAddressRootHash([
    0,
    [0, xpub],
    addressPayload.length > 0 ? new Map([[1, cbor.encode(addressPayload)]]) : new Map(),
  ])
  const addressType = 0 // Public key address
  const addressData = [addressRoot, addressAttributes, addressType]
  const addressDataEncoded = cbor.encode(addressData)

  return cbor.encode([new cbor.Tagged(24, addressDataEncoded), crc32(addressDataEncoded)])
}

function getAddressHeader(addressType, networkId) {
  return Buffer.from([(addressType << 4) | networkId])
}

function getPubKeyBlake2b224Hash(pubKey) {
  validateBuffer(pubKey, PUB_KEY_LEN)

  return blake2b(pubKey, KEY_HASH_LEN)
}

function packBaseAddress(spendingKeyHash, stakingKeyHash, networkId) {
  validateBuffer(spendingKeyHash, KEY_HASH_LEN)
  validateBuffer(stakingKeyHash, KEY_HASH_LEN)
  validateNetworkId(networkId)

  return Buffer.concat([
    getAddressHeader(AddressTypes.BASE, networkId),
    spendingKeyHash,
    stakingKeyHash,
  ])
}

function packPointerAddress(pubKeyHash, pointer, networkId) {
  validateBuffer(pubKeyHash, KEY_HASH_LEN)
  validatePointer(pointer)
  validateNetworkId(networkId)

  const {blockIndex, txIndex, certificateIndex} = pointer

  return Buffer.concat([
    getAddressHeader(AddressTypes.POINTER, networkId),
    pubKeyHash,
    Buffer.concat([
      variableLengthEncode(blockIndex),
      variableLengthEncode(txIndex),
      variableLengthEncode(certificateIndex)
    ])
  ])
}

function packEnterpriseAddress(spendingKeyHash, networkId) {
  validateBuffer(spendingKeyHash, KEY_HASH_LEN)
  validateNetworkId(networkId)

  return Buffer.concat([
    getAddressHeader(AddressTypes.ENTERPRISE, networkId),
    spendingKeyHash
  ])
}

function packRewardAddress(stakingKeyHash, networkId) {
  validateBuffer(stakingKeyHash, KEY_HASH_LEN)
  validateNetworkId(networkId)

  return Buffer.concat([
    getAddressHeader(AddressTypes.REWARD, networkId),
    stakingKeyHash
  ])
}

function unpackBootstrapAddress(address, hdPassphrase) {
  // we decode the address from the base58 string
  // and then we strip the 24 CBOR data tags (the "[0].value" part)
  const addressAsBuffer = cbor.decode(base58.decode(address))[0].value
  const addressData = cbor.decode(addressAsBuffer)
  const addressAttributes = addressData[1]
  const addressPayload = cbor.decode(addressAttributes.get(1))
  let derivationPath

  try {
    derivationPath = decryptDerivationPath(addressPayload, hdPassphrase)
  } catch (e) {
    throw new Error('Unable to get derivation path from address')
  }

  if (derivationPath && derivationPath.length > 2) {
    throw Error('Invalid derivation path length, should be at most 2')
  }

  return {
    addressAttributes,
    derivationPath,
  }
}

function isValidBootstrapAddress(address) {
  validateString(address)

  try {
    const addressAsArray = cbor.decode(base58.decode(address))
    // we strip the 24 CBOR data taga by taking the "value" attribute from the "Tagged" object
    const addressDataEncoded = addressAsArray[0].value
    const crc32Checksum = addressAsArray[1]

    if (crc32Checksum !== crc32(addressDataEncoded)) {
      return false
    }

  } catch (e) {
    return false
  }
  return true
}

function isValidShelleyAddress(address) {
  validateString(address)

  try {
    const {data: addressBuffer} = bech32.decode(address)
    
    if (!shelleyAddressTypes.includes(getAddressType(addressBuffer))) {
      return false
    }
  } catch (e) {
    return false
  }
  return true
}


function getAddressType(addressBuffer) {
  validateBuffer(addressBuffer)

  return addressBuffer[0] >> 4
}

function getShelleyAddressNetworkId(addressBuffer) {
  validateBuffer(addressBuffer)

  return addressBuffer[0] & 15
}

function encryptDerivationPath(derivationPath, hdPassphrase) {
  const serializedDerivationPath = cbor.encode(new CborIndefiniteLengthArray(derivationPath))

  return chacha20poly1305Encrypt(
    serializedDerivationPath,
    hdPassphrase,
    Buffer.from('serokellfore')
  )
}

function decryptDerivationPath(addressPayload, hdPassphrase) {
  const decipheredDerivationPath = chacha20poly1305Decrypt(
    addressPayload,
    hdPassphrase,
    Buffer.from('serokellfore')
  )

  try {
    return cbor.decode(Buffer.from(decipheredDerivationPath))
  } catch (err) {
    throw new Error('incorrect address or passphrase')
  }
}

async function xpubToHdPassphrase(xpub) {
  validateBuffer(xpub, 64)

  return pbkdf2(xpub, 'address-hashing', 500, 32, 'sha512')
}

module.exports = {
  packBootstrapAddress,
  packBaseAddress,
  packPointerAddress,
  packEnterpriseAddress,
  packRewardAddress,
  unpackBootstrapAddress,
  getAddressType,
  getShelleyAddressNetworkId,
  isValidBootstrapAddress,
  isValidShelleyAddress,
  xpubToHdPassphrase,
  getPubKeyBlake2b224Hash,
  AddressTypes,
}
