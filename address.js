const {validateBuffer, validateDerivationScheme, validateArray} = require("./utils/validation")
const {chacha20poly1305Encrypt, chacha20poly1305Decrypt, blake2b, sha3_256} = require("./crypto-primitives")

const cbor = require('borc')
const crc32 = require('./utils/crc32')
const base58 = require('./utils/base58')
const CborIndefiniteLengthArray = require('./utils/CborIndefiniteLengthArray')

const AddressTypes = {
  'BASE': 0b0000,
  'POINTER': 0b0100,
  'ENTERPRISE': 0b0110,
  'BOOTSTRAP': 0b1000,
  'REWARDS': 0b1110
}

function validateAddressType(input, addressTypeId) {
  if (!['BASE', 'POINTER', 'ENTERPRISE', 'BOOTSTRAP', 'REWARDS'].includes(addressTypeId)) {
    throw new Error("Invalid address type to validate!")
  }
  const addressType = {
    BASE: {
      BASE_ADDRESS_KEY_KEY: 0,
      BASE_ADDRESS_SCRIPT_KEY: 1,
      BASE_ADDRESS_KEY_SCRIPT: 2,
      BASE_ADDRESS_SCRIPT_SCRIPT: 3
    },
    POINTER: {
      POINTER_ADDRESS_KEY: 4,
      POINTER_ADDRESS_SCRIPT: 5
    },
    ENTERPRISE: {
      ENTERPRISE_ADDRESS_KEY: 6,
      ENTERPRISE_ADDRESS_SCRIPT: 7
    },
    BOOTSTRAP: {
      BOOTSTRAP_ADDRESS: 8
    },
    REWARDS: {
      REWARDS_ADDRESS: 14
    }
  }
  if (!Object.values(addressType[addressTypeId]).includes(input)) {
    throw new Error('Invalid address type for address: ' + input
      + ' Expected one of ' + addressType[addressTypeId])
  }
}

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

function packBootstrapAddress(derivationPath, xpub, hdPassphrase, derivationScheme) {
  validateBuffer(xpub, 64)
  validateDerivationScheme(derivationScheme)

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

  const addressRoot = getAddressHash([
    0,
    [0, xpub],
    addressPayload.length > 0 ? new Map([[1, cbor.encode(addressPayload)]]) : new Map(),
  ])
  const addressType = 0 // Public key address
  const addressData = [addressRoot, addressAttributes, addressType]
  const addressDataEncoded = cbor.encode(addressData)

  let enc = cbor.encode([new cbor.Tagged(24, addressDataEncoded), crc32(addressDataEncoded)])
  return enc
}

function getAddressHeader(addressType, networkId) {
  return Buffer.from([(addressType << 4) | networkId])
}

function getSpendingPart(pubKey) {
  return blake2b(pubKey, 28)
}

function packBaseAddress(pubKey, stakePubKey, addressType, networkId, isStakeHash = false) {
  validateBuffer(pubKey, 32)
  validateAddressType(addressType, "BASE")

  const header = getAddressHeader(addressType, networkId)
  const spending_part = getSpendingPart(pubKey)
  let staking_part
  if (isStakeHash) {
    staking_part = stakePubKey
  } else {
    staking_part = blake2b(stakePubKey, 28)
  }
  return Buffer.concat([header, spending_part, staking_part])
}

function variableLengthEncode(number) {
  if (number < 0) {
    throw new Error("Negative numbers not supported. Number supplied: " + number)
  }

  let encoded = []
  let bitLength = number.toString(2).length
  encoded.push(number & 127)

  while (bitLength > 7) {
    number >>= 7
    bitLength -= 7
    encoded.unshift((number & 127) + 128)
  }
  return Buffer.from(encoded)
}

function packPointerAddress(pubKey, pointer, addressType, networkId) {
  validateBuffer(pubKey, 32)
  validatePointer(pointer)
  validateAddressType(addressType, "POINTER")

  const header = getAddressHeader(addressType, networkId)
  const spending_part = getSpendingPart(pubKey)
  const encodedPointer = Buffer.concat([
    variableLengthEncode(pointer.blockIndex),
    variableLengthEncode(pointer.txIndex),
    variableLengthEncode(pointer.certificateIndex)
  ])
  return Buffer.concat([header, spending_part, encodedPointer])
}

function packEnterpriseAddress(pubKey, addressType, networkId) {
  validateBuffer(pubKey, 32)
  validateAddressType(addressType, "ENTERPRISE")

  const header = getAddressHeader(addressType, networkId)
  const spending_part = getSpendingPart(pubKey)
  return Buffer.concat([header, spending_part])
}

function packRewardsAccountAddress(stakePubkey, addressType, networkId, isStakeHash = false) {
  validateBuffer(stakePubkey, 32)
  validateAddressType(addressType, "REWARDS")
  let staking_part
  if (isStakeHash) {
    staking_part = stakePubKey
  } else {
    staking_part = blake2b(stakePubkey, 28)
  }
  const header = getAddressHeader(addressType, networkId)
  return Buffer.concat([header, staking_part])
}

function getAddressInfo(address) {
  if (!Buffer.isBuffer(address)) {
    throw new Error('Address not a buffer!')
  }

  return {
    addressType: address[0] >> 4,
    networkId: address[0] & 15
  }
}

function getAddressHash(input) {
  // eslint-disable-next-line camelcase
  const firstHash = sha3_256(cbor.encode(input))
  return blake2b(firstHash, 28)
}

function encryptDerivationPath(derivationPath, hdPassphrase) {
  const serializedDerivationPath = cbor.encode(new CborIndefiniteLengthArray(derivationPath))

  return chacha20poly1305Encrypt(
    serializedDerivationPath,
    hdPassphrase,
    Buffer.from('serokellfore')
  )
}

function unpackAddress(address, hdPassphrase) {
  // we decode the address from the base58 string
  // and then we strip the 24 CBOR data tags (the "[0].value" part)
  const addressAsBuffer = cbor.decode(base58.decode(address))[0].value
  const addressData = cbor.decode(addressAsBuffer)
  const attributes = addressData[1]
  const payload = cbor.decode(attributes.get(1))
  let derivationPath

  try {
    derivationPath = decryptDerivationPath(payload, hdPassphrase)
  } catch (e) {
    throw new Error('Unable to get derivation path from address')
  }

  if (derivationPath && derivationPath.length > 2) {
    throw Error('Invalid derivation path length, should be at most 2')
  }

  return {
    derivationPath,
  }
}

function isValidAddress(address) {
  try {
    // we decode the address from the base58 string
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

module.exports = {
  packBootstrapAddress,
  packBaseAddress,
  packPointerAddress,
  packEnterpriseAddress,
  packRewardsAccountAddress,
  unpackAddress,
  isValidAddress,
  getAddressInfo,
  AddressTypes,
}
