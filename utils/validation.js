const bip39 = require('bip39')

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

function validateDerivationScheme(input) {
  if (input !== 1 && input !== 2) {
    throw new Error('invalid derivation scheme!')
  }
}

function validateMnemonic(input) {
  if (!bip39.validateMnemonic(input)) {
    const e = new Error('Invalid or unsupported mnemonic format:')
    e.name = 'InvalidArgumentException'
    throw e
  }
}

function validateMnemonicWords(input) {
  const wordlist = bip39.wordlists.EN
  const words = input.split(' ')

  const valid = words.reduce((result, word) => {
    return result && wordlist.indexOf(word) !== -1
  }, true)

  if (!valid) {
    throw new Error('Invalid mnemonic words')
  }
}

function validatePaperWalletMnemonic(input) {
  validateMnemonicWords(input)

  const mnemonicLength = input.split(' ').length

  if (mnemonicLength !== 27) {
    throw Error(
      `Paper Wallet Mnemonic must be 27 words, got ${mnemonicLength} instead`
    )
  }
}

function validateNetworkId(input) {
  if (!Number.isInteger(input) || input < 0 || input > 15) {
    throw Error(
      'Network id must be an integer between 0 and 15'
    )
  }
}

function validateUint32(input) {
  if (!Number.isInteger(input) || input < 0 || input >= Math.pow(2, 32)) {
    throw Error(
      'Value must be uint32'
    )
  }
}

module.exports = {
  validateBuffer,
  validateArray,
  validateString,
  validateDerivationIndex,
  validateDerivationScheme,
  validateMnemonic,
  validateMnemonicWords,
  validatePaperWalletMnemonic,
  validateNetworkId,
  validateUint32
}
