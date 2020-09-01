const bech32 = require('bech32')
const {validateString, validateBuffer} = require('./validation')

function encode(prefix, data) {
  validateString(prefix)
  validateBuffer(data)

  const words = bech32.toWords(data)
  // we need longer than default length for privkeys and 1000 should suffice
  return bech32.encode(prefix, words, 1000)
}

function decode(str) {
  validateString(str)

  const tmp = bech32.decode(str, 1000)
  return {
    prefix: tmp.prefix,
    data: Buffer.from(bech32.fromWords(tmp.words)),
  }
}

module.exports = {
  encode,
  decode
}
