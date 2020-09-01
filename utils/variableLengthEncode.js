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

module.exports = variableLengthEncode
