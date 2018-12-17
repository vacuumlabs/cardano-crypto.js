const test = require('tape')
const lib = require('..')

const sampleWalletMnemonicV1 = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
const sampleWalletMnemonicV2 = 'cost dash dress stove morning robust group affair stomach vacant route volume yellow salute laugh'
const sampleWalletSecretV1 = Buffer.from('d809b1b4b4c74734037f76aace501730a3fe2fca30b5102df99ad3f7c0103e48d54cde47e9041b31f3e6873d700d83f7a937bea746dadfa2c5b0a6a92502356ce6f04522f875c1563682ca876ddb04c2e2e3ae718e3ff9f11c03dd9f9dccf69869272d81c376382b8a87c21370a7ae9618df8da708d1a9490939ec54ebe43000', 'hex')
const sampleWalletSecretV2 = Buffer.from('70b441728448ebbafe087474d2ddc59be673700c70c3843660f681c34a0b57442a982a7c6edb0024d5b7a520d3369c236f6e0e649b78aebbe40a7b16618b9b2b783f05bc024661edbd9aa29651ea19d48ca974e70704f3d44ff7f48c37c5aa65f25b034e06cacc37ce661cdc718a4a35a221649d55d5e5691c16f6bec6ee7b85', 'hex')
const samplePublicKey = sampleWalletSecretV1.slice(64, 96)
const sampleExtendedPublicKey = sampleWalletSecretV1.slice(64, 128)
const sampleHdPassphrase = Buffer.from('c582f8e7cf7aeb6e5f3e96e939a92ae1642360a51d45150f34e70132a152203f', 'hex')
const sampleMessage = Buffer.from('Hello world', 'utf-8')
const sampleRightSignature = Buffer.from('1096ddcfb2ad21a4c0d861ef3fabe18841e8de88105b0d8e36430d7992c588634ead4100c32b2800b31b65e014d54a8238bdda63118d829bf0bcf1b631e86f0e', 'hex')
const sampleWrongSignature = Buffer.from('2096ddcfb2ad21a4c0d861ef3fabe18841e8de88105b0d8e36430d7992c588634ead4100c33b2800b31b65e014d54a8238bdda63118d829bf0bcf1b631e86f0e', 'hex')
const sampleHardenedIndex = 0x80000001
const sampleHardenedChildKeyMode1 = Buffer.from('691741c612363ef4a53a3bfa752c038b7a5f9842791db99d9993b480b11196004bbc1614c6ca0d907e33271d14403332089b23c3679dab1fd770f48b83b6f8bf900b5f6a9976064b818f1c45a82c66755c5ae28925b44b7026b8aebebb379413b097e30d8bf55e025a87090016c4f1a47e31013ee30fb1e1c4a1a2a1c502e0b8', 'hex')
const sampleHardenedChildKeyMode2 = Buffer.from('9049fc9cd910252e75dbcac63289db674cc0ab35030bfe9ab2c343d2c3103e48ed8a975dac7e6acba9cfa755049691888f525cb05819e33d5f7ad6ec6636d06b9fa98ca6ded6d6868b7b56f9c08ed66cf8d7585436f63c6ea39ecba996a7051001a5f87bc963cb974998c33b00b4b16343cd3672ffe2664c716651219c18f11f', 'hex')
const sampleNonhardenedIndex = 1
const sampleNonHardenedChildKeyMode1 = Buffer.from('30c87a45fe4a8f143478db0d8db6cf963bdfb559f2a050fceae40bc7e97333f832635e6d3dd3409b00373d4f9b49eb8e9444a4ea8e380397e9711a95b940ecd7', 'hex')
const sampleNonHardenedChildKeyMode2 = Buffer.from('19ad2602cee521db72c4ad41c2daf36ca46cf8e80733822fa0f79c8013de8e6fed4f3181d9f544612c5f15e01db0745111b8ee7fc87b784ee083ad314e094662', 'hex')
const sampleScryptDerivedKey = '5012b74fca8ec8a4a0a62ffdeeee959d'
const samplePaperWalletMnemonic =
  'force usage medal chapter start myself odor ripple concert aspect wink melt afford lounge smart bulk way hazard burden type broken defense city announce reward same tumble'
const sampleDecodedPaperWalletMnemonic = 'swim average antenna there trap nice good stereo lion safe next brief'
const sampleV1Address = 'DdzFFzCqrhssmYoG5Eca1bKZFdGS8d6iag1mU4wbLeYcSPVvBNF2wRG8yhjzQqErbg63N6KJA4DHqha113tjKDpGEwS5x1dT2KfLSbSJ'
const sampleV2Address = 'Ae2tdPwUPEZ18ZjTLnLVr9CEvUEUX4eW1LBHbxxxJgxdAYHrDeSCSbCxrvx'
const sampleAddressInvalidChecksum = 'Ae2tdPwUPEZ18ZjTLnLVr9CEvUEUX4eW1LBHbxxxJgxdAYHrDeSCSbCxrvm'
const sampleRandomString = 'hasoiusaodiuhsaijnnsajnsaiussai'


test('wallet secret from mnemonic V1', async (t) => {
  t.plan(1)

  const walletSecret = await lib.walletSecretFromMnemonic(sampleWalletMnemonicV1, 1)
  t.equals(
    walletSecret.toString('hex'),
    sampleWalletSecretV1.toString('hex'),
    'wallet secret derivates from mnemonic properly'
  )
})

test('wallet secret from mnemonic V2', async (t) => {
  t.plan(1)

  const walletSecret = await lib.walletSecretFromMnemonic(sampleWalletMnemonicV2, 2)
  t.equals(
    walletSecret.toString('hex'),
    sampleWalletSecretV2.toString('hex'),
    'wallet secret derivates from mnemonic properly'
  )
})

test('signing', (t) => {
  t.plan(1)

  const signature = lib.sign(sampleMessage, sampleWalletSecretV1)

  t.equals(
    signature.toString('hex'),
    sampleRightSignature.toString('hex'),
    'signing works properly'
  )
})

test('verifying', (t) => {
  t.plan(2)

  t.equals(
    lib.verify(sampleMessage, samplePublicKey, sampleRightSignature),
    true,
    'should accept right signature'
  )

  t.equals(
    lib.verify(sampleMessage, samplePublicKey, sampleWrongSignature),
    false,
    'should reject wrong signature'
  )
})

test('key hardened derivation', (t) => {
  t.plan(2)

  t.equals(
    lib.derivePrivate(sampleWalletSecretV1, sampleHardenedIndex, 1).toString('hex'),
    sampleHardenedChildKeyMode1.toString('hex'),
    'should properly derive hardened child key in derivation mode 1'
  )

  t.equals(
    lib.derivePrivate(sampleWalletSecretV1, sampleHardenedIndex, 2).toString('hex'),
    sampleHardenedChildKeyMode2.toString('hex'),
    'should properly derive hardened child key in derivation mode 2'
  )
})

test('key nonhardened derivation', (t) => {
  t.plan(2)

  t.equals(
    lib.derivePublic(sampleExtendedPublicKey, sampleNonhardenedIndex, 1).toString('hex'),
    sampleNonHardenedChildKeyMode1.toString('hex'),
    'should properly derive nonhardened child key in derivation mode 1'
  )

  t.equals(
    lib.derivePublic(sampleExtendedPublicKey, sampleNonhardenedIndex, 2).toString('hex'),
    sampleNonHardenedChildKeyMode2.toString('hex'),
    'should properly derive nonhardened child key in derivation mode 2'
  )
})

test('key nonhardened derivation', (t) => {
  t.plan(2)

  t.equals(
    lib.derivePublic(sampleExtendedPublicKey, sampleNonhardenedIndex, 1).toString('hex'),
    sampleNonHardenedChildKeyMode1.toString('hex'),
    'should properly derive nonhardened child key in derivation mode 1'
  )

  t.equals(
    lib.derivePublic(sampleExtendedPublicKey, sampleNonhardenedIndex, 2).toString('hex'),
    sampleNonHardenedChildKeyMode2.toString('hex'),
    'should properly derive nonhardened child key in derivation mode 2'
  )
})

test('blake2b', (t) => {
  t.plan(1)

  t.equals(
    lib.blake2b(sampleMessage, 32).toString('hex'),
    'a21cf4b3604cf4b2bc53e6f88f6a4d75ef5ff4ab415f3e99aea6b61c8249c4d0',
    'should properly compute blake2b hash'
  )
})

test('sha3_256', (t) => {
  t.plan(1)
  const message = Buffer.from('83008200584078732eb9d33e03b3daab4a4613bc19b8820ef5911caf43785780ec6493653bf67115f7f2c460be13dcc09f06f3d63fffe05a3d12996e5224e189a41ee2ef5c95a101581e581c140539c64edded60a7f2d869373e87e744591935bfcdadaa8517974c', 'hex')

  t.equals(
    lib._sha3_256(message).toString('hex'),
    '98b05e27eab982f4d108694a5ab636d68cc898e4af98980516fe2560b13e53a9',
    'should properly compute sha3_256 hash'
  )
})

test('chacha20poly1305', (t) => {
  t.plan(2)
  const key = Buffer.from('c582f8e7cf7aeb6e5f3e96e939a92ae1642360a51d45150f34e70132a152203f', 'hex')
  const nonce = Buffer.from('serokellfore')
  const message = Buffer.from('9f1a800000001a8000000dff', 'hex')
  const expectedEncryptionResult = Buffer.from('140539c64edded60a7f2d9696b17a78b4494b6bf0eef0cc28cad3c2b', 'hex')

  t.equals(
    lib._chacha20poly1305Encrypt(message, key, nonce, true).toString('hex'),
    expectedEncryptionResult.toString('hex'),
    'should properly encrypt with chacha20poly1305'
  )

  t.equals(
    lib._chacha20poly1305Decrypt(expectedEncryptionResult, key, nonce, false).toString('hex'),
    message.toString('hex'),
    'should properly decrypt with chacha20poly1305'
  )
})

test('cardanoMemoryCombine', (t) => {
  t.plan(2)
  const input = Buffer.from('41227237bcfda3c7b921225e5d883eb7fdbd14935ebe897f5951769a0bc735bdfa3b548357e19f27d59053bfa22f415f8f5d55bfe031bfe2946a4725f3cdfa3c', 'hex')
  const password = 'WalletS3cret'
  const expectedOutput = Buffer.from('80a93f1b0c558631f9473c0169dda414535caefa1a9b4a7a29b41f0d96b4aa4359eafca30ae2726745155a8034c671786984d65b9ac11f850447e3884267801c', 'hex')

  t.equals(
    lib.cardanoMemoryCombine(input, password).toString('hex'),
    expectedOutput.toString('hex'),
    'should properly combine memory with nonempty passphrase'
  )

  t.equals(
    lib.cardanoMemoryCombine(input, '').toString('hex'),
    input.toString('hex'),
    'should properly combine memory with empty passphrase'
  )
})

test('scrypt', (t) => {
  t.plan(1)

  let key
  lib.scrypt('mypassword', 'saltysalt', {
    N: 16384,
    r: 8,
    p: 1,
    dkLen: 16,
    encoding: 'hex'
  }, (derivedKey) => {
    key = derivedKey
  })

  t.equals(
    key,
    sampleScryptDerivedKey,
    'should properly derive key by scrypt'
  )
})

test('paper wallet mnemonic decoding', async (t) => {
  t.plan(1)
  t.equals(
    await lib.decodePaperWalletMnemonic(samplePaperWalletMnemonic),
    sampleDecodedPaperWalletMnemonic,
    'should properly decode paper wallet mnemonic'
  )
})

test('address validation', async (t) => {
  t.plan(4)
  t.equals(
    lib.isValidAddress(sampleV1Address),
    true,
    'should accept V1 address'
  )
  t.equals(
    lib.isValidAddress(sampleV2Address),
    true,
    'should accept V2 address'
  )
  t.equals(
    lib.isValidAddress(sampleAddressInvalidChecksum),
    false,
    'should reject address with invalid checksum'
  )

  t.equals(
    lib.isValidAddress(sampleRandomString),
    false,
    'should reject random string'
  )
})

test('xpubToHdPassphrase', async (t) => {
  t.plan(1)
  t.equals(
    (await lib.xpubToHdPassphrase(sampleExtendedPublicKey)).toString('hex'),
    sampleHdPassphrase.toString('hex'),
    'should properly compute hd passphrase from xpub',
  )
})

test('address packing/unpacking', async (t) => {
  t.plan(3)

  const expectedV1Address = 'DdzFFzCqrhtBwFyaWje9HStKDWNwWBghBDxGTsnaxoPBE4pZg3pvZC1zDyMpbJqZ7XxpVcHoYc5TA8oA8Hc8gJPUY2kAsaNGW6b8KrrU'
  const expectedV2Address = 'Ae2tdPwUPEZCxt4UV1Uj2AMMRvg5pYPypqZowVptz3GYpK4pkcvn3EjkuNH'
  const derivationPath = [2147483648, 2147483649]

  t.equals(
    lib.packAddress(
      derivationPath,
      sampleExtendedPublicKey,
      sampleHdPassphrase,
      1
    ),
    expectedV1Address,
    'should properly pack V1 address'
  )
  t.equals(
    JSON.stringify(lib.unpackAddress(
      expectedV1Address,
      sampleHdPassphrase
    ).derivationPath),
    JSON.stringify(derivationPath),
    'should properly unpack V1 address'
  )
  t.equals(
    lib.packAddress(
      derivationPath,
      sampleExtendedPublicKey,
      sampleHdPassphrase,
      2
    ),
    'Ae2tdPwUPEZCxt4UV1Uj2AMMRvg5pYPypqZowVptz3GYpK4pkcvn3EjkuNH',
    'should properly pack V1 address'
  )
})