const test = require('tape')
const lib = require('..')
const { AddressTypes, BaseAddressTypes } = require('../features/address')

const sampleWalletMnemonicV1 = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
const sampleWalletMnemonicV2 = 'cost dash dress stove morning robust group affair stomach vacant route volume yellow salute laugh'
const sampleRootKeypairV1 = Buffer.from('d809b1b4b4c74734037f76aace501730a3fe2fca30b5102df99ad3f7c0103e48d54cde47e9041b31f3e6873d700d83f7a937bea746dadfa2c5b0a6a92502356ce6f04522f875c1563682ca876ddb04c2e2e3ae718e3ff9f11c03dd9f9dccf69869272d81c376382b8a87c21370a7ae9618df8da708d1a9490939ec54ebe43000', 'hex')
const sampleRootKeypairV2 = Buffer.from('a018cd746e128a0be0782b228c275473205445c33b9000a33dd5668b430b574426877cfe435fddda02409b839b7386f3738f10a30b95a225f4b720ee71d2505b5569bc9fa461f67b9355b3da8bd4298c5099fd4e001415117a59b424f85ce48cca8cc35f3c2be27b0b26562448a3a4b6bfd1a3828918b87ae76ce17ae96a8306', 'hex')
const samplePublicKey = sampleRootKeypairV1.slice(64, 96)
const sampleExtendedPublicKey = sampleRootKeypairV1.slice(64, 128)
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
const sampleV1AddressBuf = Buffer.from('82d818584283581c6aebd89cf88271c3ee76339930d8956b03f018b2f4871522f88eb8f9a101581e581c692a37dae3bc63dfc3e1463f12011f26655ab1d1e0f4ed4b8fc63708001ad8a9555b', 'hex')
const sampleV2Address = 'Ae2tdPwUPEZ18ZjTLnLVr9CEvUEUX4eW1LBHbxxxJgxdAYHrDeSCSbCxrvx'
const sampleAddressInvalidChecksum = 'Ae2tdPwUPEZ18ZjTLnLVr9CEvUEUX4eW1LBHbxxxJgxdAYHrDeSCSbCxrvm'
const sampleRandomString = 'hasoiusaodiuhsaijnnsajnsaiussai'
const sampleBaseAddress = 'addr1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqcyl47r'
const sampleBaseAddressBuf = Buffer.from('009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc', 'hex')
const sampleScriptAddress = 'addr_test1zqf8ysutwtlp0d25y5crls407s4wv9rs5vd82nr648um5e968m5cqvlnrhd7g8qlwu6vc59l6kcur8ycdv8z38ekat0qdk8pr8'
const sampleScriptAddressBuf = Buffer.from('101272438b72fe17b55425303fc2aff42ae61470a31a754c7aa9f9ba64ba3ee98033f31ddbe41c1f7734cc50bfd5b1c19c986b0e289f36eade', 'hex')
const sampleEnterpriseScriptAddress = 'addr_test1wqf8ysutwtlp0d25y5crls407s4wv9rs5vd82nr648um5eql2052n'
const sampleEnterpriseScriptAddressBuf = Buffer.from('701272438b72fe17b55425303fc2aff42ae61470a31a754c7aa9f9ba64', 'hex')


const mainnetProtocolMagic = 764824073
const testnetProtocolMagic = 42

test('regression for bootstrap addresses', async (t) => {
  // keep this test at the top because otherwise, the original bug may not manifest
  // see https://github.com/vacuumlabs/cardano-crypto.js/pull/40

  t.plan(1);

  const regressedAddress = lib.packBootstrapAddress(
    [2147483648, 2147483649],
    Buffer.from(
      'fa5955500ecacca4939204a8f1af4639747a161cd35a35368c9c8d48df32685b0f48b0997c0e22e87e9533ba19310ba4a9bf0c6cf37bfed513c37de15761d56e',
      'hex'
    ),
    Buffer.from('7b171a8f6a1200fbfd233094d5d39cf64f688470fa9eb59c90f43edb730020ac', 'hex'),
    1,
    764824073
  );

  t.equals(
    regressedAddress.toString('hex'),
    '82d818584283581c15df2fc2d8b33b76fb0bb55f7e85f6bb67ce6311c4375756773a4714a101581e581c2eab4601bfe583428148994f523c1e942766f5109320134e628f4db6001a2be1e66e',
    'everything should be packed properly'
  );
});

test('wallet secret from mnemonic V1', async (t) => {
  t.plan(1)

  const rootKeypair = await lib.mnemonicToRootKeypair(sampleWalletMnemonicV1, 1)
  t.equals(
    rootKeypair.toString('hex'),
    sampleRootKeypairV1.toString('hex'),
    'wallet secret derivates from mnemonic properly'
  )
})

test('wallet secret from mnemonic V2', async (t) => {
  t.plan(1)

  const rootKeypair = await lib.mnemonicToRootKeypair(sampleWalletMnemonicV2, 2)
  t.equals(
    rootKeypair.toString('hex'),
    sampleRootKeypairV2.toString('hex'),
    'wallet secret derivates from mnemonic properly'
  )
})

test('signing', (t) => {
  t.plan(1)

  const signature = lib.sign(sampleMessage, sampleRootKeypairV1)

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
    lib.derivePrivate(sampleRootKeypairV1, sampleHardenedIndex, 1).toString('hex'),
    sampleHardenedChildKeyMode1.toString('hex'),
    'should properly derive hardened child key in derivation mode 1'
  )

  t.equals(
    lib.derivePrivate(sampleRootKeypairV1, sampleHardenedIndex, 2).toString('hex'),
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

test('bootstrap address validation', async (t) => {
  t.plan(4)
  t.equals(
    lib.isValidBootstrapAddress(sampleV1Address),
    true,
    'should accept V1 address'
  )
  t.equals(
    lib.isValidBootstrapAddress(sampleV2Address),
    true,
    'should accept V2 address'
  )
  t.equals(
    lib.isValidBootstrapAddress(sampleAddressInvalidChecksum),
    false,
    'should reject address with invalid checksum'
  )

  t.equals(
    lib.isValidBootstrapAddress(sampleRandomString),
    false,
    'should reject random string'
  )
})

test('Shelley address validation', async (t) => {
  t.plan(3)
  t.equals(
    lib.isValidShelleyAddress(sampleBaseAddress),
    true,
    'should accept Shelley base address'
  )
  t.equals(
    lib.isValidShelleyAddress(sampleV1Address),
    false,
    'should reject bootstrap address'
  )
  t.equals(
    lib.isValidShelleyAddress('garbage'),
    false,
    'should reject arbitrary string'
  )
})

test('script address validation', async (t) => {
  t.plan(3)
  t.equals(lib.hasSpendingScript(lib.addressToBuffer(sampleBaseAddress)),
    false,
    'should reject pubkey address')
  t.equals(lib.hasSpendingScript(lib.addressToBuffer(sampleScriptAddress)),
    true,
    'should accept base script address')
  t.equals(lib.hasSpendingScript(lib.addressToBuffer(sampleEnterpriseScriptAddress)),
    true,
    'should accept enterprise script address')
})

test('xpubToHdPassphrase', async (t) => {
  t.plan(1)
  t.equals(
    (await lib.xpubToHdPassphrase(sampleExtendedPublicKey)).toString('hex'),
    sampleHdPassphrase.toString('hex'),
    'should properly compute hd passphrase from xpub',
  )
})

test('address decoding to buffer', async (t) => {
  t.plan(4)

  t.equals(
    lib.addressToBuffer(
      sampleV1Address
    ).toString('hex'),
    sampleV1AddressBuf.toString('hex'),
    'should properly decode bootstrap address'
  )

  t.equals(
    lib.addressToBuffer(
      sampleBaseAddress
    ).toString('hex'),
    sampleBaseAddressBuf.toString('hex'),
    'should properly decode shelley address'
  )

  t.equals(
    lib.addressToBuffer(
      sampleScriptAddress
    ).toString('hex'),
    sampleScriptAddressBuf.toString('hex'),
    'should properly decode shelley script address'
  )

  t.equals(
    lib.addressToBuffer(
      sampleEnterpriseScriptAddress
    ).toString('hex'),
    sampleEnterpriseScriptAddressBuf.toString('hex'),
    'should properly decode shelley script address'
  )
})

test('bootstrap address packing/unpacking', async (t) => {
  t.plan(11)

  const expectedV1MainnetAddress = 'DdzFFzCqrhtBwFyaWje9HStKDWNwWBghBDxGTsnaxoPBE4pZg3pvZC1zDyMpbJqZ7XxpVcHoYc5TA8oA8Hc8gJPUY2kAsaNGW6b8KrrU'
  const expectedV1TestnetAddress = '2RhQhCGqYPDmqw91gYAqUQ51tHrnCg2YqJQobexuYfy7EG6JosyBGz4X6QzDZuGo2kDQ47SCQgJcaPvxoFbBUM8oFcQY9X8bqaws6ciB7LHLSG'
  const expectedV2MainnetAddress = 'Ae2tdPwUPEZCxt4UV1Uj2AMMRvg5pYPypqZowVptz3GYpK4pkcvn3EjkuNH'
  const expectedV2TestnetAddress = '2657WMsDfac6Ta3RW1eFspxR4ihnKpJvicSzNuVvSMBYYWHP1vvsQLjh3aASd8ZN6'

  const derivationPath = [2147483648, 2147483649]

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPath,
      sampleExtendedPublicKey,
      sampleHdPassphrase,
      1,
      mainnetProtocolMagic
    )),
    expectedV1MainnetAddress,
    'should properly pack mainnet V1 address (inputs to function not matching standards!)'
  )
  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPath,
      sampleExtendedPublicKey,
      sampleHdPassphrase,
      1,
      testnetProtocolMagic
    )),
    expectedV1TestnetAddress,
    'should properly pack testnet V1 address (inputs to function not matching standards!)'
  )
  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPath,
      sampleExtendedPublicKey,
      sampleHdPassphrase,
      2,
      mainnetProtocolMagic
    )),
    expectedV2MainnetAddress,
    'should properly pack mainnet V2 address (inputs to function not matching standards!)'
  )
  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPath,
      sampleExtendedPublicKey,
      sampleHdPassphrase,
      2,
      testnetProtocolMagic
    )),
    expectedV2TestnetAddress,
    'should properly pack testnet V2 address (inputs to function not matching standards!)'
  )
  t.equals(
    lib.getBootstrapAddressAttributes(
      lib.addressToBuffer(expectedV1MainnetAddress),
    ).size,
    1,
    'should properly get Daedalus bootstrap address attributes'
  )
  t.equals(
    lib.getBootstrapAddressAttributes(
      lib.addressToBuffer(expectedV2MainnetAddress),
    ).size,
    0,
    'should properly get Icarus bootstrap address attributes'
  )
  t.equals(
    lib.getBootstrapAddressAttributes(
      lib.addressToBuffer(expectedV1TestnetAddress),
    ).size,
    2,
    'should properly get Daedalus bootstrap address attributes'
  )
  t.equals(
    JSON.stringify(lib.getBootstrapAddressDerivationPath(
      lib.addressToBuffer(expectedV1TestnetAddress),
      sampleHdPassphrase
    )),
    JSON.stringify(derivationPath),
    'should properly get Daedalus bootstrap address derivation path'
  )
  t.equals(
    lib.getBootstrapAddressDerivationPath(
      lib.addressToBuffer(expectedV2MainnetAddress),
      sampleHdPassphrase
    ),
    null,
    'should properly get Icarus bootstrap address derivation path'
  )
  t.equals(
    lib.getBootstrapAddressProtocolMagic(
      lib.addressToBuffer(expectedV1MainnetAddress),
    ),
    mainnetProtocolMagic,
    'should properly get Daedalus bootstrap mainnet address protocol magic'
  )
  t.equals(
    lib.getBootstrapAddressProtocolMagic(
      lib.addressToBuffer(expectedV1TestnetAddress),
    ),
    testnetProtocolMagic,
    'should properly get Daedalus bootstrap testnet address protocol magic'
  )
})

test('bootstrap address packing/unpacking by Cardano Specs', async (t) => {
  t.plan(8)

  // V1 (Daedalus)
  // we use the predefined `sampleWalletMnemonicV1`
  // we use the precalculated `sampleHdPassphrase`;

  // 0'/0' : Daedalus' derivation path from the root key to #0 address level
  // Should be passed to `packBootstrapAddress` function
  const derivationPathV1 = [2147483648, 2147483648]

  // we need an address-related public key to build a root part of the address properly
  // (!!!) Warning: we can still build a semi-valid address with a wrong public key, we will be able to receive funds with it, but they will be locked forever (!!!)
  const addrLevelPubKeyV1 = Buffer.from('f286b12bacea7be1a19d581bd573bdc82e8410b98c3a70485b6d6eeb5e88028e00857e69a9598ab4db1346586f8f2c9440f61ccaca62ed36182b9f26fef4a9dd', 'hex')

  const expectedV1MainnetAddress = 'DdzFFzCqrhsnx5973UzwoEcQ7cN3THD9ZQZvbVd5srhrPoECSt1WUTrQSR8YicSnH3disaSxQPcNMUEC7XNuFxRd8jCAKVXLne3r29xs'
  const expectedV1TestnetAddress = '2RhQhCGqYPDp2jj9jTSErRXMduon1NsBk9DYsA673z74iDPBEwePFxzADN5EiYR8SeueZJouVruiShPeCFrxh4TsBUPEHi9s9wQ9VAaXims2Tg'

  // V2 (Icarus)
  // we use the predefined `sampleWalletMnemonicV2`
  // we can also use the precalculated `sampleHdPassphrase`, but it shouldn't affect the result;

  // 44'/1815'/0'/0/0 : Icarus' derivation path from the root key to #0 address level
  // Can be passed to `packBootstrapAddress` function, but shouldn't affect the result
  const derivationPathV2 = [2147483692, 2147485463, 2147483648, 0, 0]

  // we need an address-related public key to build a root part of the address properly
  const addrLevelPubKeyV2 = Buffer.from('57fd54be7b38bb8952782c2f59aa276928a4dcbb66c8c62ce44f9d623ecd5a03bf36a8fa9f5e11eb7a852c41e185e3969d518e66e6893c81d3fc7227009952d4', 'hex')

  const expectedV2MainnetAddress = 'Ae2tdPwUPEZ6RUCnjGHFqi59k5WZLiv3HoCCNGCW8SYc5H9srdTzn1bec4W'
  const expectedV2TestnetAddress = '2657WMsDfac5nAAZqGe63zmpNvszCktsTup2xUqVBXgvr21nxyuXxf6WbQzKKATDg'

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPathV1,
      addrLevelPubKeyV1,
      sampleHdPassphrase,
      1,
      mainnetProtocolMagic
    )),
    expectedV1MainnetAddress,
    'should properly pack mainnet V1 address by Cardano Specs'
  )
  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPathV1,
      addrLevelPubKeyV1,
      sampleHdPassphrase,
      1,
      testnetProtocolMagic
    )),
    expectedV1TestnetAddress,
    'should properly pack testnet V1 address by Cardano Specs'
  )
  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPathV2,
      addrLevelPubKeyV2,
      sampleHdPassphrase,
      2,
      mainnetProtocolMagic
    )),
    expectedV2MainnetAddress,
    'should properly pack mainnet V2 address by Cardano Specs'
  )

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      [],
      addrLevelPubKeyV2,
      sampleHdPassphrase,
      2,
      mainnetProtocolMagic
    )),
    expectedV2MainnetAddress,
    'should properly pack mainnet V2 address by Cardano Specs with empty `derivationPath`'
  )

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPathV2,
      addrLevelPubKeyV2,
      '',
      2,
      mainnetProtocolMagic
    )),
    expectedV2MainnetAddress,
    'should properly pack mainnet V2 address by Cardano Specs with empty `hdPassphrase`'
  )

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPathV2,
      addrLevelPubKeyV2,
      sampleHdPassphrase,
      2,
      testnetProtocolMagic
    )),
    expectedV2TestnetAddress,
    'should properly pack testnet V2 address by Cardano Specs'
  )

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      [],
      addrLevelPubKeyV2,
      sampleHdPassphrase,
      2,
      testnetProtocolMagic
    )),
    expectedV2TestnetAddress,
    'should properly pack testnet V2 address by Cardano Specs with empty `derivationPath`'
  )

  t.equals(
    lib.base58.encode(lib.packBootstrapAddress(
      derivationPathV2,
      addrLevelPubKeyV2,
      '',
      2,
      testnetProtocolMagic
    )),
    expectedV2TestnetAddress,
    'should properly pack testnet V2 address by Cardano Specs with empty `hdPassphrase`'
  )
})

test('shelley addresses', (t) => {
  t.plan(6)

  let spendingPubKey = Buffer.from('73fea80d424276ad0978d4fe5310e8bc2d485f5f6bb3bf87612989f112ad5a7d', 'hex')
  let stakingPubKey = Buffer.from('2c041c9c6a676ac54d25e2fdce44c56581e316ae43adc4c7bf17f23214d8d892', 'hex')
  const scriptStakingPubKey = Buffer.from('ee2a468c65fd5c2febb1b1f2024eedde097cf3d7df43e0961b5774c1a95ad58c', 'hex')
  let spendingKeyHash = lib.getPubKeyBlake2b224Hash(spendingPubKey)
  let stakingKeyHash = lib.getPubKeyBlake2b224Hash(stakingPubKey)
  let scriptHash = Buffer.from('1272438b72fe17b55425303fc2aff42ae61470a31a754c7aa9f9ba64', 'hex')
  let scriptStakingHash = lib.getPubKeyBlake2b224Hash(scriptStakingPubKey)
  t.equals(
    lib.packBaseAddress(
      spendingKeyHash,
      stakingKeyHash,
      3
    ).toString('hex'),
    '039493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc',
    'should properly derive base address'
  )
  t.equals(
    lib.packBaseAddress(
      scriptHash,
      scriptStakingHash,
      0,
      BaseAddressTypes.SCRIPT_KEY
    ).toString('hex'),
    sampleScriptAddressBuf.toString('hex'),
    'should properly derive script address'
  )
  t.equals(
    lib.packEnterpriseAddress(spendingKeyHash, 0).toString('hex'),
    '609493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e',
    'should properly derive enterprise address'
  )
  let pointer = { blockIndex: 24157, txIndex: 177, certificateIndex: 42 }
  t.equals(
    lib.packPointerAddress(spendingKeyHash, pointer, 3).toString('hex'),
    '439493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e81bc5d81312a',
    'should properly derive pointer address'
  )
  t.equals(
    lib.getAddressType(
      Buffer.from('439493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e81bc5d81312a', 'hex')
    ),
    AddressTypes.POINTER,
    'should properly decode address type from shelley address header'
  )
  t.equals(
    lib.getShelleyAddressNetworkId(
      Buffer.from('439493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e81bc5d81312a', 'hex')
    ),
    3,
    'should properly decode address network id from shelley address header'
  )
})

test('bech32', (t) => {
  t.plan(2)

  t.equals(
    lib.bech32.encode('addr', sampleBaseAddressBuf),
    sampleBaseAddress,
    'should properly encode bech32 address'
  )
  t.equals(
    lib.bech32.decode(sampleBaseAddress).data.toString('hex'),
    sampleBaseAddressBuf.toString('hex'),
    "should properly decode bech32 address"
  )
})

test('proper error handling by the library', (t) => {
  // to avoid accidentally injecting unhandledRejection handler with Emscripten
  t.plan(1)
  t.equals(
    process.listeners('unhandledRejection').length,
    0,
    "no unhandled rejection listener should be registered"
  )
})
