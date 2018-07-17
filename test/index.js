var test = require('tape')
var lib = require('..')

var sampleWalletMnemonic = 'logic easily waste eager injury oval sentence wine bomb embrace gossip supreme'
var sampleWalletSecret = Buffer.from('d809b1b4b4c74734037f76aace501730a3fe2fca30b5102df99ad3f7c0103e48d54cde47e9041b31f3e6873d700d83f7a937bea746dadfa2c5b0a6a92502356ce6f04522f875c1563682ca876ddb04c2e2e3ae718e3ff9f11c03dd9f9dccf69869272d81c376382b8a87c21370a7ae9618df8da708d1a9490939ec54ebe43000', 'hex')
var samplePublicKey = sampleWalletSecret.slice(64, 96)
var sampleExtendedPublicKey = sampleWalletSecret.slice(64, 128)
var sampleMessage = Buffer.from('Hello world', 'utf-8')
var sampleRightSignature = Buffer.from('1096ddcfb2ad21a4c0d861ef3fabe18841e8de88105b0d8e36430d7992c588634ead4100c32b2800b31b65e014d54a8238bdda63118d829bf0bcf1b631e86f0e', 'hex')
var sampleWrongSignature = Buffer.from('2096ddcfb2ad21a4c0d861ef3fabe18841e8de88105b0d8e36430d7992c588634ead4100c33b2800b31b65e014d54a8238bdda63118d829bf0bcf1b631e86f0e', 'hex')
var sampleHardenedIndex = 0x80000001
var sampleHardenedChildKeyMode1 = Buffer.from('691741c612363ef4a53a3bfa752c038b7a5f9842791db99d9993b480b11196004bbc1614c6ca0d907e33271d14403332089b23c3679dab1fd770f48b83b6f8bf900b5f6a9976064b818f1c45a82c66755c5ae28925b44b7026b8aebebb379413b097e30d8bf55e025a87090016c4f1a47e31013ee30fb1e1c4a1a2a1c502e0b8', 'hex')
var sampleHardenedChildKeyMode2 = Buffer.from('9049fc9cd910252e75dbcac63289db674cc0ab35030bfe9ab2c343d2c3103e48ed8a975dac7e6acba9cfa755049691888f525cb05819e33d5f7ad6ec6636d06b9fa98ca6ded6d6868b7b56f9c08ed66cf8d7585436f63c6ea39ecba996a7051001a5f87bc963cb974998c33b00b4b16343cd3672ffe2664c716651219c18f11f', 'hex')
var sampleNonhardenedIndex = 1
var sampleNonHardenedChildKeyMode1 = Buffer.from('30c87a45fe4a8f143478db0d8db6cf963bdfb559f2a050fceae40bc7e97333f832635e6d3dd3409b00373d4f9b49eb8e9444a4ea8e380397e9711a95b940ecd7', 'hex')
var sampleNonHardenedChildKeyMode2 = Buffer.from('19ad2602cee521db72c4ad41c2daf36ca46cf8e80733822fa0f79c8013de8e6fed4f3181d9f544612c5f15e01db0745111b8ee7fc87b784ee083ad314e094662', 'hex')
var sampleScryptDerivedKey = '5012b74fca8ec8a4a0a62ffdeeee959d'

test('wallet secret from mnemonic', function(t) {
  t.plan(1)

  var walletSecret = lib.walletSecretFromMnemonic(sampleWalletMnemonic)
  t.equals(
    walletSecret.toString('hex'),
    sampleWalletSecret.toString('hex'),
    'wallet secret derivates from mnemonic properly'
  )
})

test('signing', function(t) {
  t.plan(1)

  var signature = lib.sign(sampleMessage, sampleWalletSecret)

  t.equals(
    signature.toString('hex'),
    sampleRightSignature.toString('hex'),
    'signing works properly'
  )
})

test('verifying', function(t){
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

test('key hardened derivation', function(t){
  t.plan(2)

  t.equals(
    lib.derivePrivate(sampleWalletSecret, sampleHardenedIndex, 1).toString('hex'),
    sampleHardenedChildKeyMode1.toString('hex'),
    'should properly derive hardened child key in derivation mode 1'
  )

  t.equals(
    lib.derivePrivate(sampleWalletSecret, sampleHardenedIndex, 2).toString('hex'),
    sampleHardenedChildKeyMode2.toString('hex'),
    'should properly derive hardened child key in derivation mode 2'
  )
})

test('key nonhardened derivation', function(t){
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

test('key nonhardened derivation', function(t){
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

test('blake2b', function(t){
  t.plan(1)

  t.equals(
    lib.blake2b(sampleMessage, 32).toString('hex'),
    'a21cf4b3604cf4b2bc53e6f88f6a4d75ef5ff4ab415f3e99aea6b61c8249c4d0',
    'should properly compute blake2b hash'
  )
})

test('sha3_256', function(t){
  t.plan(1)
  var message = Buffer.from('83008200584078732eb9d33e03b3daab4a4613bc19b8820ef5911caf43785780ec6493653bf67115f7f2c460be13dcc09f06f3d63fffe05a3d12996e5224e189a41ee2ef5c95a101581e581c140539c64edded60a7f2d869373e87e744591935bfcdadaa8517974c', 'hex')

  t.equals(
    lib.sha3_256(message).toString('hex'),
    '98b05e27eab982f4d108694a5ab636d68cc898e4af98980516fe2560b13e53a9',
    'should properly compute sha3_256 hash'
  )
})

test('chacha20poly1305', function(t) {
  t.plan(2)
  var key = Buffer.from('c582f8e7cf7aeb6e5f3e96e939a92ae1642360a51d45150f34e70132a152203f', 'hex')
  var nonce = Buffer.from('serokellfore')
  var message = Buffer.from('9f1a800000001a8000000dff', 'hex')
  var expectedEncryptionResult = Buffer.from('140539c64edded60a7f2d9696b17a78b4494b6bf0eef0cc28cad3c2b', 'hex')

  t.equals(
    lib.chacha20poly1305Encrypt(message, key, nonce, true).toString('hex'),
    expectedEncryptionResult.toString('hex'),
    'should properly encrypt with chacha20poly1305'
  )

  t.equals(
    lib.chacha20poly1305Decrypt(expectedEncryptionResult, key, nonce, false).toString('hex'),
    message.toString('hex'),
    'should properly decrypt with chacha20poly1305'
  )
})

test('cardanoMemoryCombine', function(t) {
  t.plan(2)
  var input = Buffer.from('41227237bcfda3c7b921225e5d883eb7fdbd14935ebe897f5951769a0bc735bdfa3b548357e19f27d59053bfa22f415f8f5d55bfe031bfe2946a4725f3cdfa3c', 'hex')
  var password = 'WalletS3cret'
  var expectedOutput = Buffer.from('80a93f1b0c558631f9473c0169dda414535caefa1a9b4a7a29b41f0d96b4aa4359eafca30ae2726745155a8034c671786984d65b9ac11f850447e3884267801c', 'hex')

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

test('scrypt', function (t) {
  t.plan(1)

  var key = undefined
  lib.scrypt('mypassword', 'saltysalt', {
    N: 16384,
    r: 8,
    p: 1,
    dkLen: 16,
    encoding: 'hex'
  }, function(derivedKey) {
    key = derivedKey
  })

  t.equals(
    key,
    sampleScryptDerivedKey,
    'should properly derive key by scrypt'
  )
})
