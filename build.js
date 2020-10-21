var exec = require('child_process').exec
var fs = require('fs')

var files = [
  'vendor/cbits/ed25519/ed25519.c',

  'vendor/cbits/cryptonite_cbits/cryptonite_chacha.c',
  'vendor/cbits/cryptonite_cbits/cryptonite_pbkdf2.c',
  'vendor/cbits/cryptonite_cbits/cryptonite_sha1.c',
  'vendor/cbits/cryptonite_cbits/cryptonite_sha256.c',
  'vendor/cbits/cryptonite_cbits/cryptonite_sha512.c',
  'vendor/cbits/cryptonite_cbits/cryptonite_sha3.c',
  'vendor/cbits/cryptonite_cbits/blake2/ref/blake2b-ref.c',

  'vendor/cbits/chachapoly/chacha.c',
  'vendor/cbits/chachapoly/chachapoly.c',
  'vendor/cbits/chachapoly/poly1305.c',
]
var command = `emcc cardano-crypto.c ${files.join(' ')} -o lib.js -Os -s WASM=0 -s EXPORTED_FUNCTIONS='["_malloc", "_free"]' --memory-init-file 0  -s NODEJS_CATCH_EXIT=0`
var child = exec(command, function(err){
  if(err){
    throw err
  }
})
child.stdout.pipe(process.stdout)
child.stderr.pipe(process.stderr)
child.on('exit', function(code){
  if(code){
    process.exit(code)
  }

  /*
  * hotfix to remove catching unhandled rejections. It's already fixed
  * in newer versions of emscripten (see https://github.com/emscripten-core/emscripten/issues/7855)
  * but we experience performance problems with them (see README.md), hence the hotfix.
  */
  var originalLib = fs.readFileSync('lib.js', 'utf-8')
  var patchedLib = originalLib.replace(
    `process["on"]("unhandledRejection",(function(reason,p){process["exit"](1)}));`,
    ''
  ).replace(
    `process["on"]("unhandledRejection",abort);`,
    ''
  )

  // needed in order for the library to work in the browser
  patchedLib += 'if (typeof module !== "undefined") {  module["exports"] = Module; }'
  
  // closes #31 - needed for react-native environment
  patchedLib = patchedLib.replace('(document.currentScript)', '(typeof document !== "undefined" && document.currentScript)')

  fs.writeFileSync('lib.js', patchedLib, 'utf-8')
})
