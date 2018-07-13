var glob = require('glob')
var exec = require('child_process').exec
var fs = require('fs')

//var files = glob.sync('vendor/cbits/*.c').concat(glob.sync('vendor/cbits/cryptonite_cbits/*.c')).concat(glob.sync('vendor/cbits/ed25519/*.c'))
//var files = glob.sync('vendor/cbits/ed25519/*.c').concat(glob.sync('vendor/cbits/cryptonite_cbits/*.c'))
//console.log(files)
var files = [
'vendor/cbits/ed25519/ed25519.c',
'vendor/cbits/cryptonite_cbits/cryptonite_sha512.c',
'vendor/cbits/cryptonite_cbits/cryptonite_chacha.c',
'vendor/cbits/cryptonite_cbits/cryptonite_pbkdf2.c',
'vendor/cbits/cryptonite_cbits/cryptonite_sha1.c',
'vendor/cbits/cryptonite_cbits/cryptonite_sha256.c',
'vendor/cbits/cryptonite_cbits/blake2/ref/blake2b-ref.c'
]
var command = 'emcc cardano-crypto.c ' + files.join(' ') + ' -o lib.js -O1 -s WASM=0'
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
  fs.appendFileSync(
    'lib.js',
    'if (typeof module !== "undefined") {  module["exports"] = Module; }'
  )
})
