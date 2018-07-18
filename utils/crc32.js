// taken from: https://github.com/SheetJS/js-crc32/blob/master/crc32.js

function signed_crc_table() {
  let c = 0,
    table = new Array(256)

  for (let n = 0; n != 256; ++n) {
    c = n
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    c = c & 1 ? -306674912 ^ (c >>> 1) : c >>> 1
    table[n] = c
  }

  return typeof Int32Array !== 'undefined' ? new Int32Array(table) : table
}

const T = signed_crc_table()

function crc32_buf(buf, seed) {
  if (buf.length > 10000) return crc32_buf_8(buf, seed)
  let C = seed ^ -1,
    L = buf.length - 3
  for (var i = 0; i < L;) {
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
  }
  while (i < L + 3) C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
  return C ^ -1
}

function crc32_buf_8(buf, seed) {
  let C = seed ^ -1,
    L = buf.length - 7
  for (var i = 0; i < L;) {
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
    C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
  }
  while (i < L + 7) C = (C >>> 8) ^ T[(C ^ buf[i++]) & 0xff]
  return C ^ -1
}

function crc32(buf) {
  return crc32_buf(buf) >>> 0
}

module.exports = crc32
