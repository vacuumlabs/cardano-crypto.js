Implementations of the ChaCha20 + Poly1305 and XChaCha20 + Poly1305
AEAD constructions with a goal of simplicity and correctness rather
than performance.

## About

This code provides a portable C reference implementation of two
AEAD constructions built on top of the ChaCha20 reference
implementation from [SUPERCOP](https://bench.cr.yp.to/supercop.html)
and [Poly1305-donna](https://github.com/floodyberry/poly1305-donna).

One construction is XChaCha20 + Poly1305 in a style similar to
[NaCl](https://nacl.cr.yp.to/)'s `crypto_secretbox_xsalsa20poly1305`
but using XChaCha20 instead of XSalsa20.

The other construction is ChaCha20 + Poly1305 as specified in
[RFC 7539](https://tools.ietf.org/html/rfc7539).

## License

Copyright (C) 2016 Will Glozer.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## Cryptography Notice

This distribution includes cryptographic software. The country in
which you currently reside may have restrictions on the import,
possession, use, and/or re-export to another country, of encryption
software. BEFORE using any encryption software, please check your
country's laws, regulations and policies concerning the import,
possession, or use, and re-export of encryption software, to see if
this is permitted. See <http://www.wassenaar.org/> for more
information.

The U.S. Government Department of Commerce, Bureau of Industry and
Security (BIS), has classified this software as Export Commodity
Control Number (ECCN) 5D002.C.1, which includes information security
software using or performing cryptographic functions with asymmetric
algorithms. The form and manner of this distribution makes it
eligible for export under the License Exception ENC Technology
Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and
source code.
