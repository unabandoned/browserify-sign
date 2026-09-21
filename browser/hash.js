'use strict';

// createHash / createHmac over @unabandoned/hash.js.
//
// Upstream reached these through `create-hash` and `create-hmac`, both
// unmaintained since 2018, which between them pull md5.js (2018), cipher-base,
// ripemd160, sha.js, hash-base and to-buffer's typed-array helpers. Every
// algorithm this package signs with — md5, rmd160, sha1, sha224, sha256,
// sha384, sha512 — is implemented in @unabandoned/hash.js, which has no
// dependencies of its own, so that whole subtree collapses into these few
// lines.
//
// Only the slice of the create-hash API this package uses is reproduced:
// `.update(buffer)` chained, then `.digest()` returning a Buffer. The stream
// interface create-hash also exposed is not used here — Sign and Verify are
// themselves streams and call `_hash.update()` from `_write`.

var Buffer = require('safe-buffer').Buffer;
var hash = require('@unabandoned/hash.js');

var algorithms = {
  md5: hash.md5,
  rmd160: hash.ripemd160,
  ripemd160: hash.ripemd160,
  sha1: hash.sha1,
  sha224: hash.sha224,
  sha256: hash.sha256,
  sha384: hash.sha384,
  sha512: hash.sha512
};

function resolve(algorithm) {
  var ctor = algorithms[String(algorithm).toLowerCase()];
  if (!ctor)
    throw new Error('Digest method not supported: ' + algorithm);
  return ctor;
}

// hash.js takes array-likes; Buffer is one. Strings would be interpreted as
// hex/utf8 depending on the encoding argument, so they are converted here
// instead, matching create-hash's default of utf8 for strings.
function toBytes(data, encoding) {
  if (Buffer.isBuffer(data))
    return data;
  if (typeof data === 'string')
    return Buffer.from(data, encoding || 'utf8');
  return Buffer.from(data);
}

function Digest(state) {
  this._state = state;
}

Digest.prototype.update = function update(data, encoding) {
  this._state.update(toBytes(data, encoding));
  return this;
};

Digest.prototype.digest = function digest(encoding) {
  var out = Buffer.from(this._state.digest());
  return encoding ? out.toString(encoding) : out;
};

function createHash(algorithm) {
  return new Digest(resolve(algorithm)());
}

function createHmac(algorithm, key) {
  return new Digest(hash.hmac(resolve(algorithm), toBytes(key)));
}

module.exports = createHash;
module.exports.createHash = createHash;
module.exports.createHmac = createHmac;
