var Nibbler = require('./nibbler.js');
var nacl = require('tweetnacl');

var base32 = new Nibbler({
  dataBits: 8,
  codeBits: 5,
  keyString: '0123456789abcdefghjkmnpqrstvwxyz',
  pad: '',
  arrayData: true,
});

var fromBase32 = function(s) {
  return new Uint8Array(base32.decode(s));
}

var wrap = function(data, pre) {
  return pre + "(" + base32.encode(data) + ")";
}

var unwrap = function(data, pre) {
  if (data.slice(0, pre.length) !== pre || data.slice(pre.length, pre.length + 1) !== "(" || data.slice(data.length - 1) !== ")") {
    throw "Incorrectly formatted string";
  }
  return fromBase32(data.slice(pre.length + 1, data.length - 1));
}

var concatArrays = function(a, b) {
  var tmp = new Uint8Array(a.length + b.length);
  tmp.set(a, 0);
  tmp.set(b, a.length);
  return tmp;
}

var generateRandomSigningKeypair = function() {
  var {publicKey, secretKey} = nacl.sign.keyPair();
  return {
    publicKey: wrap(publicKey, "ed25519-pub"),
    privateKey: wrap(secretKey, "ed25519-priv")
  }
}

var generateRandomBoxKeypair = function() {
  var {publicKey, secretKey} = nacl.box.keyPair();
  return {
    publicKey: wrap(publicKey, "box-pub"),
    privateKey: wrap(secretKey, "box-priv")
  }
}

var sign = function(privateKey, signable) {
  var toSign = concatArrays(signable.hash(), nacl.util.decodeUTF8(signable.type()));
  var priv = unwrap(privateKey, "ed25519-priv");
  var sig = nacl.sign.detached(toSign, priv);
  return wrap(sig, "ed25519-sig");
}

var verify = function(publicKey, signable, signature) {
  var toSign = concatArrays(signable.hash(), nacl.util.decodeUTF8(signable.type()));
  var pub = unwrap(publicKey, "ed25519-pub");
  var sig = unwrap(signature, "ed25519-sig");
  return nacl.sign.detached.verify(toSign, sig, pub);
}

var encrypt = function(message, publicKey, privateKey) {
  var nonce = nacl.randomBytes(24);
  var pub = unwrap(publicKey, "box-pub");
  var priv = unwrap(privateKey, "box-priv");
  var encrypted = nacl.box(nacl.util.decodeUTF8(message), nonce, pub, priv); 
  return wrap(concatArrays(nonce, encrypted), "box-box");
};

var decrypt = function(message, publicKey, privateKey) {
  var msg = unwrap(message, "box-box");
  var nonce = new Uint8Array(msg.buffer, 0, 24);
  var encrypted = new Uint8Array(msg.buffer, 24);
  var pub = unwrap(publicKey, "box-pub");
  var priv = unwrap(privateKey, "box-priv");

  var result = nacl.box.open(encrypted, nonce, pub, priv);
  if (result === false) {
    throw "decryption failed";
  }

  return nacl.util.encodeUTF8(result);
};

var Hasher = function() {
  this.parts = [];
};

Hasher.prototype.write = function(buffer) {
  this.parts.push(buffer);
};

Hasher.prototype.writeUint64 = function(n) {
  var buffer = new Uint8Array(8);
  for (var i = 0; i < 8; i++) {
    buffer[i] = n & 0xff;
    n = n >> 8;
  }
  this.write(buffer);
};

Hasher.prototype.sum = function() {
  var length = 0;
  for (var elem of this.parts) {
    length += elem.length;
  }
  var buffer = new Uint8Array(length);
  var index = 0;
  for (var elem of this.parts) {
    buffer.set(elem, index);
    index += elem.length;
  }
  return nacl.hash(buffer);
};

var hashString = function(s) {
  var h = new Hasher();
  h.write(nacl.util.decodeUTF8(s));
  return h.sum();
}

var toBitString = function(buffer) {
  var s = "";
  for (var i = 0; i < buffer.length; i++) {
    for (var j = 0; j < 8; j++) {
      s += (buffer[i] >> j) & 1;
    }
  }
  return s;
}

module.exports = {
  generateRandomSigningKeypair: generateRandomSigningKeypair,
  generateRandomBoxKeypair: generateRandomBoxKeypair,
  sign: sign,
  verify: verify,
  encrypt: encrypt,
  decrypt: decrypt,
  Hasher: Hasher,
  hashString: hashString,
  toBitString: toBitString,
  fromBase32: fromBase32
};
