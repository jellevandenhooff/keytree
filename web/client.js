var crypto = require('./crypto');

var $ = require('jquery');

var knownKeys = {
  "keytree.io": "ed25519-pub(26wj522ncyprkc0t9yr1e1cz2szempbddkay02qqqxqkjnkbnygg)",
  "mzero.org": "ed25519-pub(53y84fc8acd8z1t0ckwvtc1nc2srrgrkee5mwtxvtdqytpwrc36g)",
  "thesquareplanet.com": "ed25519-pub(9rr08e8hf82xfkpx944xht4asksasfgnxj8fxkmf3tczeaj1v7q0)",
};

var now = function() {
  return Date.now() / 1000;
};

var maxSignatureAge = 60; // allow signatures up to 60 seconds old

var defaultConfig = {
  keys: [knownKeys["keytree.io"], knownKeys["mzero.org"], knownKeys["thesquareplanet.com"]],
  threshold: 2
};

var downloadJson = function(url) {
  return Promise.resolve($.ajax(url, {dataType: 'json'}));
}

var completeLookup = function(lookup, key, value) {
  var current;
  var isLeaf;

  if (crypto.hashEq(value, crypto.emptyHash)) {
    current = crypto.emptyHash;
    isLeaf = false;
  } else {
    current = crypto.combineHashes(key, value);
    isLeaf = true;
  }

  var leafIdx = crypto.firstDifference(key, crypto.fromBase32(lookup.LeafKey));

  for (var i = crypto.hashBits - 1; i >= 0; i--) {
    var h;
    if (lookup.Hashes[i]) {
      h = crypto.fromBase32(lookup.Hashes[i]);
    } else {
      h = crypto.emptyHash;
    }

    if (i == leafIdx) {
      h = crypto.combineHashes(crypto.fromBase32(lookup.LeafKey), h);

      if (crypto.hashEq(current, crypto.emptyHash)) {
        current = h;
        isLeaf = true;
        continue;
      } 
    }

    if (crypto.hashEq(h, crypto.emptyHash) && isLeaf) {
      continue;
    }

    if (crypto.getBit(key, i) == 0) {
      current = crypto.combineHashes(current, h);
    } else {
      current = crypto.combineHashes(h, current);
    }
    isLeaf = false;
  }
  return current;
}

var entryType = {
  type: "github.com/jellevandenhooff/keytree.Entry-0.4",
  hash: function(entry) {
    if (entry == null) {
      return crypto.emptyHash;
    }

    var h = new crypto.Hasher();
    h.writeString(entry.Name);

    var names = Object.keys(entry.Keys);
    names.sort(); // TODO: Is this sort ordering the same as Go's?

    h.writeUint64(names.length);
    for (var name of names) {
      var key = entry.Keys[name];
      h.writeString(name);
      h.writeString(key);
    }

    h.writeUint64(entry.Timestamp);
    h.writeBool(entry.InRecovery);

    return h.sum();
  }
};

var rootType = {
  type: "github.com/jellevandenhooff/keytree.Root-0.1",
  hash: function(root) {
    var h = new crypto.Hasher();
    h.write(crypto.fromBase32(root.RootHash));
    h.writeUint64(root.Timestamp);
    return h.sum();
  }
};

var lookupRaw = async function(name) {
  var lookup = await downloadJson(`http://keytree.io/keytree/lookup?name=${name}`);

  var cutoff = now() - maxSignatureAge;

  for (var key of Object.keys(lookup.SignedTrieLookups)) {
    var signedLookup = lookup.SignedTrieLookups[key];
    var signedRoot = signedLookup.SignedRoot;

    var expectedRootHash = completeLookup(signedLookup.TrieLookup, crypto.hashString(name), entryType.hash(lookup.Entry));

    if (!crypto.hashEq(crypto.fromBase32(signedRoot.Root.RootHash), expectedRootHash)) {
      throw "bad root hash";
    }
    
    if (signedRoot.Root.Timestamp < cutoff) {
      throw "signature too old";
    }

    if (crypto.verify(key, signedRoot.Root, rootType, signedRoot.Signature) !== true) {
      throw "bad signature";
    }
  };

  return lookup;
};

var lookupWithConfig = async function(name, config) {
  var lookup = await lookupRaw(name);

  var ok = 0;
  for (var key of config.keys) {
    if (key in lookup.SignedTrieLookups) {
      ok++;
    }
  }
  
  if (ok < config.threshold) {
    throw "not enough signatures";
  }

  return lookup.Entry;
};

var lookup = async function(name) {
  return await lookupWithConfig(name, defaultConfig);
}

module.exports = {
  lookupRaw: lookupRaw,
  lookupWithConfig: lookupWithConfig,
  lookup: lookup
};
