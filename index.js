const _sodium = require('libsodium-wrappers');
const Base58 = require('base-58');


exports.setup = (async() => {
  await _sodium.ready;
  const sodium = _sodium;

  function b64url(input) {
    return sodium.to_base64(input, sodium.base64_variants.URLSAFE);
  }

  function b64dec(input) {
    return sodium.from_base64(input, sodium.base64_variants.URLSAFE);
  }

  const ed25519_pub_encoder = {
    name: 'ed25519-pub',
    code: 0xed01,
    encode: bytes => `did:key:z${Base58.encode([ed25519_pub_encoder.code, ...bytes])}`,
    decode: key => {
      if (typeof key !== 'string') {
        throw "Invalid type for key"
      }
      if (!key.startsWith('did:key:z6Mk')) {
        throw 'Only ed25519 keys are supported'
      }
      return Base58.decode(key.slice('did:key:z'.length)).slice(2)
    }
  }

  /**
   * Sign data and format as an attachment.
   * @param data the data to sign
   * @param keys publicKey and privateKey bytes
   */
  exports.signed_attachment = function(data, keys) {
    let didkey = ed25519_pub_encoder.encode(keys.publicKey)
    let protected = b64url(JSON.stringify({
      alg: 'EdDSA',
      kid: didkey,
      jwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: b64url(keys.publicKey),
        kid: didkey
      }
    }))
    let sig_data = b64url(JSON.stringify(data))
    return {
      "mime-type": "application/json",
      data: {
        base64: sig_data,
        jws: {
          header: {kid: didkey},
          protected: protected,
          signature: b64url(sodium.crypto_sign_detached(
            Buffer.from(`${protected}.${sig_data}`, 'ascii'),
            keys.privateKey
          ))
        },
      },
    }
  }

  exports.verify_signed_attachment = function(attachment) {
    let payload = attachment.data.base64
    let sig = b64dec(attachment.data.jws.signature)
    let protected = attachment.data.jws.protected
    let signed_input = Buffer.from(`${protected}.${payload}`)
    return sodium.crypto_sign_verify_detached(
      sig, signed_input, ed25519_pub_encoder.decode(attachment.data.jws.header.kid)
    )
  }

  exports.decode_signed_attachment = function(attachment) {
    return JSON.parse(sodium.to_string(b64dec(attachment.data.base64)))
  }

  exports.sign_attr = function(attr, keys) { //attr: object, keys: {publicKey: UInt8Array, privateKey: UInt8Array}
    let timestamp_bytes = Buffer.alloc(8);
    timestamp_bytes.writeUInt32BE(Math.floor(new Date()/1000), 4);

    let attr_bytes = Buffer.from(JSON.stringify(attr), 'ascii');
    let sig_data_bytes = Buffer.concat([timestamp_bytes, attr_bytes]);
    let signature_bytes = sodium.crypto_sign_detached(sig_data_bytes, keys.privateKey);

    return {
      "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
      signer: Base58.encode(keys.publicKey),
      sig_data: b64url(sig_data_bytes),
      signature: b64url(signature_bytes)
    };
  }

  exports.verify_attr = function(signed_attr) {
    let signature_bytes = b64dec(signed_attr['signature']);
    let sig_data_bytes = b64dec(signed_attr['sig_data']);
    let signer = Base58.decode(signed_attr['signer']);

    let verified = sodium.crypto_sign_verify_detached(
      signature_bytes,
      sig_data_bytes,
      signer
    );

    let attr_string = Buffer.from(sig_data_bytes.slice(8)).toString('ascii');
    return {
      'sig_verified': verified,
      'attr': JSON.parse(attr_string)
    };
  }

  exports.test = function() {
    let keys = sodium.crypto_sign_keypair();
    let res = exports.sign_attr({test: "test"}, keys);
    console.log(JSON.stringify(res));
    console.log(exports.verify_attr(res));
    let didkey = ed25519_pub_encoder.encode(keys.publicKey)
    console.log(didkey)
    console.log(ed25519_pub_encoder.decode(didkey))
    console.log(ed25519_pub_encoder.encode(ed25519_pub_encoder.decode(didkey)))
    res = exports.signed_attachment({test: 'test'}, keys)
    console.log(JSON.stringify(res))
    console.log(exports.verify_signed_attachment(res))
    console.log(exports.decode_signed_attachment(res))
  }
});

exports.setup().then(function() {
  exports.test();
});
