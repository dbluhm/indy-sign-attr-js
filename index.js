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
    }
});

exports.setup().then(function() {
    exports.test();
});
