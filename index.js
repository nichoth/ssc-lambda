const { toString } = require('uint8arrays/to-string')
const { fromString } = require('uint8arrays/from-string')
const { webcrypto } = require('one-webcrypto')
const stringify = require('json-stable-stringify')
const sodium = require("chloride")
// import { webcrypto } from 'one-webcrypto'

const KeyType = {
    RSA: "rsa",
    Edwards: "ed25519",
    BLS: "bls12-381"
}

const EDWARDS_DID_PREFIX = new Uint8Array([ 0xed, 0x01 ])
const BLS_DID_PREFIX = new Uint8Array([ 0xea, 0x01 ])
const RSA_DID_PREFIX = new Uint8Array([ 0x00, 0xf5, 0x02 ])
const BASE58_DID_PREFIX = 'did:key:z'
const DEFAULT_HASH_ALG = 'SHA-256'
const DEFAULT_CHAR_SIZE = 16
const ECC_WRITE_ALG = 'ECDSA'
const DEFAULT_ECC_CURVE = 'P-256'

module.exports = {
    didToPublicKey,
    getAuthor,
    isValidMsg,
    getId
}


// this checks the signature and also the merkle integrity of the message with
// the given previous message
function isValidMsg (msg, prevMsg, publicKey) {
    if (typeof publicKey === 'string') {
        return webcrypto.subtle.importKey(
            'raw',
            base64ToArrBuf(publicKey),
            { name: ECC_WRITE_ALG, namedCurve: DEFAULT_ECC_CURVE },
            true,
            ['verify']
        )
            .then(pubKey => {
                return verifyObj(pubKey, null, msg)
                    .then(isVal => isVal && isPrevMsgOk(prevMsg, msg))
            })
    }

    return verifyObj(publicKey, null, msg)
        .then(isVal => isVal && isPrevMsgOk(prevMsg, msg))
}

function verifyObj (publicKey, hmac_key, obj) {
    if (!obj) (obj = hmac_key), (hmac_key = null);
    obj = clone(obj);
    const sig = obj.signature;
    delete obj.signature;
    return verify(publicKey, sig, stringify(obj))
}

function base64ToArrBuf (string) {
    return fromString(string, "base64pad").buffer
}

function verify (publicKey, sig, msg) {
    if (typeof sig === 'object') {
        throw new Error('signature should be base64 string,' +
            'did you mean verifyObj(public, signed_obj)')
    }

    // if we're given a string, we need to convert that
    // into a publicKey instance
    if (typeof publicKey === 'string') {
        // console.log('****is string*****', publicKey)
        return webcrypto.subtle.importKey(
            'raw',
            base64ToArrBuf(publicKey),
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        )
            .then(pubKey => {
                console.log(typeof msg)
                return webcrypto.subtle.verify(
                    {
                        name: ECC_WRITE_ALG,
                        hash: { name: DEFAULT_HASH_ALG }
                    },
                    pubKey,
                    normalizeBase64ToBuf(sig),
                    utils.normalizeUnicodeToBuf(msg, DEFAULT_CHAR_SIZE)
                )
            })
            .then(isOk => {
                console.log('is ok?????', isOk)
                return isOk
            })
    }

    return webcrypto.subtle.verify(
        {
            name: ECC_WRITE_ALG,
            hash: { name: DEFAULT_HASH_ALG }
        },
        publicKey,
        normalizeBase64ToBuf(sig),
        normalizeUnicodeToBuf(msg, DEFAULT_CHAR_SIZE)
    )
}


// -------------------------------------------

function isPrevMsgOk (prevMsg, msg) {
    if (prevMsg === null) return (msg.previous === null)
    return ((msg.previous === getId(prevMsg)) &&
        msg.sequence === prevMsg.sequence + 1)
}


function getId (msg) {
    return '%' + hash(stringify(msg, null, 2))
}

function hash (data, enc) {
    data = (typeof data === 'string' && enc == null) ?
        Buffer.from(data, "binary") :
        Buffer.from(data, enc);

    return sodium.crypto_hash_sha256(data).toString("base64") + ".sha256"
}


// ------------------------------------------


function normalizeUnicodeToBuf (msg, charSize) {
    switch (charSize) {
      case 8: return normalizeUtf8ToBuf(msg)
      default: return normalizeUtf16ToBuf(msg)
    }
}

function normalizeBase64ToBuf (msg) {
    return normalizeToBuf(msg, base64ToArrBuf)
}

function normalizeToBuf (msg, strConv) {
    if (typeof msg === 'string') {
        return strConv(msg)
    } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
        // this is the best runtime check I could find for ArrayBuffer/Uint8Array
        const temp = new Uint8Array(msg)
        return temp.buffer
    } else {
        throw new Error("Improper value. Must be a string, ArrayBuffer, Uint8Array")
    }
}

function normalizeUtf16ToBuf (msg) {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, 16))
}

function strToArrBuf (str, charSize) {
    const view =
      charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)

    for (let i = 0, strLen = str.length; i < strLen; i++) {
      view[i] = str.charCodeAt(i)
    }

    return view.buffer
}



// -----------------------------------




function getAuthor (msg) {
    return msg.author
}

const arrBufs = {
    equal: (aBuf, bBuf) => {
        const a = new Uint8Array(aBuf)
        const b = new Uint8Array(bBuf)
        if (a.length !== b.length) return false
            for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false
        }
        return true
    }
}

function arrBufToBase64 (buf) {
    // return uint8arrays.toString(new Uint8Array(buf), "base64pad")
    return toString(new Uint8Array(buf), "base64pad")
}

function didToPublicKey (did) {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error(
            "Please use a base58-encoded DID formatted `did:key:z...`")
    }

    const didWithoutPrefix = ('' + did.substr(BASE58_DID_PREFIX.length))
    const magicalBuf = fromString(didWithoutPrefix, "base58btc")
    const { keyBuffer, type } = parseMagicBytes(magicalBuf)
  
    return {
        publicKey: arrBufToBase64(keyBuffer),
        type
    }
}

/**
 * Parse magic bytes on prefixed key-buffer
 * to determine cryptosystem & the unprefixed key-buffer.
 */
 function parseMagicBytes (prefixedKey) {
    // console.log('**magical buf**', prefixedKey)
    // RSA
    if (hasPrefix(prefixedKey, RSA_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(RSA_DID_PREFIX.byteLength),
            type: KeyType.RSA
        }
    // EDWARDS
    } else if (hasPrefix(prefixedKey, EDWARDS_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(EDWARDS_DID_PREFIX.byteLength),
            type: KeyType.Edwards
        }
    // BLS
    } else if (hasPrefix(prefixedKey, BLS_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(BLS_DID_PREFIX.byteLength),
            type: KeyType.BLS
        }
    }
  
    throw new Error("Unsupported key algorithm. Try using RSA.")
}

function hasPrefix (prefixedKey, prefix) {
    return arrBufs.equal(prefix, prefixedKey.slice(0, prefix.byteLength))
}

// -------------------------------------

function clone (obj) {
    var _obj = {}
    for (var k in obj) {
        if (Object.hasOwnProperty.call(obj, k)) _obj[k] = obj[k]
    }
    return _obj
}
