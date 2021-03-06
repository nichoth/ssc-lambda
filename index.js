const { toString } = require('uint8arrays/to-string')
const { fromString } = require('uint8arrays/from-string')
const { webcrypto } = require('one-webcrypto')
const stringify = require('json-stable-stringify')
const sodium = require("chloride")
var timestamp = require('monotonic-timestamp')

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
    publicKeyToDid,
    getAuthor,
    isValidMsg,
    createMsg,
    createKeys,
    exportKeys,
    getId,
    importKeys,
    getDidFromKeys
}

// keys is an object with { public: CryptoKey }
function getDidFromKeys (keys) {
    return exportKeys(keys).then((ks) => {
        return publicKeyToDid(ks.public)
    })
}

function importKeys (keys) {
    return Promise.all([
        webcrypto.subtle.importKey(
            'raw',
            base64ToArrBuf(keys.public),
            { name: ECC_WRITE_ALG, namedCurve: DEFAULT_ECC_CURVE },
            true,
            ['verify']
        ),

        webcrypto.subtle.importKey(
            'pkcs8',
            base64ToArrBuf(keys.private),
            // buf,
            { name: ECC_WRITE_ALG, namedCurve: DEFAULT_ECC_CURVE },
            true,
            ['sign']
        )
    ])
        .then(([pub, priv]) => {
            return { publicKey: pub, privateKey: priv }
        })
}

function isObject (o) {
    return o && 'object' === typeof o
}

function isEncrypted (msg) {
    return (typeof msg.value.content == 'string')
}

async function createMsg (keys, prevMsg, content) {
    if (!isObject(content) && !isEncrypted(content)) {
        throw new Error('invalid message content, ' +
            'must be object or encrypted string')
    }

    return exportKeys(keys).then(exported => {
        const did = publicKeyToDid(exported.public)

        var msg = {
            previous: prevMsg ? getId(prevMsg) : null,
            sequence: prevMsg ? prevMsg.sequence + 1 : 1,
            author: did,
            timestamp: +timestamp(),
            hash: 'sha256',
            content: content
        }

        var err = isInvalidShape(msg)
        if (err) throw err

        return signObj(keys, null, msg)
    })
}

function isInteger (n) {
    return ~~n === n
}

function isString (s) {
    return s && 'string' === typeof s
}

function isFeedId (data) {
    return isString(data) // && feedIdRegex.test(data)
}

function isValidOrder (msg, signed) {
    var keys = Object.keys(msg)

    if (signed && keys.length !== 7) return false

    if (
        keys[0] !== 'previous' ||
        keys[3] !== 'timestamp' ||
        keys[4] !== 'hash' ||
        keys[5] !== 'content' ||
        (signed && keys[6] !== 'signature')
    ) {
        return false
    }

    // author and sequence may be swapped.
    if (!(
        (keys[1] === 'sequence' && keys[2] === 'author') ||
        (keys[1] === 'author' && keys[2] === 'sequence')
    )) {
        return false
    }

    return true
}

function isSupportedHash (msg) {
    return msg.hash === 'sha256'
}

function isInvalidShape (msg) {
    if (
        !isObject(msg) ||
        !isInteger(msg.sequence) ||
        !isFeedId(msg.author) ||
        !(isObject(msg.content) ||
        isEncrypted(msg.content)) ||
        !isValidOrder(msg, false) || //false, because message may not be signed yet.
        !isSupportedHash(msg)
    ) {
        return new Error('message has invalid properties:' +
            JSON.stringify(msg, null, 2))
    }
}

async function signObj (keys, hmac_key, obj) {
    if (!obj) {
        obj = hmac_key
        hmac_key = null
    }
    const _obj = clone(obj)
    _obj.signature = await sign( keys, stringify(_obj) )
    return _obj
}

async function sign (keys, msg) {
    const sig = await webcrypto.subtle.sign(
        {
            name: ECC_WRITE_ALG,
            hash: { name: DEFAULT_HASH_ALG }
        },
        keys.privateKey,
        normalizeUnicodeToBuf(msg, DEFAULT_CHAR_SIZE)
    )

    return arrBufToBase64(sig)
}

function createKeys () {
    const uses = ['sign', 'verify']

    return webcrypto.subtle.generateKey({
        name:  ECC_WRITE_ALG,
        namedCurve: 'P-256'
    }, true, uses)
        .then(keys => {
            return publicKeyToId(keys.publicKey)
                .then(id => {
                    return exportKeys(keys).then(exported => {
                        return {
                            did: publicKeyToDid(exported.public),
                            id,
                            keys
                        }
                    })
                })
        })
}


function publicKeyToDid (publicKey, type) {
    type = type || 'ed25519'

    // convert base64 string to buffer if necessary
    var pubKeyBuf
    if (typeof publicKey === 'string') {
        pubKeyBuf = base64ToArrBuf(publicKey)
    } else {
        pubKeyBuf = publicKey
    }
  
    // Prefix public-write key
    const prefix = magicBytes(type)
    if (prefix === null) {
        throw new Error(`Key type '${type}' not supported`)
    }
  
    const prefixedBuf = joinBufs(prefix, pubKeyBuf)
  
    // Encode prefixed
    return BASE58_DID_PREFIX +
        toString(new Uint8Array(prefixedBuf), "base58btc")
}

function joinBufs (fst, snd) {
    const view1 = new Uint8Array(fst)
    const view2 = new Uint8Array(snd)
    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined.buffer
}


function magicBytes (keyType) {
    switch (keyType) {
        case KeyType.Edwards: return EDWARDS_DID_PREFIX
        case KeyType.RSA: return RSA_DID_PREFIX
        case KeyType.BLS: return BLS_DID_PREFIX
        default: return null
    }
}

function exportKeys (keypair) {
    return Promise.all([
        webcrypto.subtle.exportKey('raw', keypair.publicKey),
        webcrypto.subtle.exportKey('pkcs8', keypair.privateKey)
        // webcrypto.subtle.exportKey('raw', keypair.privateKey)
    ])
        .then(([pub, priv]) => {
            const pair = {
                public: arrBufToBase64(pub),
                private: arrBufToBase64(priv)
            }

            return pair
        })
}

function arrBufToBase64(buf) {
    return uint8arrays.toString(new Uint8Array(buf), "base64pad")
}


async function publicKeyToId (publicKey) {
    if (typeof publicKey === 'string') {
        return '@' + publicKey + '.' + KEY_TYPE
    }

    const raw = await webcrypto.subtle.exportKey('raw', publicKey)
    const str = arrBufToBase64(raw)
    return '@' + str + '.' +  'ed25519'
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

function verifyObj (publicKey, hmac_key, _obj) {
    if (!_obj) (_obj = hmac_key), (hmac_key = null);
    const obj = clone(_obj);
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
        return webcrypto.subtle.importKey(
            'raw',
            base64ToArrBuf(publicKey),
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        )
            .then(pubKey => {
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
    return '%' + hash(stringify(msg))
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
    const _obj = {}
    for (var k in obj) {
        if (Object.hasOwnProperty.call(obj, k)) _obj[k] = obj[k]
    }
    return _obj
}
