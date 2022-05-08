const { toString } = require('uint8arrays/to-string')
const { fromString } = require('uint8arrays/from-string')

const KeyType = {
    RSA: "rsa",
    Edwards: "ed25519",
    BLS: "bls12-381"
}

const EDWARDS_DID_PREFIX = new Uint8Array([ 0xed, 0x01 ])
const BLS_DID_PREFIX = new Uint8Array([ 0xea, 0x01 ])
const RSA_DID_PREFIX = new Uint8Array([ 0x00, 0xf5, 0x02 ])
const BASE58_DID_PREFIX = 'did:key:z'

module.exports = {
    didToPublicKey,
    getAuthor
}

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
