const testDid = 'did:key:z82T5XeMUNk67GZtcQ2pYnc34ZyUnMrE1YC1bHQAveSZn7oHAz2xyouSRLYo5FYsi2LD9wGmMBQcobhT3JbKPDfhVF5D4'
const { didToPublicKey, getAuthor, isValidMsg } = require('../')
const test = require('tape')

test('did to public key', t => {
    const { publicKey, type } = didToPublicKey(testDid)
    const expectedKey = 'BHr86Nn+Je6MQJ1gUuNSYvIJDH+nnr7c5D+ePUDY42MGiC/mmLhyXr1OPxoFVLMvycWbRy1u1hupFTfK7zUSGbs='
    t.equal(publicKey, expectedKey, 'should return the right public key')
    t.equal(type, 'ed25519', 'The type should be "ed25519"')
    t.end()
})

test('get author', t => {
    const testMsg = { author: 'me', otherStuff: '123' }
    const author = getAuthor(testMsg)
    t.equal(author, 'me', 'should return `author` value in message')
    t.end()
})

test('isValidMessage with a valid message', t => {
    const testMsg = {
        "previous": null,
        "sequence": 1,
        "author": "did:key:z82T5XnCdYQswR8oEJ6eEHUHvEVVk34jaBRwZFMZ6yEHkAPrVKpk43t6rUcZpZqzvox24hG4djgYRNq5JHigoWoxhEvEJ",
        "timestamp": 1651976991718,
        "hash": "sha256",
        "content": {
          "type": "post",
          "text": "wooo"
        },
        "signature": "HaMjv/gvbDGHnAwa94AB7SBIzriIPua/MYwsZtYHgMYSOtRl5WaEZ+KwQmQVeddHC+8Sw27hPP25UiOb1wKbdw=="
    }

    const { publicKey } = didToPublicKey(testMsg.author)

    isValidMsg(testMsg, null, publicKey).then(isVal => {
        t.ok(isVal, 'should validate a message')
        t.end()
    })

})

test('isValidMsg with an invalid message', t => {
    const testMsg = {
        "previous": null,
        "sequence": 1,
        "author": "did:key:z82T5XnCdYQswR8oEJ6eEHUHvEVVk34jaBRwZFMZ6yEHkAPrVKpk43t6rUcZpZqzvox24hG4djgYRNq5JHigoWoxhEvEJ",
        "timestamp": 1651976991718,
        "hash": "sha256",
        "content": {
          "type": "post",
          "text": "wooo"
        },
        "signature": "fooooo"
    }

    const { publicKey } = didToPublicKey(testMsg.author)

    isValidMsg(testMsg, null, publicKey).then(isVal => {
        t.equal(isVal, false, 'should say an invalid message is invalid')
        t.end()
    }).catch(err => {
        t.ok(err, 'should throw an error with invalid signature')
        t.end()
    })
})
