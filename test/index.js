const testDid = 'did:key:z82T5XeMUNk67GZtcQ2pYnc34ZyUnMrE1YC1bHQAveSZn7oHAz2xyouSRLYo5FYsi2LD9wGmMBQcobhT3JbKPDfhVF5D4'
const { didToPublicKey } = require('../')
const test = require('tape')

test('did to public key', t => {
    const { publicKey, type } = didToPublicKey(testDid)
    const expectedKey = 'BHr86Nn+Je6MQJ1gUuNSYvIJDH+nnr7c5D+ePUDY42MGiC/mmLhyXr1OPxoFVLMvycWbRy1u1hupFTfK7zUSGbs='
    t.equal(publicKey, expectedKey, 'should return the right public key')
    t.equal(type, 'ed25519', 'The type should be "ed25519"')
    t.end()
})
