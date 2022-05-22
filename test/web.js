const test = require('tape')
const ssc = require('@nichoth/ssc/web')
const sscLambda = require('../')

var msg

test('create a message in web', t => {
    ssc.createKeys().then(keys => {
        ssc.createMsg(keys, null, { type: 'test', text: 'ok' })
            .then(_msg => {
                console.log('*msg*', _msg)
                msg = _msg
                t.end()
            })
            .catch(err => {
                console.log('in here', err)
                t.end()
            })
    })
    .catch(err => {
        console.log('errrrrrrr', err)
        t.end()
    })
})

test('validate the message in lambda', t => {
    // isValidMsg(msg, null, publicKey).then(isVal => {
    const { publicKey } = sscLambda.didToPublicKey(msg.author)
    sscLambda.isValidMsg(msg, null, publicKey)
        .then(isVal => {
            t.equal(isVal, true, 'should validate the message')
            t.end()
        })
})
