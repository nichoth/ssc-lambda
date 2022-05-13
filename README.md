# ssc lambda

## install
```
npm i -S @nichoth/ssc-lambda
```

[ssc-related](https://github.com/nichoth/ssc) functions that are factored in such a way that they work in lambda functions. This is to get around [this error](https://answers.netlify.com/t/error-because-import-meta-url-is-undefined/56108).

Until the above error is resolved, this is a solution. In the lambda
functions I only need the `didToPublicKey`, `getAuthor`, and `isValidMsg`
functions so far. 

------------------------------------------

`createKeys`, `exportKeys`, `publicKeyToDid`, on node side

--------------------------------------------------

https://nodejs.org/api/packages.html#conditional-exports

### API

```js
module.exports = {
    didToPublicKey,
    publicKeyToDid,
    getAuthor,
    isValidMsg,
    createKeys,
    exportKeys,
    getId
}
```
