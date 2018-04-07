# libemojicrypt.js


## Errors

TODO


## Parameters

TODO


## Dependencies

``emoji256.js``

``pfrazee-base-emoji.js``

``protocol.1.js``
``protocol.N.js``


## Exported functions


#### decrypt
```js
emojicrypt.decrypt(emojicrypt, passphrase, progressCallback)
```
```js
/* arguments */

typeof(emojicrypt) == 'string'
// string of unicode emoji

typeof(passphrase) == 'string'
// passphrase gets normalized using "NFKC"

typeof(progressCallback) == 'function'
|| typeof(progressCallback) == 'undefined'
// called each time progress increments

progressCallback = function(progress) {
    progress >= 0  &&  progress <= 1
}
```
```js
/* result */

emojicrypt.decrypt(emojicrypt, passphrase)
    .then(message => {
        typeof(message) == 'string'
    })
    .catch(error => {
        error instanceof UnsupportedProtocolError
        || error instanceof IncorrectHmacError // likely means wrong passphrase
        || error instanceof MissingEmojiError
        || error instanceof TypeError // called with bad argument
    })
```


#### encrypt
```js
emojicrypt.encrypt(message, passphrase, params, progressCallback)
```
```js
/* arguments */

typeof(message) == 'string'
typeof(passphrase) == 'string'
// message and passphrase get normalized using "NFKC"

typeof(params) == 'object'
// see Parameters documentation

typeof(progressCallback) == 'function'
|| typeof(progressCallback) == 'undefined'
// called each time progress increments

progressCallback = function(progress) {
    progress >= 0  &&  progress <= 1
}
```
```js
/* result */

emojicrypt.encrypt(message, passphrase, params)
    .then(emojicrypt => {
        typeof(emojicrypt) == 'string'
    })
    .catch(error => {
        error instanceof UnsupportedProtocolError
        || error instanceof ProtocolParameterError
        || error instanceof TypeError // called with bad argument
    })
```


## Internal functions


#### emojiToN
```js
lib.emojiToN(emoji)
```
```js
/* arguments */

typeof(emoji) == 'string'
```
```js
/* result */

try {
    n = emojiToN(emoji)
    typeof(n) == 'number'
    n > 0  &&  n <= 255
}
catch(error) {
    error instanceof EmojiMissingError
    error.emoji == emoji
    error.n == null
}
```


#### nToEmoji
```js
lib.nToEmoji(n)
```
```js
/* arguments */

typeof(n) == 'number'
n >= 0  &&  n <= 255
```
```js
/* result */

try {
    emoji = nToEmoji(n)
    
    typeof(emoji) == 'string'
    emoji256.chars.indexOf(emoji) != -1
    emoji256.names.indexOf(emoji) != -1
    
    name = emoji256.names[emoji256.chars.indexOf(emoji)]
    typeof(name) == 'string'
}
catch(error) {
    error instanceof EmojiMissingError
    error.emoji == null
    error.n == n
}
```


#### decodeHeader
```js
lib.decodeHeader(emojicrypt)
```
```js
/* arguments */

typeof(emojicrypt) == 'string'
```
```js
/* result */

try {
    params = decodeHeader(emojicrypt)
    
    typeof(params) == 'object'
    // see Parameters documentation
}
catch(error) {
    error instanceof TypeError
    || error instanceof EmojiMissingError
    || error instanceof UnsupportedProtocolError
    || error instanceof ProtocolParameterError
}
```


#### encodeHeader
```js
lib.encodeHeader(params)
```
```js
/* arguments */

typeof(params) == 'object'
// see Parameters documentation
```
```js
/* result */

try {
    header = encodeHeader(params)
    
    typeof(header) == 'string'
    // string of emoji to prepend to the output
}
catch(error) {
    error instanceof TypeError
    || error instanceof UnsupportedProtocolError
    || error instanceof ProtocolParameterError
}
```


#### generateRandomBytes
wrapper for [Crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
```js
lib.generateRandomBytes(length)
```
```js
/* arguments */

typeof(length) == 'number'
length >= 0
```
```js
/* result */

salt = generateRandomBytes(8)
salt instanceof Uint8Array
salt.length == 8
// used for scrypt salt, AES iv, and HMAC
```


#### createKey
wrapper for [SubtleCrypto.importKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey) raw format
```js
lib.createKey(algo, bytes, uses, exportable)
```
```js
/* arguments */

typeof(algo) == 'string'

uses instanceof Array
|| typeof(uses) == 'undefined'
// defaults to ["encrypt", "decrypt"]

typeof(exportable) == 'boolean'
|| typeof(exportable) == 'undefined'
// defaults to false
```
```js
/* result */

createKey("AES-GCM", bytes, ["encrypt"])
    .then(key => {
        key instanceof CryptoKey
    })
    .catch(error => {
        error instanceof SyntaxError
        || error instanceof TypeError
    })
```


#### decryptGCM
wrapper over [SubtleCrypto.decrypt](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
```js
lib.decryptGCM(ciphertext, key, iv)
```
```js
/* arguments */

// https://developer.mozilla.org/en-US/docs/Web/API/BufferSource
ciphertext instanceof ArrayBuffer
|| ArrayBuffer.isView(ciphertext) // Uint8Array is a view

key instanceof CryptoKey
key.usages.indexOf("decrypt") != -1

// https://developer.mozilla.org/en-US/docs/Web/API/BufferSource
iv instanceof ArrayBuffer
|| ArrayBuffer.isView(iv) // Uint8Array is a view
```
```js
/* result */

decryptGCM(ciphertext, key, iv)
    .then(plaintext => {
        plaintext instanceof ArrayBuffer
    })
    .catch(error => {
        error instanceof InvalidAccessError
        || error instanceof OperationError
    })
```


#### encryptGCM
wrapper over [SubtleCrypto.encrypt](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
```js
lib.encryptGCM(ciphertext, key, iv)
```
```js
/* arguments */

// https://developer.mozilla.org/en-US/docs/Web/API/BufferSource
ciphertext instanceof ArrayBuffer
|| ArrayBuffer.isView(ciphertext) // Uint8Array is a view

key instanceof CryptoKey
key.usages.indexOf("encrypt") != -1

// https://developer.mozilla.org/en-US/docs/Web/API/BufferSource
iv instanceof ArrayBuffer
|| ArrayBuffer.isView(iv) // Uint8Array is a view
```
```js
/* result */

encryptGCM(ciphertext, key, iv)
    .then(ciphertext => {
        ciphertext instanceof ArrayBuffer
    })
    .catch(error => {
        error instanceof InvalidAccessError
        || error instanceof OperationError
    })
```


#### sha256
wrapper over [SubtleCrypto.digest](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest)
```js
lib.sha256(buffer)
```
```js
/* arguments */

buffer instanceof ArrayBuffer
|| ArrayBuffer.isView(buffer) // Uint8Array is a view
```
```js
/* result */

sha256(buffer)
    .then(digest => {
        digest instanceof ArrayBuffer
    })
    .catch(error => {
        // none listed
    })
```


#### scrypt
wrapper over [``scrypt()`` from ``ricmoo/scrypt-js``](https://github.com/ricmoo/scrypt-js/blob/master/scrypt.js#L262)
```js
lib.scrypt(passphrase, salt, N, r, p, length, progressCallback)
```
```js
/* arguments */

passphrase instanceof ArrayBuffer
|| ArrayBuffer.isView(passphrase) // Uint8Array is a view

salt instanceof ArrayBuffer
|| ArrayBuffer.isView(salt) // Uint8Array is a view

N > 0  &&  N <= 20
    (r <= 6  && N <= 20)
||  (r <= 12 && N <= 19)
||  (r <= 16 && N <= 18)
// https://github.com/ricmoo/scrypt-js/blob/master/scrypt.js#L274

r > 0  &&  r <= 16777215
// https://github.com/ricmoo/scrypt-js/blob/master/scrypt.js#L275
// protocol v1 r can be 8, 10, 12, or 16

length > 0

typeof(progressCallback) == 'function'
|| typeof(progressCallback) == 'undefined'
// called each time progress increments

progressCallback = function(progress) {
    progress >= 0  &&  progress <= 1
}
```
```js
/* result */

scrypt(passphrase, salt, N, r, p, length)
    .then(hash => {
        hash instanceof Uint8Array
        hash.length == length
    })
    .catch(error => {
        error instanceof Error
    })
```
