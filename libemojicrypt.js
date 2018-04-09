// libemojicrypt.js



var libemojicrypt = (function() {



function encrypt(message, passphrase, params, progressCallback) {
    var version, header;
    
    if (typeof(message) != "string") throw new TypeError("Invalid message.");
    if (typeof(passphrase) != "string") throw new TypeError("Invalid passphrase.");
    
    // use latest protocol version if none is specified
    params.version = params.version || protocol.length - 1;
    
    if (typeof(protocol[params.version]) == "undefined")
        throw new ProtocolUnsupportedError(version);
    
    return protocol[params.version].encrypt(
        lib, message, passphrase, params, progressCallback
    );
}



function decrypt(emojicrypt, passphrase, progressCallback) {
    var firstByte, params;
    
    if (typeof(emojicrypt) != "string") throw new TypeError("Invalid emojicrypt.");
    if (typeof(passphrase) != "string") throw new TypeError("Invalid passphrase.");
    
    try { emojicrypt = lib.emojicryptToBuffer(emojicrypt); }
    catch(error) { return Promise.reject(error); }
    
    try { params = lib.decodeHeader(emojicrypt); }
    catch(error) { return Promise.reject(error); }
    
    if (typeof(protocol[params.version]) == "undefined")
        throw new UnsupportedProtocolError(params.version);
    
    
    return protocol[params.version].decrypt(
        lib, emojicrypt, passphrase, params, progressCallback
    );
}



// this function will be updated with new protocol versions
function generateParams(input) {
    var params;
    
    params = {};
    
    params.version = input.version || (protocol.length - 1);
    
    params.scrypt = {};
    params.scrypt.N = input.N || 11;
    params.scrypt.r = input.r || 8;
    
    // NOTE: hardcoded for v1
    params.scrypt.p = protocol[params.version].p;
    params.scrypt.dkLen = protocol[params.version].dkLen;
    
    // these have to be the same for v1
    params.hmacLength = input.s || 6;
    params.saltLength = input.s || 6;
    
    params.ascii = input.ascii || false;
    
    params.lowerpw = input.lowerpw;
    if (typeof(params.lowerpw) != "boolean") params.lowerpw = true;
    
    return params;
}



var lib = {};



lib.emojiToN = function(emoji) {
    var n;
    
    n = emoji256.chars.indexOf(emoji);
    
    if (n == -1) throw new EmojiMissingError(emoji, null);
    
    return n;
}


lib.nameToN = function(name) {
    var n;
    
    n = emoji256.names.indexOf(name);
    
    if (n == -1) throw new EmojiMissingError(name, null);
    
    return n;
}



lib.nToEmoji = function(n) {
    var emoji;
    
    emoji = emoji256.chars[n];
    
    if (typeof("emoji") == "undefined") throw new EmojiMissingError(null, n);
    
    return emoji;
}



lib.emojicryptToBuffer = function(emojicrypt) {
    
    emojicrypt = emojicrypt.replace(/\s/g, '');
    
    return new Uint8Array(
        emojicrypt.split(":").filter(function(part) {
            return part != "";
        }).reduce(function(arr, part) {
            if (/^[\x20-\xFF]*$/.test(part)) {
                arr.push(lib.nameToN(part));
            } else {
                arr = arr.concat(getSymbols(part).map(lib.emojiToN));
            }
            return arr;
        }, [])
    );
    
}



lib.decodeHeader = function(emojicrypt) {
    var firstByte, version, header, params;
    
    firstByte = emojicrypt[0];
    
    version = firstByte >> 4;
    
    if (typeof(protocol[version]) == "undefined")
        throw new UnsupportedProtocolError(version);
    
    header = emojicrypt.slice(0, protocol[version].headerLength);
    
    // may throw an error
    params = protocol[version].decodeHeader(lib, header);
    
    return params;
}



lib.generateRandomBytes = function(length) {
    return window.crypto.getRandomValues(new Uint8Array(length));
}



lib.createKey = function(algo, bytes, uses, exportable) {
    
    if (typeof(uses) == "undefined") uses = ["encrypt", "decrypt"];
    if (typeof(exportable) == "undefined") exportable = false;
    
    return window.crypto.subtle.importKey(
        "raw", bytes, { name: algo }, exportable, uses
    );
}



lib.decryptGCM = function(ciphertext, key, iv) {
    return window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key, ciphertext
    );
}



lib.encryptGCM = function(plaintext, key, iv) {
    return window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key, plaintext
    );
}



lib.sha256 = function(buffer) {
    return window.crypto.subtle.digest({ name: "SHA-256" }, buffer);
}



lib.scrypt = function(passphrase, salt, scryptParams, progressCallback) {
    
    if (typeof(progressCallback) != "function")
        progressCallback = function() {};
    
    return new Promise(function(resolve, reject) {
        try {
            scrypt(
                passphrase, salt,
                1 << scryptParams.N,
                scryptParams.r, scryptParams.p,
                scryptParams.dkLen,
                function(error, progress, hash) {
                    if (error) reject(error);
                    if (!hash) return progressCallback(progress);
                    
                    resolve(new Uint8Array(hash));
                }
            );
        }
        catch(error) { return Promise.reject(error); }
    });
}



lib.utf8ToBuffer = function(string) {
    return new TextEncoder("utf-8").encode(string.normalize("NFKC"));
}



lib.bufferToUtf8 = function(buf) {
    return new TextDecoder("utf-8").decode(buf);
}



lib.asciiToBuffer = function(string) {
    var length, buf;
    
    // printable extended ascii chars only
    if (!/^[\x20-\xFF]*$/.test(string))
        throw new TypeError("String contains more than printable ASCII characters.");
    
    length = string.length;
    buf = new Uint8Array(length);
    
    for (var i = 0; i < length; i++) {
        buf[i] = string.charCodeAt(i);
    }
    
    return buf;
}



lib.bufferToAscii = function(buf) {
    var length;
    
    if (!buf instanceof Uint8Array)
        throw new TypeError("Buffer must be a Uint8Array");
    
    length = buf.length;
    
    return buf.reduce(function(string, byte) {
        return string + String.fromCharCode(byte);
    }, "");
}



lib.bitSlice = function(byte, from, to) {
    var length;
    
    if (typeof(to) != "number") to = 8;
    
    length = to - from;
    
    return byte >> (8-from-length) & ((1 << length) - 1);
}



lib.joinBuffers = function() {
    var buffers, totalLength;
    
    buffers = [].map.call(arguments, function(buf) {
        return new Uint8Array(buf);
    });
    
    totalLength = buffers.reduce(function(totalLength, buf) {
        return totalLength + buf.length;
    }, 0);
    
    return buffers.reduce(function(_, buf) {
        _.buffer.set(buf, _.index);
        _.index += buf.length;
        return _;
    }, {
        buffer: new Uint8Array(totalLength),
        index: 0,
    }).buffer;
}



lib.compareBuffers = function(a, b) {
    return a.every(function(byte, index) {
        return b[index] == byte;
    });
}



// export
return {
    encrypt: encrypt,
    decrypt: decrypt,
    generateParams: generateParams,
    _lib: lib,
};



})();



// define custom error types
EmojiMissingError.prototype = Object.create(Error.prototype);
EmojiMissingError.prototype.name = "EmojiMissingError";
EmojiMissingError.prototype.constructor = EmojiMissingError;
function EmojiMissingError(char, index) {
    this.stack = (new Error()).stack;
    
    this.char = char;
    this.index = index;
    this.message = "Missing emoji from set: " + (char || index) + ".";
}



UnsupportedProtocolError.prototype = Object.create(Error.prototype);
UnsupportedProtocolError.prototype.name = "UnsupportedProtocolError";
UnsupportedProtocolError.prototype.constructor = UnsupportedProtocolError;
function UnsupportedProtocolError(version) {
    this.stack = (new Error()).stack;
    
    this.version = version;
    this.message = "Unsupported protocol version: " + version + ".";
}



ProtocolParameterError.prototype = Object.create(Error.prototype);
ProtocolParameterError.prototype.name = "ProtocolParameterError";
ProtocolParameterError.prototype.constructor = ProtocolParameterError;
function ProtocolParameterError(version, invalidParams, validValues) {
    this.stack = (new Error()).stack;
    
    this.version = version;
    this.invalidParams = invalidParams;
    this.validValues = validValues;
    
    this.message = "Unsupported parameter values for version " + version + ":";
    invalidParams.forEach(function(param, index) {
        this.message += " for parameter " + param + " use " + validValues[index];
    });
}



IncorrectHmacError.prototype = Object.create(Error.prototype);
IncorrectHmacError.prototype.name = "IncorrectHmacError";
IncorrectHmacError.prototype.constructor = IncorrectHmacError;
function IncorrectHmacError(expected, calculated) {
    this.stack = (new Error()).stack;
    
    this.expected = expected;
    this.calculated = calculated;
    
    this.message = "Calculated HMAC does not match given HMAC.\n";
    this.message += " expected: " + baseEmoji.toUnicode(expected);
    this.message += " calculated: " + baseEmoji.toUnicode(calculated);
}
