// protocol.1.js



var protocol = protocol || [];



protocol[1] = {
    
    headerLength: 2,
    
    // scrypt constants
    p: 1,
    dkLen: 32, // for aes256 (256 / 8 == 32)
    
    
    // v1 header layout
    
    // first byte
    //  0-4 .version                always 1
    //  4-8 .scrypt.N = val+5       5 to 20
    
    // second byte
    //  0-2 .scrypt.r = 2*(val+4)   8, 10, 12, or 14
    //  2-3 .ascii                  if true ASCII-only
    //  3-4 .lowerpw                if true toLower(passphrase)
    //  4-8 .saltLength = val+4     4 to 19 emoji
    //  4-8 .hmacLength = val+4     4 to 19 emoji
    decodeHeader: function(lib, header) {
        var v, N, r, a, l, s, params;
        
        if (!header instanceof Uint8Array)
            throw new TypeError("Protocol header must be a Uint8Array.");
        if (header.length != protocol[1].headerLength)
            throw new TypeError("Protocol header is not the correct size");
        
        // first byte (emoji)
        v = lib.bitSlice(header[0], 0, 4);
        N = lib.bitSlice(header[0], 4);
        
        // second byte (emoji)
        r = lib.bitSlice(header[1], 0, 2);
        a = lib.bitSlice(header[1], 2, 3);
        l = lib.bitSlice(header[1], 3, 4);
        s = lib.bitSlice(header[1], 4);
        
        params = {
            version: 1,
            scrypt: {
                N: N + 5,
                r: 2*(r+4),
                p: protocol[1].p,
                dkLen: protocol[1].dkLen,
            },
            ascii: Boolean(a),
            lowerpw: Boolean(l),
            saltLength: s + 4,
            hmacLength: s + 4,
        };
        
        return params;
    },
    
    
    
    encodeHeader: function(lib, params) {
        var scrypt, invalidParams, validValues, header;
        
        scrypt = params.scrypt;
        
        // accrue invalid parameters
        invalidParams = [];
        validValues = [];
        
        if (params.version != 1) {
            invalidParams.push("version");
            validValues.push("only version 1.");
        }
        
        if (typeof(scrypt.N) != "number")
            throw new TypeError("scrypt.N must be a number.");
        if (scrypt.N < 5 || scrypt.N > 20) {
            invalidParams.push("scrypt.N");
            validValues.push("a number between 5 and 20 inclusive");
        }
        
        if (typeof(scrypt.r) != "number")
            throw new TypeError("scrypt.r must be a number.");
        if (scrypt.r < 8 || scrypt.r > 14 || scrypt.r % 2 != 0) {
            invalidParams.push("scrypt.r");
            validValues.push("8, 10, 12, or 14");
        }
        
        if (typeof(params.saltLength) != "number")
            throw new TypeError("saltLength must be a number.");
        if (params.saltLength < 4 || params.saltLength > 19) {
            invalidParams.push("saltLength");
            validValues.push("a number between 4 and 19 inclusive");
        }
        
        if (typeof(params.hmacLength) != "number")
            throw new TypeError("hmacLength must be a number.");
        if (params.hmacLength != params.saltLength) {
            invalidParams.push("hmacLength");
            validValues.push("the same as saltLength");
        }
        
        if (invalidParams.length > 0)
            throw new ProtocolParameterError(
                version,
                invalidParams,
                validValues
            );
        
        params.ascii = Boolean(params.ascii);
        params.lowerpw = Boolean(params.lowerpw);
        
        header = [];
        
        header[0] =
            (params.version << 4)
            | (scrypt.N - 5);
        
        header[1] =
            (scrypt.r/2 - 4 << 6)
            | (params.ascii << 5)
            | (params.lowerpw << 4)
            | (params.saltLength - 4);
        
        return header;
    },
    
    
    
    decrypt: function(lib, emojicrypt, passphrase, params, progressCallback) {
        var headerLength, hmac, salt, ciphertext;
        
        if (!emojicrypt instanceof Uint8Array)
            throw new TypeError("Emojicrypt must be a Uint8Array.");
        if (typeof(passphrase) != "string")
            throw new TypeError("Passphrase must be a string.");
        
        if (params.lowerpw) passphrase = passphrase.toLowerCase();
        passphrase = lib.utf8ToBuffer(passphrase);
        
        headerLength = protocol[1].headerLength;
        
        hmac = emojicrypt.slice(
            headerLength,
            headerLength + params.hmacLength
        );
        salt = emojicrypt.slice(
            headerLength + params.hmacLength,
            headerLength + params.hmacLength + params.saltLength
        );
        ciphertext = emojicrypt.slice(
            headerLength + params.hmacLength + params.saltLength
        );
        
        return lib.scrypt(
            passphrase, salt, params.scrypt, progressCallback
        ).then(function(scryptHash) {
            
            // calculate & verify HMAC
            return lib.sha256(
                lib.joinBuffers(scryptHash, salt, ciphertext)
            ).then(function(calculatedHmac) {
                
                calculatedHmac = calculatedHmac.slice(0, params.hmacLength);
                calculatedHmac = new Uint8Array(calculatedHmac);
                
                // incorrect HMAC
                if (!lib.compareBuffers(hmac, calculatedHmac)) {
                    return Promise.reject(new IncorrectHmacError(
                        hmac, calculatedHmac
                    ));
                }
                
                // import the scrypt hash as a CryptoKey
                return lib.createKey("AES-GCM", scryptHash, ["decrypt"]);
                
            });
            
        }).then(function(key) {
            
            // decrypt with AES-GCM
            return lib.decryptGCM(ciphertext, key, salt);
            
        }).then(function(plaintext) {
            
            plaintext = new Uint8Array(plaintext);
            
            if (params.ascii) {
                plaintext = lib.bufferToAscii(plaintext);
            } else {
                plaintext = lib.bufferToUtf8(plaintext);
            }
            
            return Promise.resolve(plaintext);
        });
    },
    
    
    
    encrypt: function(lib, message, passphrase, params, progressCallback) {
        var header, salt;
        
        if (typeof(message) != "string")
            throw new TypeError("Message must be a string.");
        if (typeof(passphrase) != "string")
            throw new TypeError("Passphrase must be a string.");
        
        header = protocol[1].encodeHeader(lib, params);
        header = header.map(lib.nToEmoji).join('');
        
        if (params.ascii) {
            message = lib.asciiToBuffer(message);
        } else {
            message = lib.utf8ToBuffer(message);
        }
        
        if (params.lowerpw) passphrase = passphrase.toLowerCase();
        passphrase = lib.utf8ToBuffer(passphrase);
        
        salt = lib.generateRandomBytes(params.saltLength);
        
        return lib.scrypt(
            passphrase, salt, params.scrypt, progressCallback
        ).then(function(scryptHash) {
            
            return lib.createKey(
                "AES-GCM", scryptHash, ["encrypt"]
            ).then(function(key) {
                
                // encrypt with AES-GCM
                // use salt as the IV
                return lib.encryptGCM(message, key, salt);
                
            }).then(function(ciphertext) {
                
                ciphertext = new Uint8Array(ciphertext);
                
                // calculate HMAC
                return lib.sha256(
                    lib.joinBuffers(scryptHash, salt, ciphertext)
                ).then(function(hmac) {
                    
                    hmac = hmac.slice(0, params.hmacLength);
                    hmac = new Uint8Array(hmac);
                    
                    return Promise.resolve(
                        header
                        + baseEmoji.toUnicode(hmac)
                        + baseEmoji.toUnicode(salt)
                        + baseEmoji.toUnicode(ciphertext)
                    );
                    
                });
                
            });
            
        });
    },
    
};

