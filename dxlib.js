// For Postman, define functions without relying on global window object
// Place this in your Collection Pre-request Script

// Define utility functions that will be accessible throughout the collection
var dxlib = {};

(function (dxlib) {
    'use strict';

    // These functions replace TextEncoder/TextDecoder
    function encodeUTF8(str) {
        let pos = 0;
        const len = str.length;
        let out = [];

        for (let i = 0; i < len; i++) {
            let point = str.charCodeAt(i);

            if (point <= 0x7F) {
                out[pos++] = point;
            } else if (point <= 0x7FF) {
                out[pos++] = 0xC0 | (point >>> 6);
                out[pos++] = 0x80 | (point & 0x3F);
            } else if (point <= 0xFFFF) {
                out[pos++] = 0xE0 | (point >>> 12);
                out[pos++] = 0x80 | ((point >>> 6) & 0x3F);
                out[pos++] = 0x80 | (point & 0x3F);
            } else if (point <= 0x10FFFF) {
                out[pos++] = 0xF0 | (point >>> 18);
                out[pos++] = 0x80 | ((point >>> 12) & 0x3F);
                out[pos++] = 0x80 | ((point >>> 6) & 0x3F);
                out[pos++] = 0x80 | (point & 0x3F);
            }
        }

        return new Uint8Array(out);
    }

    function decodeUTF8(bytes) {
        let out = '';
        let pos = 0;
        const len = bytes.length;

        while (pos < len) {
            const byte1 = bytes[pos++];
            if (byte1 <= 0x7F) {
                out += String.fromCharCode(byte1);
            } else if (byte1 <= 0xDF) {
                const byte2 = bytes[pos++];
                out += String.fromCharCode(((byte1 & 0x1F) << 6) | (byte2 & 0x3F));
            } else if (byte1 <= 0xEF) {
                const byte2 = bytes[pos++];
                const byte3 = bytes[pos++];
                out += String.fromCharCode(((byte1 & 0x0F) << 12) |
                    ((byte2 & 0x3F) << 6) |
                    (byte3 & 0x3F));
            } else if (byte1 <= 0xF7) {
                const byte2 = bytes[pos++];
                const byte3 = bytes[pos++];
                const byte4 = bytes[pos++];
                let point = ((byte1 & 0x07) << 18) |
                    ((byte2 & 0x3F) << 12) |
                    ((byte3 & 0x3F) << 6) |
                    (byte4 & 0x3F);
                if (point > 0xFFFF) {
                    point -= 0x10000;
                    out += String.fromCharCode(((point >>> 10) & 0x3FF) | 0xD800);
                    point = 0xDC00 | (point & 0x3FF);
                }
                out += String.fromCharCode(point);
            }
        }

        return out;
    }

    // Make sure nacl is available - you'll need to import this in your collection or environment
    // For example, import TweetNaCl.js as a Pre-request Script at the collection level
    var nacl = null;
    try {
        // Try to get nacl from environment if already loaded
        nacl = pm.environment.get("nacl");
        if (!nacl) {
            // Otherwise, assume TweetNaCl is already loaded in the environment
            nacl = nacl || {}; // This should be replaced with your nacl library
            console.log("Warning: nacl not found. Some cryptographic functions will fail.");
        }
    } catch (e) {
        console.error("Error loading nacl:", e);
    }

    class Ed25519 {
        static keyPair() {
            if (!nacl || !nacl.sign) {
                throw new Error("nacl library not available");
            }
            return nacl.sign.keyPair();
        }

        static sign(msg, selfPrivateKey) {
            if (!nacl || !nacl.sign) {
                throw new Error("nacl library not available");
            }
            return nacl.sign.detached(msg, selfPrivateKey);
        }

        static verify(msg, signature, peerPublicKey) {
            if (!nacl || !nacl.sign) {
                throw new Error("nacl library not available");
            }
            return nacl.sign.detached.verify(msg, signature, peerPublicKey);
        }
    }

    class X25519 {
        static keyPair() {
            if (!nacl || !nacl.box) {
                throw new Error("nacl library not available");
            }
            return nacl.box.keyPair();
        }

        static computeSharedSecret(privateAKey, publicBKey) {
            if (!nacl || !nacl.scalarMult) {
                throw new Error("nacl library not available");
            }
            
            // Ensure the privateKey and publicKey are Uint8Arrays
            if (!(privateAKey instanceof Uint8Array) || !(publicBKey instanceof Uint8Array)) {
                throw new Error('Both keys must be Uint8Arrays');
            }

            return nacl.scalarMult(privateAKey, publicBKey);
        }
    }

    function toUint8Array(data) {
        // If already a Uint8Array, return it
        if (data instanceof Uint8Array) {
            return data;
        }

        // If it's an ArrayBuffer, create a view of it
        if (data instanceof ArrayBuffer) {
            return new Uint8Array(data);
        }

        // If it's a string, encode it using our custom UTF-8 encoder
        if (typeof data === 'string') {
            return encodeUTF8(data);
        }

        // If it's a number (assuming 32-bit integer)
        if (typeof data === 'number') {
            const arr = new Uint8Array(4);
            new DataView(arr.buffer).setInt32(0, data, true);
            return arr;
        }

        // If it's an array-like object
        if (Array.isArray(data) || ArrayBuffer.isView(data)) {
            return new Uint8Array(data);
        }

        // If it's an object, stringify it and then encode
        if (typeof data === 'object') {
            return encodeUTF8(JSON.stringify(data));
        }

        // If we can't handle the input, throw an error
        throw new Error('Unsupported data type');
    }

    class LV {
        constructor(value) {
            this.Value = new Uint8Array();
            this.Length = 0;
            this.setValue(value);
        }

        static unmarshalBinary(data) {
            if (!(data instanceof Uint8Array)) {
                if (!Array.isArray(data)) {
                    data = [data];
                }
                data = new Uint8Array(data);
            }
            let dataArray = new DataView(data.buffer);
            let l = dataArray.getInt32(0, false);
            let v = new Uint8Array(data.slice(4, 4 + l));
            return new LV(v);
        }

        static combine(lvs) {
            if (!Array.isArray(lvs)) {
                lvs = [lvs];
            }
            let totalLength = 0;
            let lvAsBytesArray = [];
            for (let i = 0; i < lvs.length; i++) {
                let t = lvs[i];
                let b = t.marshalBinary();
                lvAsBytesArray.push(b);
                totalLength = totalLength + b.length;
            }

            let r = new Uint8Array(totalLength);
            let o = 0;
            for (let i = 0; i < lvs.length; i++) {
                r.set(lvAsBytesArray[i], o);
                o = o + lvAsBytesArray[i].length;
            }
            return new LV(r);
        }

        setValue(value) {
            let t = toUint8Array(value);
            this.Value = new Uint8Array(t);
            this.Length = this.Value.length;
        }

        setValueAsString(valueAsString) {
            this.setValue(encodeUTF8(valueAsString));
        }

        getValueAsString() {
            return decodeUTF8(this.Value);
        }

        marshalBinary() {
            let bufferLength = 4 + this.Value.length;

            let buffer = new ArrayBuffer(bufferLength);
            let dataView = new DataView(buffer);

            // Write Length as int32 in BigEndian byte order
            dataView.setUint32(0, this.Length, false);

            // Create a new Uint8Array view for the buffer
            let thisAsBytes = new Uint8Array(buffer);

            // Copy Value into thisAsBytes
            thisAsBytes.set(this.Value, 4);

            return thisAsBytes;
        }

        expand() {
            let data = this.Value;
            let dataArray = new DataView(data.buffer);

            let r = [];
            let i = 0;
            let j = 0;
            while (i < this.Value.length) {
                let l = dataArray.getInt32(i, false);
                i = i + 4;
                j = i + l;
                let v = this.Value.subarray(i, j);
                let e = new LV(v);
                r.push(e);
                i = j;
            }
            return r;
        }
    }

    class DataBlock {
        constructor(data) {
            this.Time = new LV({});
            this.Nonce = new LV({});
            this.PreKey = new LV({});
            this.Data = new LV({});
            this.DataHash = new LV({});
            
            this.setTimeNow();
            this.generateNonce();
            if (data !== undefined) {
                this.setDataValue(data);
            }
        }

        static fromLV(aLV) {
            let lvs = aLV.expand();
            let db = new DataBlock();
            db.Time = lvs[0];
            db.Nonce = lvs[1];
            db.PreKey = lvs[2];
            db.Data = lvs[3];
            db.DataHash = lvs[4];
            return db;
        }

        setTimeNow() {
            let now = new Date();
            let currentTimeInUTC_ISOFormat = now.toISOString();
            this.Time.setValueAsString(currentTimeInUTC_ISOFormat);
        }

        generateNonce() {
            if (!nacl) {
                throw new Error("nacl library not available");
            }
            this.Nonce.setValue(nacl.randomBytes(32));
        }

        setDataValue(data) {
            this.Data.setValue(data);
            this.generateDataHash();
        }

        generateDataHash() {
            if (!nacl) {
                throw new Error("nacl library not available");
            }
            let dataAsBytes = this.Data.Value;
            let hash = nacl.hash(dataAsBytes);
            this.DataHash.setValue(hash);
        }

        checkDataHash() {
            if (!nacl) {
                throw new Error("nacl library not available");
            }
            let dataAsBytes = this.Data.Value;
            let dataHashAsBytes = this.DataHash.Value;
            let hash = nacl.hash(dataAsBytes);
            return compareByteArrays(hash, dataHashAsBytes);
        }

        asLV() {
            return LV.combine([this.Time, this.Nonce, this.PreKey, this.Data, this.DataHash]);
        }
    }

    class AES {
        static async encrypt(key, data) {
            try {
                // Use CryptoJS provided by Postman
                const keyWords = CryptoJS.lib.WordArray.create(key);
                const dataWords = CryptoJS.lib.WordArray.create(data);

                // Generate random IV using CryptoJS
                const ivWords = CryptoJS.lib.WordArray.random(16);
                
                // Convert IV to Uint8Array
                const iv = new Uint8Array(16);
                for (let i = 0; i < 16; i++) {
                    iv[i] = (ivWords.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                }

                // Encrypt using CBC mode
                const encrypted = CryptoJS.AES.encrypt(dataWords, keyWords, {
                    iv: ivWords,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });

                // Get ciphertext as WordArray
                const ciphertext = encrypted.ciphertext;

                // Combine IV and ciphertext into result array
                const resultArray = new Uint8Array(16 + ciphertext.sigBytes);

                // Set IV at start
                resultArray.set(iv, 0);

                // Convert ciphertext to Uint8Array and set after IV
                for (let i = 0; i < ciphertext.sigBytes; i++) {
                    resultArray[i + 16] = (ciphertext.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                }

                return resultArray;
            } catch (err) {
                console.log(err);
                throw err;
            }
        }

        static async decrypt(key, encrypted) {
            try {
                // Extract IV and data
                const iv = encrypted.slice(0, 16);
                const data = encrypted.slice(16);

                // Convert to WordArrays
                const keyWords = CryptoJS.lib.WordArray.create(key);
                const ivWords = CryptoJS.lib.WordArray.create(iv);
                const dataWords = CryptoJS.lib.WordArray.create(data);

                // Create cipher params
                const cipherParams = CryptoJS.lib.CipherParams.create({
                    ciphertext: dataWords,
                    iv: ivWords
                });

                // Decrypt
                const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWords, {
                    iv: ivWords,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });

                // Convert to Uint8Array
                const resultArray = new Uint8Array(decrypted.sigBytes);
                for (let i = 0; i < decrypted.sigBytes; i++) {
                    resultArray[i] = (decrypted.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                }

                return resultArray;
            } catch (err) {
                console.log(err);
                throw err;
            }
        }
    }

    async function packLVPayload(preKeyIndex, edSelfPrivateKey, encryptKey, arrayOfLvParams) {
        let lvPackedPayload = dxlib.LV.combine(arrayOfLvParams);
        let lvPackedPayloadAsBytes = lvPackedPayload.marshalBinary();

        let dataBlock = new dxlib.DataBlock(lvPackedPayloadAsBytes);
        dataBlock.PreKey.setValue(preKeyIndex);
        let lvDataBlock = dataBlock.asLV();
        let lvDataBlockAsBytes = lvDataBlock.marshalBinary();

        let encryptedLVDataBlockAsBytes = await dxlib.AES.encrypt(encryptKey, lvDataBlockAsBytes);
        let lvEncryptedLVDataBlockAsBytes = new dxlib.LV(encryptedLVDataBlockAsBytes);
        let signature = Ed25519.sign(encryptedLVDataBlockAsBytes, edSelfPrivateKey);
        let lvSignature = new dxlib.LV(signature);
        let lvDataBlockEnvelope = dxlib.LV.combine([lvEncryptedLVDataBlockAsBytes, lvSignature]);
        let lvDataBlockEnvelopeAsBytes = lvDataBlockEnvelope.marshalBinary();
        return bytesToHex(lvDataBlockEnvelopeAsBytes);
    }

    const UNPACK_TTL_MS = 5 * 60 * 1000;

    async function unpackLVPayload(preKeyIndex, peerPublicKey, decryptKey, dataAsHexString, skipVerify = false) {
        let dataAsBytes;
        let lvData;
        let lvDataElements;
        let decryptedData;
        let lvDecryptedLVDataBlock;
        let dataBlockPreKeyIndex;
        let lvPtrDataPayload;
        let lvCombinedPayloadAsBytes;
        let lvCombinedPayload;
        let valid;
        let dataBlock;

        dataAsBytes = hexToBytes(dataAsHexString);

        lvData = LV.unmarshalBinary(dataAsBytes);

        lvDataElements = lvData.expand();

        if (lvDataElements === null) {
            throw new Error('INVALID_DATA');
        }

        if (lvDataElements.length < 2) {
            throw new Error('INVALID_DATA');
        }

        let lvEncryptedData = lvDataElements[0];
        let lvSignature = lvDataElements[1];

        if (!skipVerify) {
            valid = Ed25519.verify(lvEncryptedData.Value, lvSignature.Value, peerPublicKey);
            if (!valid) {
                throw new Error('INVALID_SIGNATURE');
            }
        }

        decryptedData = await AES.decrypt(decryptKey, lvEncryptedData.Value);

        lvDecryptedLVDataBlock = LV.unmarshalBinary(decryptedData);

        dataBlock = DataBlock.fromLV(lvDecryptedLVDataBlock);

        let timeStamp = dataBlock.Time.getValueAsString();
        let parsedTimestamp = new Date(timeStamp);

        if (parsedTimestamp.toString() === 'Invalid Date') {
            throw new Error("INVALID_TIMESTAMP_DATA");
        }

        const differenceMS = new Date() - parsedTimestamp;
        if ((differenceMS - UNPACK_TTL_MS) > 0) {
            throw new Error("TIME_EXPIRED");
        }

        dataBlockPreKeyIndex = dataBlock.PreKey.getValueAsString();
        if (dataBlockPreKeyIndex !== preKeyIndex) {
            throw new Error('INVALID_PREKEY');
        }

        if (!dataBlock.checkDataHash()) {
            throw new Error('INVALID_DATA_HASH');
        }

        lvCombinedPayloadAsBytes = dataBlock.Data.Value;

        lvCombinedPayload = LV.unmarshalBinary(lvCombinedPayloadAsBytes);
        lvPtrDataPayload = lvCombinedPayload.expand();

        return lvPtrDataPayload;
    }

    function bytesToHex(bytes) {
        return Array.from(bytes, byte => {
            // Ensure byte is treated as a number
            let num = Number(byte);
            // Check if it's a valid number
            if (isNaN(num)) {
                throw new Error('Invalid byte value');
            }
            return num.toString(16).padStart(2, '0');
        }).join('');
    }

    function hexToBytes(hex) {
        if (hex.length % 2 !== 0) {
            throw new Error('Hex string must have an even length');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            let s = hex.substring(i, i + 2);
            bytes[i / 2] = parseInt(s, 16);
        }
        return bytes;
    }

    function compareByteArrays(arr1, arr2) {
        if (arr1.length !== arr2.length) {
            return false;
        }
        for (let i = 0; i < arr1.length; i++) {
            if (arr1[i] !== arr2[i]) {
                return false;
            }
        }
        return true;
    }

    // Assign all methods to the dxlib object
    dxlib.Ed25519 = Ed25519;
    dxlib.X25519 = X25519;
    dxlib.LV = LV;
    dxlib.DataBlock = DataBlock;
    dxlib.AES = AES;
    dxlib.packLVPayload = packLVPayload;
    dxlib.unpackLVPayload = unpackLVPayload;
    dxlib.bytesToHex = bytesToHex;
    dxlib.hexToBytes = hexToBytes;
    dxlib.encodeUTF8 = encodeUTF8;
    dxlib.decodeUTF8 = decodeUTF8;
    
    // Log to verify the library was loaded
    console.log("dxlib library loaded successfully");
    
})(dxlib);

// Store key functions in environment variables for persistence
pm.environment.set('dxlib_loaded', true);

