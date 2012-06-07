/* A JavaScript implementation of the SHA family of hashes, as defined in FIPS
 * PUB 180-2 as well as the corresponding HMAC implementation as defined in
 * FIPS PUB 198a
 *
 * Version 1.3 Copyright Brian Turek 2008-2010
 * Distributed under the BSD License
 * See http://jssha.sourceforge.net/ for more information
 *
 * Several functions taken from Paul Johnson
 */

let charSize = 8, b64pad = "", hexCase = 0,

str2binb = function (a) {
    let b = [], mask = (1 << charSize) - 1, length = a.length * charSize, i;
    for (i = 0; i < length; i += charSize) {
        b[i >> 5] |= (a.charCodeAt(i / charSize) & mask) << (32 - charSize - (i % 32))
    }
    return b
},

hex2binb = function (a) {
    let b = [], length = a.length, i, num;
    for (i = 0; i < length; i += 2) {
        num = parseInt(a.substr(i, 2), 16);
        if (!isNaN(num)) {
            b[i >> 3] |= num << (24 - (4 * (i % 8)))
        } else {
            return "INVALID HEX STRING"
        }
    }
    return b
}, 
binb2hex = function (a) {
    let b = (hexCase) ? "0123456789ABCDEF" : "0123456789abcdef", str = "", length = a.length * 4, i, srcByte;
    for (i = 0; i < length; i += 1) {
        srcByte = a[i >> 2] >> ((3 - (i % 4)) * 8);
        str += b.charAt((srcByte >> 4) & 0xF) + b.charAt(srcByte & 0xF)
    }
    return str
},

binb2b64 = function (a) {
    let b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789+/", str = "", length = a.length * 4, i, j, triplet;
    for (i = 0; i < length; i += 3) {
        triplet = (((a[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16) | (((a[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) | ((a[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
        for (j = 0; j < 4; j += 1) {
            if (i * 8 + j * 6 <= a.length * 32) {
                str += b.charAt((triplet >> 6 * (3 - j)) & 0x3F)
            } else {
                str += b64pad
            }
        }
    }
    return str
},

rotl = function (x, n) {
    return (x << n) | (x >>> (32 - n))
},

parity = function (x, y, z) {
    return x ^ y ^ z
},

ch = function (x, y, z) {
    return (x & y) ^ (~x & z)
},

maj = function (x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z)
},

safeAdd_2 = function (x, y) {
    let a = (x & 0xFFFF) + (y & 0xFFFF), msw = (x >>> 16) + (y >>> 16) + (a >>> 16);
    return ((msw & 0xFFFF) << 16) | (a & 0xFFFF)
},

safeAdd_5 = function (a, b, c, d, e) {
    let f = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) + (e & 0xFFFF), msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (f >>> 16);
    return ((msw & 0xFFFF) << 16) | (f & 0xFFFF)
},

coreSHA1 = function (f, g) {
    let W = [], a, b, c, d, e, T, i, t, appendedMessageLength,
	H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
	K = [0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6];
    f[g >> 5] |= 0x80 << (24 - (g % 32));
    f[(((g + 65) >> 9) << 4) + 15] = g;
    appendedMessageLength = f.length;
    for (i = 0; i < appendedMessageLength; i += 16) {
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        for (t = 0; t < 80; t += 1) {
            if (t < 16) {
                W[t] = f[t + i]
            } else {
                W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1)
            }
            if (t < 20) {
                T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, K[t], W[t])
            } else if (t < 40) {
                T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t])
            } else if (t < 60) {
                T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, K[t], W[t])
            } else {
                T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t])
            }
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = T
        }
        H[0] = safeAdd_2(a, H[0]);
        H[1] = safeAdd_2(b, H[1]);
        H[2] = safeAdd_2(c, H[2]);
        H[3] = safeAdd_2(d, H[3]);
        H[4] = safeAdd_2(e, H[4])
    }
    return H
},

jsSHA = function (a, b) {
    this.sha1 = null;
    this.strBinLen = null;
    this.strToHash = null;
    if ("HEX" === b) {
        if (0 !== (a.length % 2)) {
            return "TEXT MUST BE IN BYTE INCREMENTS"
        }
        this.strBinLen = a.length * 4;
        this.strToHash = hex2binb(a)
    } else if (("ASCII" === b) || ('undefined' === typeof (b))) {
        this.strBinLen = a.length * charSize;
        this.strToHash = str2binb(a)
    } else {
        return "UNKNOWN TEXT INPUT TYPE"
    }
};

jsSHA.prototype = {
    getHash: function (a) {
        let b = null, message = this.strToHash.slice();
        switch (a) {
        case "HEX":
            b = binb2hex;
            break;
        case "B64":
            b = binb2b64;
            break;
        default:
            return "FORMAT NOT RECOGNIZED"
        }
        if (null === this.sha1) {
            this.sha1 = coreSHA1(message, this.strBinLen)
        }
        return b(this.sha1)
    },
    getHMAC: function (a, b, c) {
        let d, keyToUse, i, retVal, keyBinLen, keyWithIPad = [], keyWithOPad = [];
        switch (c) {
        case "HEX":
            d = binb2hex;
            break;
        case "B64":
            d = binb2b64;
            break;
        default:
            return "FORMAT NOT RECOGNIZED"
        }
        if ("HEX" === b) {
            if (0 !== (a.length % 2)) {
                return "KEY MUST BE IN BYTE INCREMENTS"
            }
            keyToUse = hex2binb(a);
            keyBinLen = a.length * 4
        } else if ("ASCII" === b) {
            keyToUse = str2binb(a);
            keyBinLen = a.length * charSize
        } else {
            return "UNKNOWN KEY INPUT TYPE"
        }
        if (64 < (keyBinLen / 8)) {
            keyToUse = coreSHA1(keyToUse, keyBinLen);
            keyToUse[15] &= 0xFFFFFF00
        } else if (64 > (keyBinLen / 8)) {
            keyToUse[15] &= 0xFFFFFF00
        }
        for (i = 0; i <= 15; i += 1) {
            keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
            keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C
        }
        retVal = coreSHA1(keyWithIPad.concat(this.strToHash), 512 + this.strBinLen);
        retVal = coreSHA1(keyWithOPad.concat(retVal), 672);
        return (d(retVal))
    }
};

// Mock/stub code
//jsSHA = function (srcString, inputFormat) { /* ignore input */ }
//jsSHA.prototype = {
//    getHMAC : function (key, inputFormat, variant, outputFormat) { return "JUSTATEST"; }
//}

// http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/

function dec2hex(s) {
    return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
}

function hex2dec(s) {
    return parseInt(s, 16);
}

function base32tohex(base32) {
    let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let hex = "";

    for (let i = 0; i < base32.length; i++) {
        let val = base32chars.indexOf(base32.charAt(i).toUpperCase());
        bits += leftpad(val.toString(2), 5, '0');
    }

    // leftpad bits with 0 until length is a multiple of 4
    while (bits.length % 4 != 0) {
        bits = "0" + bits;
    }

    for (let i = bits.length - 4; i >= 0; i = i - 4) {
        let chunk = bits.substr(i, 4);
        hex = parseInt(chunk, 2).toString(16) + hex;
    }
    return hex;
}

function leftpad(str, len, pad) {
    if (len + 1 >= str.length) {
        str = Array(len + 1 - str.length).join(pad) + str;
    }
    return str;
}

function updateOtp(secret) {            
    let key = base32tohex(secret);
    let now = new Date();
    let epoch = Math.round(now.getTime() / 1000.0);
    let time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0');

    let hmacObj = new jsSHA(time, "HEX");
    let hmac = hmacObj.getHMAC(key, "HEX", "HEX");			// Only using the sha1 part of the jsSHA library
    //let hmac = hmacObj.getHMAC(key, "HEX", "SHA-1", "HEX");		// When using the full jsSHA library

    //qrImg = https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=otpauth://totp/' + account + '3Fsecret%3D' + secret;
    //var keyLength = (key.length * 4);

    let offset = hex2dec(hmac.substring(hmac.length - 1));
    // For debug purpose
    //var part1 = hmac.substr(0, offset * 2);
    //var part2 = hmac.substr(offset * 2, 8);
    //var part3 = hmac.substr(offset * 2 + 8, hmac.length - offset);

    let otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + '';
    return "" + (otp).substr(otp.length - 6, 6);
}
