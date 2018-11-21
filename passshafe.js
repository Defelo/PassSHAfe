const CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/!$%&()=?*'[]{}<>|-_.:,;#@";

function rot_r(a, n) {
    return ((a >>> n) | (a << (32 - n)));
}

function ch(x, y, z) {
    return z ^ (x & (y ^ z));
}

function maj(x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

function sigma0(x) {
    return rot_r(x, 2) ^ rot_r(x, 13) ^ rot_r(x, 22);
}

function sigma1(x) {
    return rot_r(x, 6) ^ rot_r(x, 11) ^ rot_r(x, 25);
}

function gamma0(x) {
    return rot_r(x, 7) ^ rot_r(x, 18) ^ (x >>> 3);
}

function gamma1(x) {
    return rot_r(x, 17) ^ rot_r(x, 19) ^ (x >>> 10);
}

const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function sha256(input) {
    let H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    let data = [];
    for (let i = 0; i < input.length; i++)
        data[i] = input[i];

    let bitLength = data.length * 8;
    let words = [];
    data[data.length] = 0x80;
    while (data.length % 64 - 56)
        data[data.length] = 0x00;
    for (let i = 0; i < data.length; i++) {
        let j = data[i];
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((bitLength / 2 ** 32) | 0);
    words[words.length] = bitLength;

    for (let j = 0; j < words.length;) {
        let w = words.slice(j, j += 16);
        let g = [];
        for (let i = 0; i < 8; i++)
            g[i] = H[i];
        for (let i = 0; i < 64; i++) {
            if (i >= 16) {
                w[i] = (gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) | 0;
            }
            let t1 = g[7] + sigma1(g[4]) + ch(g[4], g[5], g[6]) + K[i] + w[i];
            let t2 = (sigma0(g[0]) + maj(g[0], g[1], g[2]));
            g = [(t1 + t2) | 0, g[0], g[1], g[2], (g[3] + t1) | 0, g[4], g[5], g[6]];
        }
        for (let i = 0; i < 8; i++)
            H[i] = (H[i] + g[i]) | 0;
    }
    let result = [];
    for (let i = 0; i < 8; i++) {
        if (H[i] < 0)
            H[i] += 2 ** 32;
        for (let j = 3; j >= 0; j--) {
            result[i * 4 + j] = H[i] & 0xff;
            H[i] = H[i] >> 8;
        }
    }
    return result;
}

function stringToAscii(str) {
    let out = [];
    for (let i = 0; i < str.length; i++)
        out[i] = str.charCodeAt(i);
    return out;
}

function hmac(key, msg) {
    if (key.length > 64)
        key = sha256(key);
    while (key.length < 64)
        key[key.length] = 0;
    let opad = [];
    let ipad = [];
    for (let i = 0; i < key.length; i++) {
        opad[i] = key[i] ^ 0x5c;
        ipad[i] = key[i] ^ 0x36;
    }

    return sha256(opad.concat(sha256(ipad.concat(msg))));
}

function expmod(base, exp, mod) {
    if (exp === 0)
        return 1;
    if (exp % 2 === 0) {
        return Math.pow(expmod(base, (exp / 2), mod), 2) % mod;
    }
    else {
        return (base * expmod(base, (exp - 1), mod)) % mod;
    }
}

function generate_password(master_password, account_identifier, length) {
    master_password = stringToAscii(master_password);
    let digest = hmac(master_password.concat(length % 256), stringToAscii(account_identifier));
    let out = "";
    for (let i = 0; i < length; i++) {
        let num = 0;
        for (let j = 0; j < 32; j++)
            num += expmod(256, j, CHARSET.length) * digest[31 - j];
        digest = hmac(master_password.concat(i % 256), digest);
        out += CHARSET.charAt(num % CHARSET.length);
    }
    return out;
}
