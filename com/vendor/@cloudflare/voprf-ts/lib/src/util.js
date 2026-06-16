// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
export function joinAll(a) {
    let size = 0;
    for (let i = 0; i < a.length; i++) {
        size += a[i].length;
    }
    const ret = new Uint8Array(new ArrayBuffer(size));
    for (let i = 0, offset = 0; i < a.length; i++) {
        ret.set(a[i], offset);
        offset += a[i].length;
    }
    return ret;
}
export function xor(a, b) {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length');
    }
    const n = a.length, c = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        c[i] = a[i] ^ b[i];
    }
    return c;
}
export function ctEqual(a, b) {
    if (a.length !== b.length || a.length === 0) {
        return false;
    }
    const n = a.length;
    let c = 0;
    for (let i = 0; i < n; i++) {
        c |= a[i] ^ b[i];
    }
    return c === 0;
}
export function to16bits(n) {
    if (!(n >= 0 && n < 0xffff)) {
        throw new Error('number bigger than 2^16');
    }
    return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}
export function hashParams(hash) {
    switch (hash) {
        case 'SHA-1':
            return { outLenBytes: 20, blockLenBytes: 64 };
        case 'SHA-256':
            return { outLenBytes: 32, blockLenBytes: 64 };
        case 'SHA-384':
            return { outLenBytes: 48, blockLenBytes: 128 };
        case 'SHA-512':
            return { outLenBytes: 64, blockLenBytes: 128 };
        default:
            throw new Error(`invalid hash name: ${hash}`);
    }
}
//# sourceMappingURL=util.js.map