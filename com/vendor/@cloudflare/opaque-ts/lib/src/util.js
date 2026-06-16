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
export function encode_number(n, bits) {
    if (!(bits > 0 && bits <= 32)) {
        throw new Error('only supports 32-bit encoding');
    }
    const max = 1 << bits;
    if (!(n >= 0 && n < max)) {
        throw new Error(`number out of range [0,2^${bits}-1]`);
    }
    const numBytes = Math.ceil(bits / 8);
    const out = new Uint8Array(numBytes);
    for (let i = 0; i < numBytes; i++) {
        out[(numBytes - 1 - i)] = (n >> (8 * i)) & 0xff;
    }
    return out;
}
function decode_number(a, bits) {
    if (!(bits > 0 && bits <= 32)) {
        throw new Error('only supports 32-bit encoding');
    }
    const numBytes = Math.ceil(bits / 8);
    if (a.length !== numBytes) {
        throw new Error('array has wrong size');
    }
    let out = 0;
    for (let i = 0; i < a.length; i++) {
        out <<= 8;
        out += a[i];
    }
    return out;
}
function encode_vector(a, bits_header) {
    return joinAll([encode_number(a.length, bits_header), a]);
}
function decode_vector(a, bits_header) {
    if (a.length === 0) {
        throw new Error('empty vector not allowed');
    }
    const numBytes = Math.ceil(bits_header / 8);
    const header = a.subarray(0, numBytes);
    const len = decode_number(header, bits_header);
    const consumed = numBytes + len;
    const payload = a.slice(numBytes, consumed);
    return { payload, consumed };
}
export function encode_vector_8(a) {
    return encode_vector(a, 8);
}
export function encode_vector_16(a) {
    return encode_vector(a, 16);
}
export function decode_vector_16(a) {
    return decode_vector(a, 16);
}
export function checked_vector(a, n, str = 'array') {
    if (a.length < n) {
        throw new Error(`${str} has wrong length`);
    }
    return a.slice(0, n);
}
export function checked_vector_array(a, n, str = 'array') {
    return checked_vector(Uint8Array.from(a), n, str);
}
export function xor(a, b) {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length');
    }
    const n = a.length;
    const c = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        c[i] = a[i] ^ b[i];
    }
    return c;
}
export function ctEqual(a, b) {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length');
    }
    const n = a.length;
    let c = 0;
    for (let i = 0; i < n; i++) {
        c |= a[i] ^ b[i];
    }
    return c === 0;
}
//# sourceMappingURL=util.js.map