// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { ctEqual, joinAll } from './util.js';
import { scrypt } from '@noble/hashes/lib/scrypt';
export class Prng {
    /* eslint-disable-next-line class-methods-use-this */
    random(numBytes) {
        return Array.from(crypto.getRandomValues(new Uint8Array(numBytes)));
    }
}
export class Hash {
    constructor(name) {
        this.name = name;
        switch (name) {
            case Hash.ID.SHA1:
                this.Nh = 20;
                break;
            case Hash.ID.SHA256:
                this.Nh = 32;
                break;
            case Hash.ID.SHA384:
                this.Nh = 48;
                break;
            case Hash.ID.SHA512:
                this.Nh = 64;
                break;
            default:
                throw new Error(`invalid hash name: ${name}`);
        }
    }
    async sum(msg) {
        return new Uint8Array(await crypto.subtle.digest(this.name, msg));
    }
}
/* eslint-disable-next-line @typescript-eslint/no-namespace */
(function (Hash) {
    Hash.ID = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA384: 'SHA-384',
        SHA512: 'SHA-512'
    };
})(Hash || (Hash = {}));
export class Hmac {
    constructor(hash) {
        this.hash = hash;
        this.Nm = new Hash(hash).Nh;
    }
    async with_key(key) {
        return new Hmac.Macops(await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: this.hash }, false, [
            'sign'
        ]));
    }
}
Hmac.Macops = class {
    constructor(crypto_key) {
        this.crypto_key = crypto_key;
    }
    async sign(msg) {
        return new Uint8Array(await crypto.subtle.sign(this.crypto_key.algorithm.name, this.crypto_key, msg));
    }
    async verify(msg, output) {
        return ctEqual(output, await this.sign(msg));
    }
};
export class Hkdf {
    constructor(hash) {
        this.hash = hash;
        this.Nx = new Hmac(hash).Nm;
    }
    async extract(salt, ikm) {
        return (await new Hmac(this.hash).with_key(salt)).sign(ikm);
    }
    async expand(prk, info, lenBytes) {
        const hashLen = new Hash(this.hash).Nh;
        const N = Math.ceil(lenBytes / hashLen);
        const T = new Uint8Array(N * hashLen);
        const hm = await new Hmac(this.hash).with_key(prk);
        let Ti = new Uint8Array();
        let offset = 0;
        for (let i = 0; i < N; i++) {
            Ti = await hm.sign(joinAll([Ti, info, Uint8Array.of(i + 1)])); // eslint-disable-line no-await-in-loop
            T.set(Ti, offset);
            offset += hashLen;
        }
        return T.slice(0, lenBytes);
    }
}
export const IdentityMemHardFn = { name: 'Identity', harden: (x) => x };
export const ScryptMemHardFn = {
    name: 'scrypt',
    harden: (msg) => scrypt(msg, new Uint8Array(), { N: 32768, r: 8, p: 1 })
};
//# sourceMappingURL=thecrypto.js.map