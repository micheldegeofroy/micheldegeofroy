// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { Oprf } from './oprf.js';
import { SerializedElt, SerializedScalar } from './group.js';
export function getKeySizes(id) {
    const { gg } = Oprf.params(id);
    return { Nsk: gg.size, Npk: 1 + gg.size };
}
export function validatePrivateKey(id, privateKey) {
    try {
        const { gg } = Oprf.params(id), s = gg.deserializeScalar(new SerializedScalar(privateKey));
        return !s.equals(0);
    }
    catch (_) {
        return false;
    }
}
export function validatePublicKey(id, publicKey) {
    try {
        const { gg } = Oprf.params(id), P = gg.deserialize(new SerializedElt(publicKey));
        return !P.isIdentity;
    }
    catch (_) {
        return false;
    }
}
export async function randomPrivateKey(id) {
    const { gg } = Oprf.params(id), priv = await gg.randomScalar();
    return new Uint8Array(gg.serializeScalar(priv));
}
export async function derivePrivateKey(id, seed) {
    const { gg } = Oprf.params(id), priv = await gg.hashToScalar(seed, Oprf.getHashToScalarDST(id));
    return new Uint8Array(gg.serializeScalar(priv));
}
export function generatePublicKey(id, privateKey) {
    const { gg } = Oprf.params(id), priv = gg.deserializeScalar(new SerializedScalar(privateKey)), pub = gg.mulBase(priv);
    return new Uint8Array(gg.serialize(pub));
}
export async function generateKeyPair(id) {
    const privateKey = await randomPrivateKey(id), publicKey = generatePublicKey(id, privateKey);
    return { privateKey, publicKey };
}
export async function deriveKeyPair(id, seed) {
    const privateKey = await derivePrivateKey(id, seed), publicKey = generatePublicKey(id, privateKey);
    return { privateKey, publicKey };
}
//# sourceMappingURL=keys.js.map