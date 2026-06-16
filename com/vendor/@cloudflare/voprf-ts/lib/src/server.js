// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { Blinded, Evaluation, Oprf } from './oprf.js';
import { Group, SerializedScalar } from './group.js';
import { ctEqual } from './util.js';
export class OPRFServer extends Oprf {
    constructor(id, privateKey) {
        super(id);
        this.supportsWebCryptoOPRF = false;
        this.privateKey = privateKey;
    }
    async evaluate(blindedElement, info) {
        const context = Oprf.getEvalContext(this.params.id, info), dst = Oprf.getHashToScalarDST(this.params.id), m = await this.params.gg.hashToScalar(context, dst), serSk = new SerializedScalar(this.privateKey), sk = this.params.gg.deserializeScalar(serSk), t = this.params.gg.addScalar(sk, m), tInv = this.params.gg.invScalar(t);
        if (this.supportsWebCryptoOPRF) {
            const serTInv = this.params.gg.serializeScalar(tInv);
            return this.evaluateWebCrypto(blindedElement, serTInv);
        }
        return Promise.resolve(this.evaluateSJCL(blindedElement, tInv));
    }
    async evaluateWebCrypto(blindedElement, secret) {
        const key = await crypto.subtle.importKey('raw', secret, {
            name: 'OPRF',
            namedCurve: this.params.gg.id
        }, true, ['sign']);
        // webcrypto accepts only compressed points.
        let compressed = Uint8Array.from(blindedElement);
        if (blindedElement[0] === 0x04) {
            const P = this.params.gg.deserialize(blindedElement);
            compressed = Uint8Array.from(this.params.gg.serialize(P, true));
        }
        const evaluation = await crypto.subtle.sign('OPRF', key, compressed);
        return new Evaluation(evaluation);
    }
    evaluateSJCL(blindedElement, secret) {
        const P = this.params.gg.deserialize(blindedElement), Z = Group.mul(secret, P);
        return new Evaluation(this.params.gg.serialize(Z));
    }
    async fullEvaluate(input, info) {
        const dst = Oprf.getHashToGroupDST(this.params.id), T = await this.params.gg.hashToGroup(input, dst), issuedElement = new Blinded(this.params.gg.serialize(T)), evaluation = await this.evaluate(issuedElement, info), digest = await this.coreFinalize(input, info, evaluation);
        return digest;
    }
    async verifyFinalize(input, output, info) {
        const digest = await this.fullEvaluate(input, info);
        return ctEqual(output, digest);
    }
}
//# sourceMappingURL=server.js.map