// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { Group, GroupID, SerializedElt, SerializedScalar } from './group.js';
import { joinAll, to16bits } from './util.js';
export class Blind extends SerializedScalar {
    constructor() {
        super(...arguments);
        this._BlindBrand = '';
    }
}
export class Blinded extends SerializedElt {
    constructor() {
        super(...arguments);
        this._BlindedBrand = '';
    }
}
export class Evaluation extends SerializedElt {
    constructor() {
        super(...arguments);
        this._EvaluationBrand = '';
    }
}
export var OprfID;
(function (OprfID) {
    OprfID[OprfID["OPRF_P256_SHA256"] = 3] = "OPRF_P256_SHA256";
    OprfID[OprfID["OPRF_P384_SHA384"] = 4] = "OPRF_P384_SHA384";
    OprfID[OprfID["OPRF_P521_SHA512"] = 5] = "OPRF_P521_SHA512";
})(OprfID || (OprfID = {}));
export class Oprf {
    constructor(id) {
        this.params = Oprf.params(id);
    }
    static validateID(id) {
        switch (id) {
            case OprfID.OPRF_P256_SHA256:
            case OprfID.OPRF_P384_SHA384:
            case OprfID.OPRF_P521_SHA512:
                return true;
            default:
                throw new Error(`not supported ID: ${id}`);
        }
    }
    static params(id) {
        Oprf.validateID(id);
        let gid = GroupID.P256, hash = 'SHA-256';
        switch (id) {
            case OprfID.OPRF_P256_SHA256:
                break;
            case OprfID.OPRF_P384_SHA384:
                gid = GroupID.P384;
                hash = 'SHA-384';
                break;
            case OprfID.OPRF_P521_SHA512:
                gid = GroupID.P521;
                hash = 'SHA-512';
                break;
            default:
                throw new Error(`not supported ID: ${id}`);
        }
        const gg = new Group(gid);
        return {
            id,
            gg,
            hash,
            blindedSize: 1 + gg.size,
            evaluationSize: 1 + gg.size,
            blindSize: gg.size
        };
    }
    static getContextString(id) {
        Oprf.validateID(id);
        return joinAll([new TextEncoder().encode(Oprf.version), new Uint8Array([Oprf.mode, 0, id])]);
    }
    static getHashToGroupDST(id) {
        return joinAll([new TextEncoder().encode('HashToGroup-'), Oprf.getContextString(id)]);
    }
    static getHashToScalarDST(id) {
        return joinAll([new TextEncoder().encode('HashToScalar-'), Oprf.getContextString(id)]);
    }
    static getEvalContext(id, info) {
        return joinAll([
            new TextEncoder().encode('Context-'),
            Oprf.getContextString(id),
            to16bits(info.length),
            info
        ]);
    }
    async coreFinalize(input, info, unblindedElement) {
        const finalizeDST = joinAll([
            new TextEncoder().encode('Finalize-'),
            Oprf.getContextString(this.params.id)
        ]), hashInput = joinAll([
            to16bits(input.length),
            input,
            to16bits(info.length),
            info,
            to16bits(unblindedElement.length),
            unblindedElement,
            to16bits(finalizeDST.length),
            finalizeDST
        ]);
        return new Uint8Array(await crypto.subtle.digest(this.params.hash, hashInput));
    }
}
Oprf.mode = 0;
Oprf.version = 'VOPRF08-';
//# sourceMappingURL=oprf.js.map