// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { AKE3DH, OPRFBaseMode } from './common.js';
import { Hash, Hkdf, Hmac, Prng } from './thecrypto.js';
import { OprfID } from '@cloudflare/voprf-ts';
export var OpaqueID;
(function (OpaqueID) {
    OpaqueID[OpaqueID["OPAQUE_P256"] = 3] = "OPAQUE_P256";
    OpaqueID[OpaqueID["OPAQUE_P384"] = 4] = "OPAQUE_P384";
    OpaqueID[OpaqueID["OPAQUE_P521"] = 5] = "OPAQUE_P521";
})(OpaqueID || (OpaqueID = {}));
class OpaqueConfig {
    constructor(opaqueID) {
        this.opaqueID = opaqueID;
        let oprfID = 0;
        switch (opaqueID) {
            case OpaqueID.OPAQUE_P256:
                oprfID = OprfID.OPRF_P256_SHA256;
                break;
            case OpaqueID.OPAQUE_P384:
                oprfID = OprfID.OPRF_P384_SHA384;
                break;
            case OpaqueID.OPAQUE_P521:
                oprfID = OprfID.OPRF_P521_SHA512;
                break;
            default:
                throw new Error('invalid opaque id');
        }
        this.constants = { Nn: 32, Nseed: 32 };
        this.prng = new Prng();
        this.oprf = new OPRFBaseMode(oprfID);
        this.hash = new Hash(this.oprf.hash);
        this.mac = new Hmac(this.hash.name);
        this.kdf = new Hkdf(this.hash.name);
        this.ake = new AKE3DH(this.oprf.id);
    }
    toString() {
        return (`${OpaqueID[this.opaqueID]} = {` +
            `OPRF: ${this.oprf.name}, ` +
            `Hash: ${this.hash.name}}`);
    }
}
export function getOpaqueConfig(opaqueID) {
    return new OpaqueConfig(opaqueID);
}
//# sourceMappingURL=suites.js.map