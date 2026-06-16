// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { CredentialResponse, Envelope, RegistrationResponse } from './messages.js';
import { checked_vector, joinAll, xor } from './util.js';
import { LABELS } from './common.js';
export class OpaqueCoreServer {
    constructor(config, oprf_seed) {
        this.config = config;
        this.oprf_seed = checked_vector(oprf_seed, config.hash.Nh);
    }
    async doOPRFEvaluation(blinded, credential_identifier) {
        const oprf_key_seed = await this.config.kdf.expand(this.oprf_seed, joinAll([credential_identifier, Uint8Array.from(LABELS.OprfKey)]), this.config.constants.Nseed);
        const oprf_key = await this.config.oprf.deriveOPRFKey(oprf_key_seed);
        return this.config.oprf.evaluate(oprf_key, blinded);
    }
    async createRegistrationResponse(request, server_public_key, credential_identifier) {
        const evaluation = await this.doOPRFEvaluation(request.data, credential_identifier);
        return new RegistrationResponse(this.config, evaluation, server_public_key);
    }
    async createCredentialResponse(request, record, server_public_key, credential_identifier) {
        const evaluation = await this.doOPRFEvaluation(request.data, credential_identifier);
        const masking_nonce = new Uint8Array(this.config.prng.random(this.config.constants.Nn));
        const Ne = Envelope.sizeSerialized(this.config);
        const credential_response_pad = await this.config.kdf.expand(record.masking_key, joinAll([masking_nonce, Uint8Array.from(LABELS.CredentialResponsePad)]), this.config.ake.Npk + Ne);
        const plaintext = joinAll([server_public_key, Uint8Array.from(record.envelope.serialize())]);
        const masked_response = xor(credential_response_pad, plaintext);
        return new CredentialResponse(this.config, evaluation, masking_nonce, masked_response);
    }
}
//# sourceMappingURL=core_server.js.map