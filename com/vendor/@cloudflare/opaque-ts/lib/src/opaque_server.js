// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { Serializable } from './messages.js';
import { AKE3DHServer } from './3dh_server.js';
import { OpaqueCoreServer } from './core_server.js';
export class OpaqueServer {
    constructor(config, oprf_seed, ake_keypair_export, server_identity) {
        this.config = config;
        Serializable.check_bytes_arrays([
            ake_keypair_export.public_key,
            ake_keypair_export.private_key
        ]);
        this.ake_keypair = {
            private_key: new Uint8Array(ake_keypair_export.private_key),
            public_key: new Uint8Array(ake_keypair_export.public_key)
        };
        Serializable.check_bytes_array(oprf_seed);
        this.server_identity = server_identity
            ? new TextEncoder().encode(server_identity)
            : this.ake_keypair.public_key;
        this.opaque_core = new OpaqueCoreServer(config, new Uint8Array(oprf_seed));
        this.ake = new AKE3DHServer(this.config);
    }
    registerInit(request, credential_identifier) {
        return this.opaque_core.createRegistrationResponse(request, this.ake_keypair.public_key, new TextEncoder().encode(credential_identifier));
    }
    async authInit(ke1, record, credential_identifier, client_identity, context) {
        const credential_identifier_u8array = new TextEncoder().encode(credential_identifier);
        const response = await this.opaque_core.createCredentialResponse(ke1.request, record, this.ake_keypair.public_key, credential_identifier_u8array);
        const te = new TextEncoder();
        // eslint-disable-next-line no-undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined;
        const context_u8array = context ? te.encode(context) : new Uint8Array(0);
        return this.ake.response(this.ake_keypair.private_key, this.server_identity, ke1, response, context_u8array, record.client_public_key, client_identity_u8array);
    }
    authFinish(ke3, expected) {
        return this.ake.finish(ke3.auth_finish, expected);
    }
}
//# sourceMappingURL=opaque_server.js.map