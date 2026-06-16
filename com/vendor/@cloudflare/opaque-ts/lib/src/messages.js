// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
import { checked_vector, decode_vector_16, encode_vector_16, joinAll } from './util.js';
export class Serializable {
    static check_string(a) {
        if (typeof a === 'string') {
            return true;
        }
        throw new Error('string expected');
    }
    static check_uint8array(a) {
        if (a instanceof Uint8Array) {
            return true;
        }
        throw new Error('Uint8Array expected');
    }
    static check_uint8arrays(as) {
        return as.every(this.check_uint8array);
    }
    static check_bytes_array(a) {
        if (!Array.isArray(a) ||
            !a.every((element) => Number.isInteger(element) && element >= 0 && element <= 255)) {
            throw new Error('Array of byte-sized integers expected');
        }
        return true;
    }
    static check_bytes_arrays(as) {
        return as.every(this.check_bytes_array);
    }
    static sizeSerialized(_) {
        throw new Error('child class must implement');
    }
    static checked_bytes_to_uint8array(cfg, bytes) {
        this.check_bytes_array(bytes);
        const u8array = Uint8Array.from(bytes);
        this.checked_object(cfg, u8array);
        return u8array;
    }
    static checked_object(cfg, u8array) {
        checked_vector(u8array, this.sizeSerialized(cfg), this.name);
    }
}
export class Envelope extends Serializable {
    constructor(cfg, nonce, auth_tag) {
        super();
        this.nonce = checked_vector(nonce, cfg.constants.Nn);
        this.auth_tag = checked_vector(auth_tag, cfg.mac.Nm);
    }
    serialize() {
        return Array.from(joinAll([this.nonce, this.auth_tag]));
    }
    static sizeSerialized(cfg) {
        return cfg.constants.Nn + cfg.mac.Nm;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.constants.Nn;
        const nonce = u8array.slice(start, end);
        start = end;
        end += cfg.mac.Nm;
        const auth_tag = u8array.slice(start, end);
        return new Envelope(cfg, nonce, auth_tag);
    }
}
export class RegistrationRequest extends Serializable {
    constructor(cfg, data) {
        Serializable.check_uint8array(data);
        super();
        this.data = checked_vector(data, cfg.oprf.Noe);
    }
    serialize() {
        return Array.from(this.data);
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = cfg.oprf.Noe;
        const data = u8array.slice(start, end);
        return new RegistrationRequest(cfg, data);
    }
}
export class RegistrationResponse extends Serializable {
    constructor(cfg, data, server_public_key) {
        Serializable.check_uint8arrays([data, server_public_key]);
        super();
        this.evaluation = checked_vector(data, cfg.oprf.Noe);
        this.server_public_key = checked_vector(server_public_key, cfg.ake.Npk);
    }
    serialize() {
        return Array.from(joinAll([this.evaluation, this.server_public_key]));
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe + cfg.ake.Npk;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.oprf.Noe;
        const evaluation = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk;
        const server_public_key = u8array.slice(start, end);
        return new RegistrationResponse(cfg, evaluation, server_public_key);
    }
}
export class RegistrationRecord extends Serializable {
    constructor(cfg, client_public_key, masking_key, envelope) {
        Serializable.check_uint8arrays([client_public_key, masking_key]);
        super();
        this.client_public_key = checked_vector(client_public_key, cfg.ake.Npk);
        this.masking_key = checked_vector(masking_key, cfg.hash.Nh);
        this.envelope = envelope;
    }
    serialize() {
        return Array.from(joinAll([
            this.client_public_key,
            this.masking_key,
            Uint8Array.from(this.envelope.serialize())
        ]));
    }
    static sizeSerialized(cfg) {
        return cfg.ake.Npk + cfg.hash.Nh + Envelope.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.ake.Npk;
        const client_public_key = u8array.slice(start, end);
        start = end;
        end += cfg.hash.Nh;
        const masking_key = u8array.slice(start, end);
        start = end;
        end += Envelope.sizeSerialized(cfg);
        const envelope_bytes = u8array.slice(start, end);
        const envelope = Envelope.deserialize(cfg, Array.from(envelope_bytes));
        return new RegistrationRecord(cfg, client_public_key, masking_key, envelope);
    }
    static async createFake(cfg) {
        const seed = cfg.prng.random(cfg.constants.Nseed);
        const { public_key: client_public_key } = await cfg.ake.deriveAuthKeyPair(new Uint8Array(seed));
        const masking_key = new Uint8Array(cfg.prng.random(cfg.hash.Nh));
        const envelope = Envelope.deserialize(cfg, new Array(Envelope.sizeSerialized(cfg)).fill(0));
        return new RegistrationRecord(cfg, client_public_key, masking_key, envelope);
    }
}
export class CredentialRequest extends Serializable {
    constructor(cfg, data) {
        Serializable.check_uint8array(data);
        super();
        this.data = checked_vector(data, cfg.oprf.Noe);
    }
    serialize() {
        return Array.from(this.data);
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = cfg.oprf.Noe;
        const data = u8array.slice(start, end);
        return new CredentialRequest(cfg, data);
    }
}
export class CredentialResponse extends Serializable {
    constructor(cfg, evaluation, masking_nonce, masked_response) {
        Serializable.check_uint8arrays([masking_nonce, masked_response]);
        super();
        this.evaluation = evaluation;
        this.masking_nonce = checked_vector(masking_nonce, cfg.constants.Nn);
        this.masked_response = checked_vector(masked_response, cfg.ake.Npk + Envelope.sizeSerialized(cfg));
    }
    serialize() {
        return Array.from(joinAll([this.evaluation, this.masking_nonce, this.masked_response]));
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe + cfg.constants.Nn + cfg.ake.Npk + Envelope.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.oprf.Noe;
        const evaluation_bytes = u8array.slice(start, end);
        const evaluation = checked_vector(evaluation_bytes, cfg.oprf.Noe);
        start = end;
        end += cfg.constants.Nn;
        const masking_nonce = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk + Envelope.sizeSerialized(cfg);
        const masked_response = u8array.slice(start, end);
        return new CredentialResponse(cfg, evaluation, masking_nonce, masked_response);
    }
}
export class CredentialFile extends Serializable {
    constructor(credential_identifier, record, client_identity) {
        if (!(Serializable.check_string(credential_identifier) &&
            (client_identity ? Serializable.check_string(client_identity) : true))) {
            throw new Error('expected string inputs');
        }
        super();
        this.credential_identifier = credential_identifier;
        this.record = record;
        this.client_identity = client_identity;
    }
    serialize() {
        const te = new TextEncoder();
        return Array.from(joinAll([
            encode_vector_16(te.encode(this.credential_identifier)),
            Uint8Array.from(this.record.serialize()),
            encode_vector_16(te.encode(this.client_identity))
        ]));
    }
    static sizeSerialized(cfg) {
        // This is the minimum size of a valid CredentialFile.
        return (2 + // Size of header for credential_identifier.
            RegistrationRecord.sizeSerialized(cfg) +
            2 // Size of header for client_identity.
        );
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const td = new TextDecoder();
        const res = decode_vector_16(u8array);
        const credential_identifier = td.decode(res.payload);
        let start = 0;
        let end = res.consumed;
        start = end;
        end += RegistrationRecord.sizeSerialized(cfg);
        const record = RegistrationRecord.deserialize(cfg, Array.from(u8array.slice(start, end)));
        start = end;
        const { payload } = decode_vector_16(u8array.slice(start));
        const client_identity = payload.length === 0 ? undefined : td.decode(payload); // eslint-disable-line no-undefined
        return new CredentialFile(credential_identifier, record, client_identity);
    }
}
export class AuthInit extends Serializable {
    constructor(cfg, client_nonce, client_keyshare) {
        Serializable.check_uint8arrays([client_nonce, client_keyshare]);
        super();
        this.client_nonce = checked_vector(client_nonce, cfg.constants.Nn);
        this.client_keyshare = checked_vector(client_keyshare, cfg.ake.Npk);
    }
    serialize() {
        return Array.from(joinAll([this.client_nonce, this.client_keyshare]));
    }
    static sizeSerialized(cfg) {
        return cfg.constants.Nn + cfg.ake.Npk;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.constants.Nn;
        const client_nonce = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk;
        const client_keyshare = u8array.slice(start, end);
        return new AuthInit(cfg, client_nonce, client_keyshare);
    }
}
export class AuthResponse extends Serializable {
    constructor(cfg, server_nonce, server_keyshare, server_mac) {
        Serializable.check_uint8arrays([server_nonce, server_keyshare, server_mac]);
        super();
        this.server_nonce = checked_vector(server_nonce, cfg.constants.Nn);
        this.server_keyshare = checked_vector(server_keyshare, cfg.ake.Npk);
        this.server_mac = checked_vector(server_mac, cfg.mac.Nm);
    }
    serialize() {
        return Array.from(joinAll([this.server_nonce, this.server_keyshare, this.server_mac]));
    }
    static sizeSerialized(cfg) {
        return cfg.constants.Nn + cfg.ake.Npk + cfg.mac.Nm;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.constants.Nn;
        const server_nonce = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk;
        const server_keyshare = u8array.slice(start, end);
        start = end;
        end += cfg.mac.Nm;
        const server_mac = u8array.slice(start, end);
        return new AuthResponse(cfg, server_nonce, server_keyshare, server_mac);
    }
}
export class AuthFinish extends Serializable {
    constructor(cfg, client_mac) {
        Serializable.check_uint8array(client_mac);
        super();
        this.client_mac = checked_vector(client_mac, cfg.mac.Nm);
    }
    serialize() {
        return Array.from(this.client_mac.slice());
    }
    static sizeSerialized(cfg) {
        return cfg.mac.Nm;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = cfg.mac.Nm;
        const client_mac = u8array.slice(start, end);
        return new AuthFinish(cfg, client_mac);
    }
}
export class ExpectedAuthResult extends Serializable {
    constructor(cfg, expected_client_mac, session_key) {
        Serializable.check_uint8arrays([expected_client_mac, session_key]);
        super();
        this.expected_client_mac = checked_vector(expected_client_mac, cfg.mac.Nm);
        this.session_key = checked_vector(session_key, cfg.kdf.Nx);
    }
    serialize() {
        return Array.from(joinAll([this.expected_client_mac, this.session_key]));
    }
    static sizeSerialized(cfg) {
        return cfg.mac.Nm + cfg.kdf.Nx;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.mac.Nm;
        const expected_client_mac = u8array.slice(start, end);
        start = end;
        end += cfg.kdf.Nx;
        const session_key = u8array.slice(start, end);
        return new ExpectedAuthResult(cfg, expected_client_mac, session_key);
    }
}
export class KE1 extends Serializable {
    constructor(request, auth_init) {
        super();
        this.request = request;
        this.auth_init = auth_init;
    }
    serialize() {
        return [...this.request.serialize(), ...this.auth_init.serialize()];
    }
    static sizeSerialized(cfg) {
        return CredentialRequest.sizeSerialized(cfg) + AuthInit.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = CredentialRequest.sizeSerialized(cfg);
        const request = CredentialRequest.deserialize(cfg, bytes.slice(start, end));
        start = end;
        end += AuthInit.sizeSerialized(cfg);
        const auth_init = AuthInit.deserialize(cfg, bytes.slice(start, end));
        return new KE1(request, auth_init);
    }
}
export class KE2 extends Serializable {
    constructor(response, auth_response) {
        super();
        this.response = response;
        this.auth_response = auth_response;
    }
    serialize() {
        return [...this.response.serialize(), ...this.auth_response.serialize()];
    }
    static sizeSerialized(cfg) {
        return CredentialResponse.sizeSerialized(cfg) + AuthResponse.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = CredentialResponse.sizeSerialized(cfg);
        const response = CredentialResponse.deserialize(cfg, bytes.slice(start, end));
        start = end;
        end += AuthResponse.sizeSerialized(cfg);
        const auth_response = AuthResponse.deserialize(cfg, bytes.slice(start, end));
        return new KE2(response, auth_response);
    }
}
export class KE3 extends Serializable {
    constructor(auth_finish) {
        super();
        this.auth_finish = auth_finish;
    }
    serialize() {
        return this.auth_finish.serialize();
    }
    static sizeSerialized(cfg) {
        return AuthFinish.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = Number(AuthFinish.sizeSerialized(cfg));
        const auth_finish = AuthFinish.deserialize(cfg, bytes.slice(start, end));
        return new KE3(auth_finish);
    }
}
//# sourceMappingURL=messages.js.map