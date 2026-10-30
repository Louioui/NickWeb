// A software passkey for tests: does what a phone or security key does (makes a P-256 key pair, signs challenges), so
// the real server code can be checked end to end without a browser. Every field can be bent to test a bad answer.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha = (data) => createHash('sha256').update(data).digest();
const FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_AT = 0x40;

function clientData(type, challenge, origin) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

export function createAuthenticator({ rpId, origin }) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credId = randomBytes(32);
    // COSE key, as a CBOR map with integer keys: kty EC2, alg ES256, crv P-256, x, y.
    const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    let counter = 0;

    const authData = (rp, flags, count, extra = Buffer.alloc(0)) => {
        const c = Buffer.alloc(4); c.writeUInt32BE(count >>> 0);
        return Buffer.concat([sha(rp), Buffer.from([flags]), c, extra]);
    };

    return {
        id: b64u(credId),
        get counter() { return counter; },
        set counter(v) { counter = v; },
        // Answers navigator.credentials.create().
        register(options, { origin: o = origin, rpId: r = rpId, uv = true, challenge = options.challenge } = {}) {
            const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
            const attested = Buffer.concat([Buffer.alloc(16), len, credId, Buffer.from(cose)]);
            const data = authData(r, FLAG_UP | (uv ? FLAG_UV : 0) | FLAG_AT, counter, attested);
            const attestationObject = isoCBOR.encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', data]]));
            return {
                id: b64u(credId), rawId: b64u(credId), type: 'public-key', clientExtensionResults: {},
                response: { clientDataJSON: b64u(clientData('webauthn.create', challenge, o)), attestationObject: b64u(attestationObject), transports: ['internal'] },
            };
        },
        // Answers navigator.credentials.get(). Each answer moves the counter forward unless `count` says otherwise.
        login(options, { origin: o = origin, rpId: r = rpId, uv = true, challenge = options.challenge, count, badSignature = false } = {}) {
            const use = count ?? (counter > 0 ? ++counter : 0);
            const data = authData(r, FLAG_UP | (uv ? FLAG_UV : 0), use);
            const cdj = clientData('webauthn.get', challenge, o);
            let signature = sign('sha256', Buffer.concat([data, sha(cdj)]), privateKey);
            if (badSignature) signature = Buffer.from(signature.map((v, i) => (i === signature.length - 1 ? v ^ 1 : v)));
            return {
                id: b64u(credId), rawId: b64u(credId), type: 'public-key', clientExtensionResults: {},
                response: { clientDataJSON: b64u(cdj), authenticatorData: b64u(data), signature: b64u(signature) },
            };
        },
    };
}
