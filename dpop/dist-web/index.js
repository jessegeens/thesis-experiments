function encode(input) {
    const base64string = btoa(String.fromCharCode.apply(0, input));
    return base64string.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decode(input) {
    input = input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    return new Uint8Array(Array.prototype.map.call(atob(input), (c) => c.charCodeAt(0)));
}

const rsa = (rest) => ({
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    ...rest,
});
const ps = (hash) => rsa({ name: "RSA-PSS", hash: { name: `SHA-${hash}` }, saltLength: hash / 8 });
const rs = (hash) => rsa({ name: "RSASSA-PKCS1-v1_5", hash: { name: `SHA-${hash}` } });
const es = (hash, namedCurve) => ({
    name: "ECDSA",
    namedCurve,
    hash: { name: `SHA-${hash}` },
});
const algs = {
    PS256: ps(256),
    PS384: ps(384),
    PS512: ps(512),
    RS256: rs(256),
    RS384: rs(384),
    RS512: rs(512),
    ES256: es(256, "P-256"),
    ES384: es(384, "P-384"),
    ES512: es(512, "P-521"),
};
var subtleAlg = (alg) => {
    if (!(alg in algs)) {
        throw new TypeError("unrecognized or unsupported JWS algorithm");
    }
    return algs[alg];
};

const utf8ToUint8Array = (str) => decode(btoa(unescape(encodeURIComponent(str))));
async function JWT(privateKey, header, payload) {
    const p = JSON.stringify(payload);
    const h = JSON.stringify(header);
    const partialToken = [
        encode(utf8ToUint8Array(h)),
        encode(utf8ToUint8Array(p)),
    ].join(".");
    const messageAsUint8Array = utf8ToUint8Array(partialToken);
    const signature = await crypto.subtle.sign(subtleAlg(header.alg), privateKey, messageAsUint8Array);
    const signatureAsBase64 = encode(new Uint8Array(signature));
    return `${partialToken}.${signatureAsBase64}`;
}

const charset = "_-0123456789aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ";
var jti = () => {
    let size = 21;
    var id = "";
    var bytes = crypto.getRandomValues(new Uint8Array(size));
    while (0 < size--) {
        id += charset[bytes[size] & 63];
    }
    return id;
};

const iat = () => (Date.now() / 1000) | 0;
async function toJWK(publicKey) {
    const { kty, x, y, e, n, crv } = await crypto.subtle.exportKey("jwk", publicKey);
    return { kty, x, y, e, n, crv };
}
var dpop = async (keypair, alg, htu, htm, accessToken, additional) => {
    const jwk = await toJWK(keypair.publicKey);
    return JWT(keypair.privateKey, { typ: "dpop+jwt", alg, jwk }, {
        ...additional,
        iat: iat(),
        jti: jti(),
        htu,
        htm,
        ath: accessToken
            ? encode(new Uint8Array(await crypto.subtle.digest({ name: "SHA-256" }, new TextEncoder().encode(accessToken))))
            : undefined,
    });
};

async function generateKeyPair(alg) {
    const algorithm = subtleAlg(alg);
    return crypto.subtle.generateKey(algorithm, false, ["sign"]);
}

export default dpop;
export { generateKeyPair };
//# sourceMappingURL=index.js.map
