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
export default (alg) => {
    if (!(alg in algs)) {
        throw new TypeError("unrecognized or unsupported JWS algorithm");
    }
    return algs[alg];
};
