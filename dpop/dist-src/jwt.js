import * as base64url from "./base64url.js";
import { webcrypto as crypto } from "node:crypto";

import alg from "./algs.js";
const utf8ToUint8Array = (str) => base64url.decode(btoa(unescape(encodeURIComponent(str))));
async function JWT(privateKey, header, payload) {
    const p = JSON.stringify(payload);
    const h = JSON.stringify(header);
    const partialToken = [
        base64url.encode(utf8ToUint8Array(h)),
        base64url.encode(utf8ToUint8Array(p)),
    ].join(".");
    const messageAsUint8Array = utf8ToUint8Array(partialToken);
    const signature = await crypto.subtle.sign(alg(header.alg), privateKey, messageAsUint8Array);
    const signatureAsBase64 = base64url.encode(new Uint8Array(signature));
    return `${partialToken}.${signatureAsBase64}`;
}
export default JWT;
