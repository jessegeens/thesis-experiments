import subtleAlg from "./algs.js";
import { webcrypto as crypto } from "node:crypto";

async function generateKeyPair(alg) {
    const algorithm = subtleAlg(alg);
    return await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
}
export default generateKeyPair;
