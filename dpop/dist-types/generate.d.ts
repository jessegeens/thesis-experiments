declare function generateKeyPair(alg: string): Promise<CryptoKey | CryptoKeyPair>;
export default generateKeyPair;
