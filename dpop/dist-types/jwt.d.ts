declare function JWT(privateKey: CryptoKey, header: {
    alg: string;
    [key: string]: any;
}, payload: object): Promise<string>;
export default JWT;
