import { EmbeddedJWK, jwtVerify, calculateJwkThumbprint }from 'jose'

export async function verifyDpopProof(publicJwkThumb, dpopProof, alg, {url, method}) {
    const { payload, protectedHeader } = await jwtVerify(dpopProof, EmbeddedJWK, {
        typ: 'dpop+jwt',
        algorithms: [alg],
        maxTokenAge: '60s',
        clockTolerance: '5s'
    });
    
    // Check if required properties exist
    /*if (!(typeof payload.jti === 'string' && payload.jti)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing jti field");
    }*/
    if(!(typeof payload.htu === 'string' && payload.htu)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing htu field");
    }
    if(!(typeof payload.htm === 'string' && payload.htm)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing htm field");
    }
    /*if(!(typeof payload.webid === 'string' && payload.webid)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing webid field");
    }
    if(!(typeof payload.aud === 'string' && payload.aud)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing aud field");
    }
    if(!(typeof payload.iss === 'string' && payload.iss)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing iss field");
    }*/
    if(!(typeof payload.exp === 'number' && payload.exp)) {
        throw new InvalidDpopProofError("Failed to verify JWT: missing exp field");
    }

    // Check if properties are correct
    if(payload.exp < Date.now()) {
        throw new InvalidDpopProofError("Failed to verify JWT: expired");
    }
    if(!(payload.htu == url)) {
        throw new InvalidDpopProofError("Failed to verify JWT: invalid target");
    }
    if(!(payload.htm == method)) {
        throw new InvalidDpopProofError("Failed to verify JWT: invalid method");
    }
    /*if(!(payload.iss == location)) {
        throw new InvalidDpopProofError("Failed to verify JWT: invalid location");
    }
    if(!(payload.aud == "solid")) {
        throw new InvalidDpopProofError("Failed to verify JWT: invalid audience");
    }
    if(!(payload.webid == webid)) {
        throw new InvalidDpopProofError("Failed to verify JWT: invalid webid");
    }*/


    // Check if key thumbprint is correct    
    const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

    if (!(thumbprint == publicJwkThumb)) {
        throw new InvalidDpopProofError("Failed to verify JWT: invalid thumbprint");
    }

    return true;
}

class InvalidDpopProofError extends Error {
    constructor(message) {
      super(message);
      this.name = "InvalidDpopProofError"; 
    }
  }