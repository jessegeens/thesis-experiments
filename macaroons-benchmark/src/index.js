import macaroon from 'macaroons.js';
const MacaroonsBuilder = macaroon.MacaroonsBuilder;
const MacaroonsVerifier = macaroon.MacaroonsVerifier;
import {v4 as uuid} from "uuid";
import { createSolidTokenVerifier } from '../../access-token-verifier/dist/index.js';
import { PerformanceObserver, performance } from 'perf_hooks';
import DPoP, { generateKeyPair } from '../../dpop/dist-src/index.js';
import { webcrypto as crypto } from "node:crypto";

// Counter replay attacks by keeping used identifiers
function IdentifierVerifier(caveat) {
    if (!caveat.includes("identifier = ")) return false;
    let identifier = caveat.replace("identifier = ", "");
    if (parsedIdentifiers.includes(identifier)) {
        //console.log("[WARN] Macaroon has already been used");
        return false;
    } else {
      //  console.log("[INFO] Verified unique identifier")
    }
    parsedIdentifiers.push(identifier);
    return true;
}

// Verify macaroon hasn't expired
function TimestampVerifier(caveat) {
    if (!caveat.includes("time <")) return false;
    let timestamp = parseInt(caveat.replace("time < ", ""));
    if (timestamp > Date.now()){
     //   console.log("[INFO] Verified timestamp")
        return true;
    }
    console.log("[WARN] Macaroon has expired");
    return false;
}


// Experiment 1 -> Verify Macaroons throughput
{ /*
// Parameters
let noOfSeconds = 60;
const myFile = "myFile";
const myMethod = "GET";
const mySecret = "Secret passphrase";
const location = "http://my.website.example"
const identifier = uuid();

// Generate macaroon
let myMacaroon = MacaroonsBuilder.create(location, mySecret, identifier);
    
myMacaroon = MacaroonsBuilder.modify(myMacaroon)
    .add_first_party_caveat("time < " + (Date.now() + 1000 * (noOfSeconds + 10)))
    .add_first_party_caveat(`file = ${myFile}`)
    .add_first_party_caveat(`method = ${myMethod}`)
    .getMacaroon();

const auth = myMacaroon.serialize();

let count = 0;
let start = performance.now();

while (performance.now() < start + noOfSeconds * 1000) {
    count++;
    let myMacaroon = MacaroonsBuilder.deserialize(auth);
    let verifier = new MacaroonsVerifier(myMacaroon);
    verifier.satisfyGeneral(TimestampVerifier);
    verifier.satisfyGeneral(IdentifierVerifier);
    verifier.satisfyExact(`file = ${myFile}`);
    verifier.satisfyExact(`method = ${myMethod}`);
}

console.log(`Verified ${count} macaroons in ${noOfSeconds} seconds`)
*/ }


// Experiment 2 -> Generate Macaroons throughput
{ /*
// Parameters
let noOfSeconds = 60;
const myFile = "myFile";
const myMethod = "GET";
const mySecret = "Secret passphrase";
const location = "http://my.website.example"

// Generate macaroon
let count = 0;
let start = performance.now();

while (performance.now() < start + noOfSeconds * 1000) {
    count++;
    let myMacaroon = MacaroonsBuilder.create(location, mySecret, uuid());
    
    myMacaroon = MacaroonsBuilder.modify(myMacaroon)
    .add_first_party_caveat("time < " + (Date.now() + 1000 * (noOfSeconds + 10)))
    .add_first_party_caveat(`file = ${myFile}`)
    .add_first_party_caveat(`method = ${myMethod}`)
    .getMacaroon();

    const auth = myMacaroon.serialize();
}

console.log(`Generated ${count} macaroons in ${noOfSeconds} seconds`);
*/ }


// Experiment 3 -> Generate DPoP throughput
{ /*
    // Parameters
    let noOfSeconds = 60;
    const myFile = "myFile";
    const myMethod = "GET";
    const accessTokenValue = 'W0lFSOAgL4oxWwnFtigwmXtL3tHNDjUCXVRasB3hQWahsVvDb0YX1Q2fk7rMJ-oy';
    const location = "http://my.website.example"
    const alg = 'ES256';
    const keypair = await generateKeyPair(alg);


    let count = 0;
    let start = performance.now();

    while (performance.now() < start + noOfSeconds * 1000) {
        count++;
        const protectedResourceAccessProof = await DPoP(keypair, alg, `${location}/${myFile}`, myMethod, accessTokenValue);
    }
    
    console.log(`Generated ${count} DPoP tokens in ${noOfSeconds} seconds`);
*/ }


// Experiment 4 -> Verify DPoP throughput
{
    // Parameters
    let noOfSeconds = 60;
    const myFile = "myFile";
    const myMethod = "GET";
    const accessTokenValue = 'W0lFSOAgL4oxWwnFtigwmXtL3tHNDjUCXVRasB3hQWahsVvDb0YX1Q2fk7rMJ-oy';
    const location = "https://pod.geens.cloud/"
    const alg = 'ES256';
    const keypair = await generateKeyPair(alg);
    const myUrl = `${location}${myFile}`
    const protectedResourceAccessProof = await DPoP(keypair, alg, myUrl, myMethod, accessTokenValue, 
        {
            webid: `${location}jesse/profile/card#me`,
            iss: location,
            aud: 'audience',
            exp: Date.now() + (noOfSeconds + 10) * 1000 
        }
    );

    //const cache = new SolidTokenVerifier();
    //const solidOidcAccessTokenVerifier = cache.verify.bind(cache);

    const solidOidcAccessTokenVerifier = createSolidTokenVerifier();

    //console.log("protected resource access proof: " + protectedResourceAccessProof)
    let count = 0;
    let start = performance.now();

   // try {
    const { client_id, webid} = await solidOidcAccessTokenVerifier(
        `DPoP ${protectedResourceAccessProof}`,
        keypair.publicKey,
        {
          //header: protectedResourceAccessProof,
          method: myMethod,
          url: myUrl
        }
      );
    console.log(`Client id: ${client_id}, webid: ${webid}`)
   /* } catch (err) {
        console.log("Error occured: " + err)
    }*/
   

    /*while (performance.now() < start + noOfSeconds * 1000) {
        count++;
    }*/
    
    console.log(`Verified ${count} DPoP tokens in ${noOfSeconds} seconds`);
}