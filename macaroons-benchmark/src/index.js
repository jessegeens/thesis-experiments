import macaroon from 'macaroons.js';
const MacaroonsBuilder = macaroon.MacaroonsBuilder;
const MacaroonsVerifier = macaroon.MacaroonsVerifier;
import {v4 as uuid} from "uuid";
import { PerformanceObserver, performance } from 'perf_hooks';
import DPoP, { generateKeyPair } from '../../dpop/dist-src/index.js';
import { webcrypto as crypto } from "node:crypto";
import { calculateJwkThumbprint }from 'jose'
import { verifyDpopProof } from './verifyDpop.js';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

const runExp1 = true;
const runExp2 = true;
const runExp3 = true;
const runExp4 = true;
const runExp5 = true;
const runExp6 = true;

const noOfSeconds = 1;
const repeat = 100


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
if (runExp1) { 
// Parameters
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

console.log(`=== Verify Macaroon ===`)
    for (let i = 0; i < repeat; i++) {
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

            verifier.isValid(mySecret);
        }
        console.log(`${count},${noOfSeconds}`);
        await sleep(1000);
    }
}


// Experiment 2 -> Generate Macaroons throughput
if (runExp2) { 
// Parameters
const myFile = "myFile";
const myMethod = "GET";
const mySecret = "Secret passphrase";
const location = "http://my.website.example"

// Generate macaroon

console.log(`=== Generate Macaroon ===`)
    for (let i = 0; i < repeat; i++) {
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

            myMacaroon.serialize();
        }
        console.log(`${count},${noOfSeconds}`);
        await sleep(1000);
    }
}


// Experiment 3 -> Generate DPoP throughput (ES256)
if (runExp3) { 
    // Parameters
    const myFile = "myFile";
    const myMethod = "GET";
    const accessTokenValue = 'W0lFSOAgL4oxWwnFtigwmXtL3tHNDjUCXVRasB3hQWahsVvDb0YX1Q2fk7rMJ-oy';
    const location = "http://my.website.example"
    const alg = 'ES256';
    const keypair = await generateKeyPair(alg);

    console.log(`=== Generate DPoP ${alg} ===`)
    for (let i = 0; i < repeat; i++) {
        let count = 0;
        let start = performance.now();
        while (performance.now() < start + noOfSeconds * 1000) {
            count++;
            await DPoP(keypair, alg, `${location}/${myFile}`, myMethod, accessTokenValue);
        }
        console.log(`${count},${noOfSeconds}`);
        await sleep(1000);
    }
}


// Experiment 4 -> Verify DPoP throughput (ES256)
if (runExp4) {
    // Parameters
    const myFile = "myFile";
    const myMethod = "GET";
    const accessTokenValue = 'W0lFSOAgL4oxWwnFtigwmXtL3tHNDjUCXVRasB3hQWahsVvDb0YX1Q2fk7rMJ-oy';
    const location = "https://pod.geens.cloud/"
    const alg = 'ES256';
    const keypair = await generateKeyPair(alg);
    const myUrl = `${location}${myFile}`
    const accessProof = await DPoP(keypair, alg, myUrl, myMethod, accessTokenValue, 
        {
            webid: `${location}jesse/profile/card#me`,
            iss: location,
            aud: 'solid',
            exp: Date.now() + (noOfSeconds + 10) * 1000,
        }
    );

    const publicJwk = await crypto.subtle.exportKey("jwk", keypair.publicKey);
    const publicThumbprint = await calculateJwkThumbprint(publicJwk);

    console.log(`=== Verify DPoP ${alg} ===`)
    for (let i = 0; i < repeat; i++) {
        let count = 0;
        let start = performance.now();
        while (performance.now() < start + noOfSeconds * 1000) {
            count++;
            await verifyDpopProof(publicThumbprint, accessProof, alg, {
                url: myUrl,
                method: myMethod
            });
        }
        console.log(`${count},${noOfSeconds}`);
        await sleep(1000);
    }   
}

// Experiment 5 -> Generate DPoP throughput (PS256)
if (runExp5) { 
    // Parameters
    const myFile = "myFile";
    const myMethod = "GET";
    const accessTokenValue = 'W0lFSOAgL4oxWwnFtigwmXtL3tHNDjUCXVRasB3hQWahsVvDb0YX1Q2fk7rMJ-oy';
    const location = "http://my.website.example"
    const alg = 'PS256';
    const keypair = await generateKeyPair(alg);

    console.log(`=== Generate DPoP ${alg} ===`)
    for (let i = 0; i < repeat; i++) {
        let count = 0;
        let start = performance.now();
        while (performance.now() < start + noOfSeconds * 1000) {
            count++;
            await DPoP(keypair, alg, `${location}/${myFile}`, myMethod, accessTokenValue);
        }
        console.log(`${count},${noOfSeconds}`);
        await sleep(1000);
    }
}


// Experiment 6 -> Verify DPoP throughput (PS256)
if (runExp6) {
    // Parameters
    const myFile = "myFile";
    const myMethod = "GET";
    const accessTokenValue = 'W0lFSOAgL4oxWwnFtigwmXtL3tHNDjUCXVRasB3hQWahsVvDb0YX1Q2fk7rMJ-oy';
    const location = "https://pod.geens.cloud/"
    const alg = 'PS256';
    const keypair = await generateKeyPair(alg);
    const myUrl = `${location}${myFile}`
    const accessProof = await DPoP(keypair, alg, myUrl, myMethod, accessTokenValue, 
        {
            webid: `${location}jesse/profile/card#me`,
            iss: location,
            aud: 'solid',
            exp: Date.now() + (noOfSeconds + 10) * 1000,
        }
    );

    const publicJwk = await crypto.subtle.exportKey("jwk", keypair.publicKey);
    const publicThumbprint = await calculateJwkThumbprint(publicJwk);

    console.log(`=== Verify DPoP ${alg} ===`)
    for (let i = 0; i < repeat; i++) {
        let count = 0;
        let start = performance.now();
        while (performance.now() < start + noOfSeconds * 1000) {
            count++;
            await verifyDpopProof(publicThumbprint, accessProof, alg, {
                url: myUrl,
                method: myMethod
            });
        }
        console.log(`${count},${noOfSeconds}`);
        await sleep(1000);
    }   
}
