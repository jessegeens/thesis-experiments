# Thesis experiments
This repository contains a number of tools used to evaluate performance of a number of technologies, in the context of my thesis research

## Acknowledgements
The `dpop` library is based on [panva/dpop](https://github.com/panva/dpop), but modified to make use of node's crypto API instead of the WebCrypto API.

The `pepsa-benchmark` tool is partially based on the [demo app from Inrupt](https://github.com/inrupt/solid-client-authn-js/tree/main/packages/browser/examples/demoClientApp).

The `verifyDpop` module in the `macaroons-benchmark` tool is based on an example implementation from the [jose library](https://github.com/panva/jose/discussions/99).

## Available tools

### Data generator
The `data-generator` tool was built to generate synthetic datasets, which are used in the benchmarking of PePSA. It supports generating synthetic TCX and financial transaction data. Instructions can be found [here](data-generator/README.md)

### PePSA benchmark
This tool is written to benchmark [PePSA](https://github.com/jessegeens/pepsa-component) by timing request times to a Solid resource. It can be run in the browser by setting the correct resources to fetch. Timings of the request are written to the console in CSV format.

### Macaroons benchmark
This tool measures the performance difference between using DPoP or macaroons as access tokens. Generating and verifying macaroons is done with the [macaroons.js](https://github.com/nitram509/macaroons.js) library. Generating DPoP tokens is done using a modified version of the [dpop](https://github.com/panva/dpop) library (see above). For verifying DPoP tokens, a custom implementation is used that can be found [here](macaroons-benchmark/src/verifyDpop.js). This is because solid's access token verifier does not support injecting the necessary public keys out of the box.