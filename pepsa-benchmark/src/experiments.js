
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

const SERVER_ADDRESS = "http://localhost:3000/jesse/"
const targetFiles = [
    `${SERVER_ADDRESS}benchmark/output-10-pretty.json`,      // 3 kb
    `${SERVER_ADDRESS}benchmark/output-100-pretty.json`,     // 30 kb
    `${SERVER_ADDRESS}benchmark/output-1000-pretty.json`,    // 300 kb
    `${SERVER_ADDRESS}benchmark/output-10000-pretty.json`,   // 3 mb
    //`${SERVER_ADDRESS}benchmark/output-100000-pretty.json`,  // 30 mb
]

export async function runExperiments(session) {
    await sleep(3000);
    console.log(`Starting experiments`)
    let csv = "iteration, target, duration (ms), response length\n"
    let noIterations = 10
    for (let i = 0; i < noIterations; i++) {
        for (let target of targetFiles) {
            let startTime = window.performance.now();
            let response = await fetchResource(target, session);
            let endTime = window.performance.now();
            csv = csv.concat(`${i},${target},${endTime - startTime},${response.length}\n`)
        }
        console.log(`Finished iteration ${i + 1} / ${noIterations}`)
        await sleep(2000);
    }
    console.log(`Experiment results: \n ${csv}`)
}


export async function fetchResource(target, session) {
    const response = await (
        await session.fetch(target, {})
    ).text();
    return response;
}