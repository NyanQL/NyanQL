console.log("loaded check_test1.js");

function main() {
    console.log("nyanAllParams:", nyanAllParams);
    console.log("accepted keys:", nyanAcceptedParamsKeys);
    console.log("nyanErros:", typeof nyanErros);
    console.log("nyanGetAPI:", typeof nyanGetAPI);
    console.log("nyanJsonAPI", typeof nyanJsonAPI);

    return JSON.stringify({success: true, status: 200});
}

main();
