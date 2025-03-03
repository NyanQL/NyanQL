function main() {
    console.log("nyanAllParams:", nyanAllParams);
    console.log("accepted keys:", nyanAcceptedParamsKeys);
    console.log("nyanErros:", typeof nyanErros);
    console.log("nyanGetAPI:", typeof nyanGetAPI);
    console.log("nyanJsonAPI", typeof nyanJsonAPI);
    console.log("nyanHostExec:" , typeof nyanHostExec);
    console.log(nyanHostExec("ls"));


    if (nyanRequestCheck()) {
        console.log(nyanErros);
        return JSON.stringify({success: false, status: 401, error: nyanErros});
    }

    return JSON.stringify({success: true, status: 200});
}

main();
