function main() {
    console.log("nyanAllParams:", nyanAllParams);
    console.log("accepted keys:", nyanAcceptedParamsKeys);
    console.log("nyanErros:", typeof nyanErros);
    console.log("nyanGetAPI:", typeof nyanGetAPI);
    console.log("nyanJsonAPI", typeof nyanJsonAPI);
    console.log("nyanHostExec:" , typeof nyanHostExec);
    //console.log(nyanHostExec("ls"));
    //let r2 = nyanJsonAPI("http://localhost:8443/nyan", '{"key":"value"}', "neko", "nyan", headers);
    //console.log(r2);


    if (nyanRequestCheck()) {
        console.log(nyanErros);
        return JSON.stringify({success: false, status: 401, error: nyanErros});
    }

    return JSON.stringify({success: true, status: 200});
}

main();
