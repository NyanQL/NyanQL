function main() {
    console.log(nyanAllParams);
    console.log(typeof nyanGetAPI);
    console.log(typeof nyanJsonAPI);

    return JSON.stringify({ success: true, status: 200 });
}
main();
