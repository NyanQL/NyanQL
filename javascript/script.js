
const nyanAcceptedParams = {"date": "2024-06-25"};

const nyanOutputColumns =  ["date"];

console.log("loaded script.js");


function main(){
    console.log(nyanAllParams);
    let data = nyanAllParams;
    console.log(JSON.stringify(data));
    data.ids = [2];
    console.log(data);
    //SQLファイル取り込みの確認
    let result = JSON.parse(nyanRunSQL("./sql/sqlite/checkToday.sql" , {}));
    console.log(JSON.stringify(result));

    return JSON.stringify({success: true, status: 200, result: result , api: nyanAllParams.api });
}

main();