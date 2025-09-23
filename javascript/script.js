
const nyanAcceptedParams = {"date": "2024-06-25"};

const nyanOutputColumns =  ["date"];

console.log("loaded script.js");


function main(){
    console.log(nyanAllParams);
    let data = nyanAllParams;
    console.log(JSON.stringify(data));
    //SQLファイル取り込みの確認
    let sqlResult = nyanRunSQL("./sql/sqlite/checkToday.sql", {});
    console.log(typeof nyanSaveFile)

    //ファイルの保存テスト
    const b64 = nyanBase64Encode("こんにちは！ にゃんくる");
    nyanSaveFile(b64, "./test/test.txt");

    console.log(sha256("test"));
    console.log(sha1("test"));

    return JSON.stringify({success: true, status: 200, result: sqlResult , api: nyanAllParams.api });
}

main();
