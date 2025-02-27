console.log("loaded nyanRequestCheck.js");

let nyanErros = {};
console.log("nyanErros:", typeof nyanErros);

function nyanRequestCheck(keyArray = [], requiredParams = {}) {
    if (Object.keys(requiredParams).length == 0) {
        requiredParams = nyanAllParams;
    }
    if (keyArray.length == 0) {
        keyArray = nyanAcceptedParamsKeys;
    }

    // requiredParams 配列の各キーについて、requiredParams に存在するか確認
    keyArray.forEach(param => {
        if (!(param in requiredParams)) {
            nyanErros[param] = "Request does not exist";
        }
    });

// エラーがある場合はエラーオブジェクトを出力
    if (Object.keys(nyanErros).length > 0) {
        console.log("nyanErros:", typeof nyanErros);
        return nyanErros;
    } else {
        return;
    }
}