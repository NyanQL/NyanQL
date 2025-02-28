
const nyanAcceptedParams = {"date": "2024-06-25"};

const nyanOutputColumns =  ["date"];




function main(){
    console.log(nyanAllParams);
    let err = nyanRequestCheck(Object.keys(nyanAcceptedParams) , nyanAcceptedParams);
    console.log("check", err);
    let result = JSON.parse(nyanGetSQL("./sql/sqlite/check_day.sql" , {"date": "2024%"}));
    if(result[0].this_days_count == 1)
    {
        console.log(1);
    }
    console.log(JSON.stringify(result));
    console.log(JSON.stringify(nyanErros));
    return JSON.stringify({success: true, status: 200, data: { result: result, request: nyanAllParams} });
}

main();