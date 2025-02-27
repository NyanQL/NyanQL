function main() {
    if (!nyanAllParams.token) {
        return { status: 500, success: false, error: {"test": "hogehoge" , "2": "エラー2つめ"} };
    }
    return { status: 200, success: true };
}
main();

