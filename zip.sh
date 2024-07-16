#!/bin/bash

# 配布用バイナリデータとサンプルをzipファイルにするプログラムです。

# プロジェクト名
PROJECT_NAME="NyanQL"
os=Windows
echo "create ${os} zip  .."
zip -r ${PROJECT_NAME}_${os}.zip ssl
zip -r ${PROJECT_NAME}_${os}.zip sql/sqlite
zip -r ${PROJECT_NAME}_${os}.zip api.json
zip -r ${PROJECT_NAME}_${os}.zip config.json
zip -r ${PROJECT_NAME}_${os}.zip go.sum
zip -r ${PROJECT_NAME}_${os}.zip go.mod
zip -r ${PROJECT_NAME}_${os}.zip ${PROJECT_NAME}_${os}.exe
zip -r ${PROJECT_NAME}_${os}.zip README.md

os=Mac
echo "create ${os} zip ..."
zip -r ${PROJECT_NAME}_${os}.zip ssl
zip -r ${PROJECT_NAME}_${os}.zip sql/sqlite
zip -r ${PROJECT_NAME}_${os}.zip api.json
zip -r ${PROJECT_NAME}_${os}.zip config.json
zip -r ${PROJECT_NAME}_${os}.zip go.sum
zip -r ${PROJECT_NAME}_${os}.zip go.mod
zip -r ${PROJECT_NAME}_${os}.zip ${PROJECT_NAME}_${os}
zip -r ${PROJECT_NAME}_${os}.zip README.md

os=Linux_amd64
echo "create ${os} zip ..."
zip -r ${PROJECT_NAME}_${os}.zip ssl
zip -r ${PROJECT_NAME}_${os}.zip sql/sqlite
zip -r ${PROJECT_NAME}_${os}.zip api.json
zip -r ${PROJECT_NAME}_${os}.zip config.json
zip -r ${PROJECT_NAME}_${os}.zip go.sum
zip -r ${PROJECT_NAME}_${os}.zip go.mod
zip -r ${PROJECT_NAME}_${os}.zip ${PROJECT_NAME}_${os}
zip -r ${PROJECT_NAME}_${os}.zip README.md

os=Linux_arm64
echo "create ${os} zip"
zip -r ${PROJECT_NAME}_${os}.zip ssl
zip -r ${PROJECT_NAME}_${os}.zip sql/sqlite
zip -r ${PROJECT_NAME}_${os}.zip api.json
zip -r ${PROJECT_NAME}_${os}.zip config.json
zip -r ${PROJECT_NAME}_${os}.zip go.sum
zip -r ${PROJECT_NAME}_${os}.zip go.mod
zip -r ${PROJECT_NAME}_${os}.zip ${PROJECT_NAME}_${os}
zip -r ${PROJECT_NAME}_${os}.zip README.md