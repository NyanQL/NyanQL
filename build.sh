#!/bin/bash

# これはクロスコンパイル用のshellです。
# Mac環境でのビルドを想定しています。


# プロジェクト名
PROJECT_NAME="NyanQL"

# クロスコンパイラのディレクトリをPATHに追加
export PATH="/opt/homebrew/opt/musl-cross/bin:$PATH"

# Linux (x86_64) 用ビルド
#echo "Building for Linux (x86_64)..."
#CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-musl-gcc go build -o ${PROJECT_NAME}_Linux_amd64

# Linux (ARM64) 用ビルド
#echo "Building for Linux (ARM64)..."
#CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-musl-gcc go build -o ${PROJECT_NAME}_Linux_arm64

# macOS (ARM) 用ビルド
echo "Building for macOS (ARM)..."
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o ${PROJECT_NAME}_Mac

# Windows (x86_64) 用ビルド
echo "Building for Windows (x86_64)..."
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o ${PROJECT_NAME}_Windows.exe

echo "Build complete. Binaries are in the current directory."




