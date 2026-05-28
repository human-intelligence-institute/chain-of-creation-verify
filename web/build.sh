#!/usr/bin/env sh
# Build the WebAssembly verifier and stage the Go loader shim alongside it.
# Serve this directory over HTTP afterwards (file:// will not load .wasm).
set -e
cd "$(dirname "$0")"
GOOS=js GOARCH=wasm go build -o cocverify.wasm ../cmd/wasmverify
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .
echo "built: web/cocverify.wasm + web/wasm_exec.js"
echo "serve with e.g.: (cd web && python3 -m http.server 8000)"
