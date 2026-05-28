//go:build !(js && wasm)

// This binary targets WebAssembly only. The stub keeps `go build ./...` working
// on other platforms and tells the operator how to build the real artifact.
package main

import "fmt"

func main() {
	fmt.Println("wasmverify must be built for WebAssembly: GOOS=js GOARCH=wasm go build -o cocverify.wasm ./cmd/wasmverify")
}
