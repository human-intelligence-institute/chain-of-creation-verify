//go:build js && wasm

// Command wasmverify exposes chain-of-creation verification to the browser. Built
// with GOOS=js GOARCH=wasm, it registers a global cocVerifyLeaf(leafB64, mediaB64)
// function that returns a JSON string: either the verification result or
// {"error": "..."}.
package main

import (
	"encoding/base64"
	"encoding/json"
	"syscall/js"

	"github.com/human-intelligence-institute/chain-of-creation/pkg/cocverify"
)

func main() {
	js.Global().Set("cocVerifyLeaf", js.FuncOf(verifyLeaf))
	select {} // keep the Go runtime alive for callbacks
}

// verifyLeaf(leafBase64 string, mediaBase64 string|null) -> JSON string.
func verifyLeaf(_ js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return errJSON("first argument must be a base64 leaf string")
	}
	rawLeaf, err := base64.StdEncoding.DecodeString(args[0].String())
	if err != nil {
		return errJSON("leaf is not valid base64")
	}
	var media []byte
	if len(args) > 1 && args[1].Type() == js.TypeString {
		media, err = base64.StdEncoding.DecodeString(args[1].String())
		if err != nil {
			return errJSON("media is not valid base64")
		}
	}
	res, err := cocverify.VerifyLeaf(rawLeaf, media)
	if err != nil {
		return errJSON(err.Error())
	}
	b, err := json.Marshal(res)
	if err != nil {
		return errJSON(err.Error())
	}
	return string(b)
}

func errJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}
