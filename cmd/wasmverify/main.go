//go:build js && wasm

// Command wasmverify exposes chain-of-creation verification to the browser. Built
// with GOOS=js GOARCH=wasm, it registers two globals:
//
//   - cocVerifyLeaf(leafB64, mediaB64?) string
//     Offline: signature + content match. Synchronous (no network).
//
//   - cocVerifyInclusion(leafB64, index, readBaseURL, origin, vkey) Promise<string>
//     Proves the leaf is committed in the published log: fetches the signed
//     checkpoint + proof-path tiles and verifies an RFC6962 inclusion proof. It
//     returns a Promise because it does network I/O (browser fetch, via Go's
//     net/http js transport). The checkpoint is verified against the caller-pinned
//     (origin, vkey) — never the key the server presents.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/human-intelligence-institute/chain-of-creation/pkg/cocverify"
	"github.com/transparency-dev/tessera/client"
)

func main() {
	js.Global().Set("cocVerifyLeaf", js.FuncOf(verifyLeaf))
	js.Global().Set("cocVerifyInclusion", js.FuncOf(verifyInclusion))
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

// verifyInclusion(leafB64, index, readBaseURL, origin, vkey) -> Promise<JSON string>.
// The Promise resolves with the InclusionResult JSON or rejects with an error
// message string.
func verifyInclusion(_ js.Value, args []js.Value) any {
	return newPromise(func() (string, error) {
		rawLeaf, index, baseURL, origin, vkey, err := inclusionArgs(args)
		if err != nil {
			return "", err
		}
		u, err := url.Parse(ensureTrailingSlash(baseURL))
		if err != nil {
			return "", err
		}
		f, err := client.NewHTTPFetcher(u, http.DefaultClient)
		if err != nil {
			return "", err
		}
		fetcher := cocverify.Fetcher{Checkpoint: f.ReadCheckpoint, Tile: f.ReadTile}
		res, err := cocverify.VerifyInclusion(context.Background(), fetcher, rawLeaf, index, origin, vkey)
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(res)
		if err != nil {
			return "", err
		}
		return string(b), nil
	})
}

func inclusionArgs(args []js.Value) (rawLeaf []byte, index uint64, baseURL, origin, vkey string, err error) {
	if len(args) < 5 {
		return nil, 0, "", "", "", errArg("cocVerifyInclusion(leafB64, index, readBaseURL, origin, vkey)")
	}
	rawLeaf, derr := base64.StdEncoding.DecodeString(args[0].String())
	if derr != nil {
		return nil, 0, "", "", "", errArg("leaf is not valid base64")
	}
	// index may arrive as a JS number or a string; accept both.
	var idxStr string
	if args[1].Type() == js.TypeNumber {
		idxStr = strconv.Itoa(args[1].Int())
	} else {
		idxStr = args[1].String()
	}
	index, perr := strconv.ParseUint(strings.TrimSpace(idxStr), 10, 64)
	if perr != nil {
		return nil, 0, "", "", "", errArg("index must be a non-negative integer")
	}
	baseURL = strings.TrimSpace(args[2].String())
	origin = args[3].String()
	vkey = strings.TrimSpace(args[4].String())
	if baseURL == "" || origin == "" || vkey == "" {
		return nil, 0, "", "", "", errArg("readBaseURL, origin, and vkey are required")
	}
	return rawLeaf, index, baseURL, origin, vkey, nil
}

// newPromise runs work on a goroutine (so blocking network I/O does not stall the
// JS event loop) and returns a JS Promise that settles with its result.
func newPromise(work func() (string, error)) js.Value {
	handler := js.FuncOf(func(_ js.Value, pargs []js.Value) any {
		resolve, reject := pargs[0], pargs[1]
		go func() {
			res, err := work()
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(res)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func ensureTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}

type argError struct{ msg string }

func (e argError) Error() string { return e.msg }
func errArg(msg string) error    { return argError{msg} }

func errJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}
