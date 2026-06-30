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
	"encoding/hex"
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
	js.Global().Set("cocVerifyIdentity", js.FuncOf(verifyIdentity))
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
		fetcher, err := buildFetcher(baseURL)
		if err != nil {
			return "", err
		}
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

// verifyIdentity(leafB64, bindingIndex, readBaseURL, origin, checkpointVkey, identityRootsHex)
// -> Promise<JSON string>. identityRootsHex is one or more comma-separated 64-hex
// Ed25519 identity-root public keys (a set, for rotation).
func verifyIdentity(_ js.Value, args []js.Value) any {
	return newPromise(func() (string, error) {
		if len(args) < 6 {
			return "", errArg("cocVerifyIdentity(leafB64, bindingIndex, readBaseURL, origin, checkpointVkey, identityRootsHex)")
		}
		rawLeaf, err := base64.StdEncoding.DecodeString(args[0].String())
		if err != nil {
			return "", errArg("leaf is not valid base64")
		}
		bindingIndex, err := parseIndex(args[1])
		if err != nil {
			return "", err
		}
		baseURL := strings.TrimSpace(args[2].String())
		origin := args[3].String()
		vkey := strings.TrimSpace(args[4].String())
		roots, err := parseRoots(args[5].String())
		if err != nil {
			return "", err
		}
		if baseURL == "" || origin == "" || vkey == "" {
			return "", errArg("readBaseURL, origin, and checkpointVkey are required")
		}
		fetcher, err := buildFetcher(baseURL)
		if err != nil {
			return "", err
		}
		res, err := cocverify.VerifyIdentity(context.Background(), fetcher, rawLeaf, bindingIndex, origin, vkey, roots)
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

// buildFetcher wires a cocverify.Fetcher over Go's net/http (the browser Fetch API
// under js/wasm) using the Tessera HTTPFetcher, including the entry-bundle fetcher
// needed for identity resolution.
func buildFetcher(baseURL string) (cocverify.Fetcher, error) {
	u, err := url.Parse(ensureTrailingSlash(baseURL))
	if err != nil {
		return cocverify.Fetcher{}, err
	}
	f, err := client.NewHTTPFetcher(u, http.DefaultClient)
	if err != nil {
		return cocverify.Fetcher{}, err
	}
	return cocverify.Fetcher{Checkpoint: f.ReadCheckpoint, Tile: f.ReadTile, Entries: f.ReadEntryBundle}, nil
}

func parseIndex(v js.Value) (uint64, error) {
	var s string
	if v.Type() == js.TypeNumber {
		s = strconv.Itoa(v.Int())
	} else {
		s = v.String()
	}
	i, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, errArg("index must be a non-negative integer")
	}
	return i, nil
}

func parseRoots(s string) ([][32]byte, error) {
	var roots [][32]byte
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := hex.DecodeString(part)
		if err != nil || len(b) != 32 {
			return nil, errArg("identity root must be 32 bytes (64 hex chars)")
		}
		var r [32]byte
		copy(r[:], b)
		roots = append(roots, r)
	}
	if len(roots) == 0 {
		return nil, errArg("at least one identity root is required")
	}
	return roots, nil
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
