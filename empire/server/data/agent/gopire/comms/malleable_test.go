//go:build malleable

package comms

// Unit tests for the runtime malleable profile interpreter.
//
// These tests pin the byte semantics that must match the Python reference
// implementation in empire/server/common/malleable/transformation.py and
// empire/server/common/malleable/transaction.py. Any drift here breaks
// interop with the malleable HTTP listener.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// helperEncodeB64 base64-encodes a JSON string so tests can construct the
// same shape the server emits (base64 of the compact JSON blob).
func helperEncodeB64(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestParseMalleableProfile_EmptyReturnsNilNil(t *testing.T) {
	// Empty input signals "legacy mode" — NOT an error.
	for _, in := range []string{"", "   ", "\t\n"} {
		mp, err := ParseMalleableProfile(in)
		if err != nil {
			t.Errorf("ParseMalleableProfile(%q): unexpected err %v", in, err)
		}
		if mp != nil {
			t.Errorf("ParseMalleableProfile(%q): expected nil, got %+v", in, mp)
		}
	}
}

func TestParseMalleableProfile_MalformedBase64(t *testing.T) {
	_, err := ParseMalleableProfile("!!!not valid base64!!!")
	if err == nil {
		t.Fatal("expected error for malformed base64")
	}
}

func TestParseMalleableProfile_MalformedJSON(t *testing.T) {
	// Valid base64 that decodes to non-JSON.
	in := base64.StdEncoding.EncodeToString([]byte("not json {"))
	_, err := ParseMalleableProfile(in)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseMalleableProfile_UnsupportedVersion(t *testing.T) {
	// A server emitting v != supportedProfileVersion must hard-fail at the
	// agent, not silently drop new sections. See _AGENT_PROFILE_SCHEMA_VERSION
	// on the server side (empire/server/common/malleable/profile.py).
	for _, badV := range []int{0, 2, 999} {
		payload := map[string]any{
			"v":        badV,
			"sleep":    1000,
			"jitter":   0,
			"sections": map[string]any{},
		}
		_, err := ParseMalleableProfile(helperEncodeB64(t, payload))
		if err == nil {
			t.Errorf("v=%d: expected unsupported-version error, got nil", badV)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported schema version") {
			t.Errorf("v=%d: expected version error, got %v", badV, err)
		}
	}
}

func TestParseMalleableProfile_ValidBlob(t *testing.T) {
	payload := map[string]any{
		"v":      1,
		"sleep":  60000,
		"jitter": 10,
		"sections": map[string]any{
			"stager": map[string]any{
				"client": map[string]any{
					"verb":       "GET",
					"uris":       []string{"/stage1", "/stage2"},
					"headers":    map[string]string{"X": "Y"},
					"parameters": map[string]string{},
					"body":       "",
					"metadata": map[string]any{
						"transforms": []any{map[string]string{"op": "base64"}},
						"terminator": map[string]string{"type": "header", "arg": "Cookie"},
					},
				},
				"server": map[string]any{
					"headers":     map[string]string{},
					"body_prefix": "",
					"output": map[string]any{
						"transforms": []any{},
						"terminator": map[string]string{"type": "print"},
					},
				},
			},
			"get":  map[string]any{"client": map[string]any{}, "server": map[string]any{}},
			"post": map[string]any{"client": map[string]any{}, "server": map[string]any{}},
		},
	}
	blob := helperEncodeB64(t, payload)
	mp, err := ParseMalleableProfile(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if mp.V != 1 {
		t.Errorf("V: want 1, got %d", mp.V)
	}
	if mp.Sleep != 60000 {
		t.Errorf("Sleep: want 60000, got %d", mp.Sleep)
	}
	stager := mp.Sections["stager"]
	if len(stager.Client.URIs) != 2 {
		t.Errorf("stager uris: %v", stager.Client.URIs)
	}
	if stager.Client.Metadata == nil ||
		len(stager.Client.Metadata.Transforms) != 1 ||
		stager.Client.Metadata.Transforms[0].Op != "base64" {
		t.Errorf("stager metadata transforms: %+v", stager.Client.Metadata)
	}
}

// -- Transform round-trip tests -------------------------------------------------

func roundTripCase(t *testing.T, name string, transforms []Transform, input []byte) {
	t.Helper()
	c := &Container{Transforms: transforms}
	forward, err := c.Apply(input)
	if err != nil {
		t.Fatalf("%s: apply: %v", name, err)
	}
	reverse, err := c.Reverse(forward)
	if err != nil {
		t.Fatalf("%s: reverse: %v", name, err)
	}
	if !bytes.Equal(reverse, input) {
		t.Errorf("%s: round-trip mismatch\n want: %x\n  got: %x", name, input, reverse)
	}
}

func TestTransform_Base64_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("hello"),
		{0x00, 0xFF, 0x7F, 0x80, 0x01},
	}
	for _, in := range inputs {
		roundTripCase(t, "base64", []Transform{{Op: "base64"}}, in)
	}
}

func TestTransform_Base64_PythonCompatible(t *testing.T) {
	// Python: base64.b64encode(b"hello") -> "aGVsbG8="
	c := &Container{Transforms: []Transform{{Op: "base64"}}}
	out, err := c.Apply([]byte("hello"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if string(out) != "aGVsbG8=" {
		t.Errorf("base64 apply: want aGVsbG8=, got %s", out)
	}
}

func TestTransform_Base64URL_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("hello"),
		{0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0xAB},
	}
	for _, in := range inputs {
		roundTripCase(t, "base64url", []Transform{{Op: "base64url"}}, in)
	}
}

func TestTransform_Base64URL_AllByteValuesRoundTrip(t *testing.T) {
	// Make sure every byte value survives the base64 + URL-encode + reverse
	// pipeline, since routing packets include arbitrary binary bytes.
	all := make([]byte, 256)
	for i := 0; i < 256; i++ {
		all[i] = byte(i)
	}
	roundTripCase(t, "base64url-all-bytes", []Transform{{Op: "base64url"}}, all)
}

func TestTransform_Base64URL_PythonCompatible(t *testing.T) {
	// Python urllib.parse.quote(base64.b64encode(...)) uses safe='/'.
	// Verified via: python3 -c "import base64, urllib.parse; print(urllib.parse.quote(base64.b64encode(b'hello')))"
	// -> 'aGVsbG8%3D'
	c := &Container{Transforms: []Transform{{Op: "base64url"}}}
	out, err := c.Apply([]byte("hello"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if string(out) != "aGVsbG8%3D" {
		t.Errorf("base64url apply(hello): want aGVsbG8%%3D, got %s", out)
	}

	// Binary data that exercises +, /, = chars:
	// python3 -c "import base64, urllib.parse; print(urllib.parse.quote(base64.b64encode(bytes([0, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0xAB]))))"
	// -> 'AP9/gAH%2Bqw%3D%3D'
	out, err = c.Apply([]byte{0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0xAB})
	if err != nil {
		t.Fatalf("apply binary: %v", err)
	}
	if string(out) != "AP9/gAH%2Bqw%3D%3D" {
		t.Errorf("base64url apply(binary): want AP9/gAH%%2Bqw%%3D%%3D, got %s", out)
	}
}

func TestTransform_Netbios_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("hello"),
		{0x00, 0xFF, 0x7F, 0x80},
	}
	for _, in := range inputs {
		roundTripCase(t, "netbios", []Transform{{Op: "netbios"}}, in)
	}
}

func TestTransform_Netbios_PythonCompatible(t *testing.T) {
	// Python: ''.join([chr((c >> 4) + 0x61) + chr((c & 0xF) + 0x61) for c in b"A"])
	//       = chr(0x61 + 4) + chr(0x61 + 1) = "eb"
	c := &Container{Transforms: []Transform{{Op: "netbios"}}}
	out, err := c.Apply([]byte("A"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if string(out) != "eb" {
		t.Errorf("netbios apply: want eb, got %s", out)
	}
}

func TestTransform_Netbios_AllByteValuesRoundTrip(t *testing.T) {
	// Mirrors TestNetbiosTransform::test_all_byte_values_roundtrip.
	all := make([]byte, 256)
	for i := 0; i < 256; i++ {
		all[i] = byte(i)
	}
	roundTripCase(t, "netbios-all-bytes", []Transform{{Op: "netbios"}}, all)
}

func TestTransform_NetbiosU_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("hello"),
		{0x00, 0xFF, 0x7F, 0x80},
	}
	for _, in := range inputs {
		roundTripCase(t, "netbiosu", []Transform{{Op: "netbiosu"}}, in)
	}
}

func TestTransform_NetbiosU_PythonCompatible(t *testing.T) {
	// Python: chr((ord('A') >> 4) + 0x41) + chr((ord('A') & 0xF) + 0x41) = "EB"
	c := &Container{Transforms: []Transform{{Op: "netbiosu"}}}
	out, err := c.Apply([]byte("A"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if string(out) != "EB" {
		t.Errorf("netbiosu apply: want EB, got %s", out)
	}
}

func TestTransform_NetbiosU_AllByteValuesRoundTrip(t *testing.T) {
	all := make([]byte, 256)
	for i := 0; i < 256; i++ {
		all[i] = byte(i)
	}
	roundTripCase(t, "netbiosu-all-bytes", []Transform{{Op: "netbiosu"}}, all)
}

func TestTransform_Mask_RoundTrip(t *testing.T) {
	roundTripCase(t, "mask", []Transform{{Op: "mask", Key: "a5"}},
		[]byte("hello world"))
	roundTripCase(t, "mask-binary", []Transform{{Op: "mask", Key: "42"}},
		[]byte{0x00, 0xFF, 0x7F, 0x80, 0x42})
}

func TestTransform_Mask_PythonCompatible(t *testing.T) {
	// Python: ''.join([chr(c ^ 0xa5) for c in b"A"]) -> chr(0x41 ^ 0xa5) = chr(0xe4)
	c := &Container{Transforms: []Transform{{Op: "mask", Key: "a5"}}}
	out, err := c.Apply([]byte("A"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(out) != 1 || out[0] != 0xE4 {
		t.Errorf("mask apply: want [0xE4], got %v", out)
	}
}

func TestTransform_Mask_InvalidKey(t *testing.T) {
	c := &Container{Transforms: []Transform{{Op: "mask", Key: ""}}}
	if _, err := c.Apply([]byte("x")); err == nil {
		t.Error("expected error for empty key")
	}
	c = &Container{Transforms: []Transform{{Op: "mask", Key: "zz"}}}
	if _, err := c.Apply([]byte("x")); err == nil {
		t.Error("expected error for non-hex key")
	}
}

func TestTransform_Prepend_RoundTrip(t *testing.T) {
	// prepend/append Value is base64-encoded bytes (see Transform doc).
	roundTripCase(t, "prepend",
		[]Transform{{Op: "prepend", Value: base64.StdEncoding.EncodeToString([]byte("SESSION="))}},
		[]byte("payload"))
}

func TestTransform_Append_RoundTrip(t *testing.T) {
	roundTripCase(t, "append",
		[]Transform{{Op: "append", Value: base64.StdEncoding.EncodeToString([]byte(";end"))}},
		[]byte("payload"))
}

func TestTransform_Prepend_HighBitBytesPreserved(t *testing.T) {
	// Python profile declares prepend("caf\xe9") as 4 latin-1 bytes. The
	// serializer base64-encodes it (b"caf\xe9" -> "Y2Fm6Q==") so the
	// length survives the JSON UTF-8 round-trip. The Go apply must decode
	// and concat the raw 4 bytes, not the 5-byte UTF-8 expansion.
	raw := []byte{'c', 'a', 'f', 0xE9}
	c := &Container{Transforms: []Transform{
		{Op: "prepend", Value: "Y2Fm6Q=="},
	}}
	out, err := c.Apply([]byte("payload"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := append([]byte{}, raw...)
	want = append(want, []byte("payload")...)
	if !bytes.Equal(out, want) {
		t.Errorf("apply high-bit prepend: want %x got %x", want, out)
	}
	// Reverse must strip exactly 4 bytes, not 5.
	rev, err := c.Reverse(out)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !bytes.Equal(rev, []byte("payload")) {
		t.Errorf("reverse high-bit prepend: want %q got %q", "payload", rev)
	}
}

func TestTransform_Print_Identity(t *testing.T) {
	c := &Container{Transforms: []Transform{{Op: "print"}}}
	in := []byte("unchanged")
	out, err := c.Apply(in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("print forward: expected identity, got %s", out)
	}
	out, err = c.Reverse(in)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("print reverse: expected identity, got %s", out)
	}
}

// Composed: base64 -> prepend "SESSION=" -> mask "a5"
func TestTransform_Composed_RoundTrip(t *testing.T) {
	c := &Container{Transforms: []Transform{
		{Op: "base64"},
		{Op: "prepend", Value: base64.StdEncoding.EncodeToString([]byte("SESSION="))},
		{Op: "mask", Key: "a5"},
	}}
	in := []byte{0x00, 0x01, 0x02, 0xFE, 0xFF, 0xA5, 0x5A}
	forward, err := c.Apply(in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	reverse, err := c.Reverse(forward)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !bytes.Equal(reverse, in) {
		t.Errorf("composed round-trip mismatch\n want %x\n  got %x", in, reverse)
	}
}

func TestTransform_Ordering_EncodeBeforeMask(t *testing.T) {
	// Forward applies in declared order; reverse applies in reverse order.
	// A broken inverse would surface here.
	in := []byte("abc")
	c := &Container{Transforms: []Transform{
		{Op: "prepend", Value: base64.StdEncoding.EncodeToString([]byte("hdr="))},
		{Op: "base64"},
	}}
	forward, err := c.Apply(in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Expected: base64(b"hdr=abc") = "aGRyPWFiYw=="
	if string(forward) != "aGRyPWFiYw==" {
		t.Errorf("ordered apply: want aGRyPWFiYw==, got %s", forward)
	}
	rev, err := c.Reverse(forward)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !bytes.Equal(rev, in) {
		t.Errorf("ordered reverse mismatch: want %s got %s", in, rev)
	}
}

// -- Terminator round-trip tests ------------------------------------------------

func mkRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func TestTerminator_Header_RoundTrip(t *testing.T) {
	data := []byte("abc123==")
	req := mkRequest(t, "GET", "http://host/x")
	if err := StoreTerminator(req, data, Terminator{Type: "header", Arg: "X-Session"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// Synthesize the response the server would bounce back — same header.
	resp := &http.Response{Header: http.Header{}, Request: req}
	resp.Header.Set("X-Session", req.Header.Get("X-Session"))
	out, err := ExtractTerminator(resp, Terminator{Type: "header", Arg: "X-Session"}, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("header round-trip: want %q got %q", data, out)
	}
}

func TestTerminator_Cookie_Header_RoundTrip(t *testing.T) {
	// Cookie headers get URL-encoded on store; the extractor unquotes.
	data := []byte("session=abc def/xyz")
	req := mkRequest(t, "GET", "http://host/x")
	if err := StoreTerminator(req, data, Terminator{Type: "header", Arg: "Cookie"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// The stored cookie value must be URL-encoded.
	stored := req.Header.Get("Cookie")
	if stored == string(data) {
		t.Error("expected cookie value to be URL-encoded, got raw")
	}
	resp := &http.Response{Header: http.Header{}, Request: req}
	resp.Header.Set("Cookie", stored)
	out, err := ExtractTerminator(resp, Terminator{Type: "header", Arg: "Cookie"}, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("cookie round-trip: want %q got %q", data, out)
	}
}

func TestTerminator_Print_RoundTrip(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0xFF}
	req := mkRequest(t, "POST", "http://host/x")
	if err := StoreTerminator(req, data, Terminator{Type: "print"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// Read back the request body as the server would see it, then feed it
	// into the response-side extractor (same shape).
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read req body: %v", err)
	}
	if !bytes.Equal(reqBody, data) {
		t.Errorf("print store: want %x got %x", data, reqBody)
	}
	resp := &http.Response{
		Body:    io.NopCloser(bytes.NewReader(reqBody)),
		Header:  http.Header{},
		Request: req,
	}
	out, err := ExtractTerminator(resp, Terminator{Type: "print"}, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("print round-trip: want %x got %x", data, out)
	}
}

func TestTerminator_Parameter_RoundTrip(t *testing.T) {
	data := []byte("abc+def=123/zzz")
	req := mkRequest(t, "GET", "http://host/x")
	if err := StoreTerminator(req, data, Terminator{Type: "parameter", Arg: "id"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// Verify URL encoding actually happened.
	if !strings.Contains(req.URL.RawQuery, "id=") {
		t.Errorf("expected id= in query, got %q", req.URL.RawQuery)
	}
	resp := &http.Response{Header: http.Header{}, Request: req}
	out, err := ExtractTerminator(resp, Terminator{Type: "parameter", Arg: "id"}, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("param round-trip: want %q got %q", data, out)
	}
}

func TestTerminator_URIAppend_RoundTrip(t *testing.T) {
	data := []byte("abc def/xyz")
	req := mkRequest(t, "GET", "http://host/base/")
	if err := StoreTerminator(req, data, Terminator{Type: "uri-append"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// The path must have been extended with URL-encoded bytes.
	if req.URL.Path == "/base/" {
		t.Error("expected path to be extended by uri-append")
	}
	resp := &http.Response{Header: http.Header{}, Request: req}
	out, err := ExtractTerminator(resp, Terminator{Type: "uri-append"}, []string{"/base/"})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("uri-append round-trip: want %q got %q", data, out)
	}
}

// -- ResolveStagerURIs ---------------------------------------------------------

func TestResolveStagerURIs_NilFallback(t *testing.T) {
	s1, s2 := ResolveStagerURIs(nil)
	if s1 != "/stage1" || s2 != "/stage2" {
		t.Errorf("nil fallback: got %s/%s", s1, s2)
	}
}

func TestResolveStagerURIs_MissingStagerSection(t *testing.T) {
	mp := &MalleableProfile{Sections: map[string]Section{}}
	s1, s2 := ResolveStagerURIs(mp)
	if s1 != "/stage1" || s2 != "/stage2" {
		t.Errorf("missing stager: got %s/%s", s1, s2)
	}
}

func TestResolveStagerURIs_TwoURIs(t *testing.T) {
	mp := &MalleableProfile{Sections: map[string]Section{
		"stager": {Client: ClientBlock{URIs: []string{"/a.php", "/b.php"}}},
	}}
	s1, s2 := ResolveStagerURIs(mp)
	if s1 != "/a.php" || s2 != "/b.php" {
		t.Errorf("two uris: got %s/%s", s1, s2)
	}
}

func TestResolveStagerURIs_SingleURI(t *testing.T) {
	mp := &MalleableProfile{Sections: map[string]Section{
		"stager": {Client: ClientBlock{URIs: []string{"/only.php"}}},
	}}
	s1, s2 := ResolveStagerURIs(mp)
	if s1 != "/only.php" || s2 != "/only.php" {
		t.Errorf("single uri: got %s/%s", s1, s2)
	}
}

// -- Legacy fallback pinned ----------------------------------------------------

func TestNewMalleableHttpMessageSender_EmptyProfile_LegacyOnly(t *testing.T) {
	// Empty MALLEABLE_PROFILE must leave the sender in legacy mode so the
	// plain HTTP listener keeps working even in the malleable-tagged build.
	sender, err := NewMalleableHttpMessageSender("example.com", nil, "/news.php,/admin/get.php|Mozilla|", "", "session", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sender.malleable != nil {
		t.Error("expected malleable to be nil when blob is empty")
	}
	if len(sender.TaskURIs) != 2 {
		t.Errorf("expected 2 task URIs, got %v", sender.TaskURIs)
	}
	if sender.Server != "http://example.com" {
		t.Errorf("server normalization: %q", sender.Server)
	}
}

func TestNewMalleableHttpMessageSender_WithProfile(t *testing.T) {
	payload := map[string]any{
		"v":      1,
		"sleep":  1000,
		"jitter": 0,
		"sections": map[string]any{
			"stager": map[string]any{
				"client": map[string]any{
					"verb": "GET",
					"uris": []string{"/s.php"},
					"metadata": map[string]any{
						"transforms": []any{},
						"terminator": map[string]string{"type": "print"},
					},
				},
				"server": map[string]any{
					"output": map[string]any{
						"transforms": []any{},
						"terminator": map[string]string{"type": "print"},
					},
				},
			},
			"get":  map[string]any{},
			"post": map[string]any{},
		},
	}
	b64 := helperEncodeB64(t, payload)
	sender, err := NewMalleableHttpMessageSender("http://host", nil, "", b64, "session", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	mp, ok := sender.malleable.(*MalleableProfile)
	if !ok || mp == nil {
		t.Fatalf("expected *MalleableProfile, got %T", sender.malleable)
	}
	if mp.V != 1 || mp.Sleep != 1000 {
		t.Errorf("parsed values wrong: %+v", mp)
	}
}

func TestNewHttpMessageSender_PlainDoesNotParseMalleable(t *testing.T) {
	// The base constructor must never touch a malleable blob — it's
	// the legacy constructor used by plain-http builds and by malleable
	// builds as the underlying allocator.
	sender := NewHttpMessageSender("example.com", nil, "/a.php|UA|", "session", nil)
	if sender.malleable != nil {
		t.Error("base NewHttpMessageSender must leave malleable nil")
	}
}

// Sanity: URL parsing doesn't get tripped up on empty params map.
func TestStoreTerminator_ParameterKeepsOtherQuery(t *testing.T) {
	req := mkRequest(t, "GET", "http://host/x?existing=1")
	if err := StoreTerminator(req, []byte("data"), Terminator{Type: "parameter", Arg: "id"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	q, _ := url.ParseQuery(req.URL.RawQuery)
	if q.Get("existing") != "1" || q.Get("id") != "data" {
		t.Errorf("parameter clobbered existing query: %v", q)
	}
}

// TestStoreTerminator_Cookie_SpaceEncodedAsPercent20 pins Fix 4 (cookie
// encoding parity with Python's unquote_to_bytes). url.QueryEscape would
// encode a space as '+', which Python's server-side extractor does NOT
// decode back to ' ' — so the round-trip diverges. PathEscape is the
// right call; a space must become %20.
func TestStoreTerminator_Cookie_SpaceEncodedAsPercent20(t *testing.T) {
	req := mkRequest(t, "GET", "http://host/x")
	if err := StoreTerminator(req, []byte("a b"), Terminator{Type: "header", Arg: "Cookie"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	got := req.Header.Get("Cookie")
	if got != "a%20b" {
		t.Errorf("cookie space encoding: want %q got %q", "a%20b", got)
	}
	// Non-Cookie headers keep raw bytes (no encoding at all).
	req2 := mkRequest(t, "GET", "http://host/x")
	if err := StoreTerminator(req2, []byte("a b"), Terminator{Type: "header", Arg: "X-Other"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := req2.Header.Get("X-Other"); got != "a b" {
		t.Errorf("non-cookie header encoding: want %q got %q", "a b", got)
	}
}

// TestExtractTerminator_URIAppend_StripsLongestRegisteredPrefix pins Fix 3
// against the Python reference at transaction.py:489-497. Registered URI
// "/admin/" with actual path "/admin/ABC%2FDEF" must yield "ABC/DEF", NOT
// the last slash segment ("DEF") that the previous implementation returned.
func TestExtractTerminator_URIAppend_StripsLongestRegisteredPrefix(t *testing.T) {
	req := mkRequest(t, "GET", "http://host/admin/ABC%2FDEF")
	resp := &http.Response{Header: http.Header{}, Request: req}
	out, err := ExtractTerminator(resp, Terminator{Type: "uri-append"}, []string{"/admin/"})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if string(out) != "ABC/DEF" {
		t.Errorf("uri-append extract: want %q got %q", "ABC/DEF", out)
	}
}

// TestExtractTerminator_URIAppend_PicksLongestURI verifies the tie-breaker
// when multiple registered URIs match: the longest prefix wins.
func TestExtractTerminator_URIAppend_PicksLongestURI(t *testing.T) {
	// Both "/a/" and "/a/b/" would match, but the longest must win so we
	// return "tail", not "b/tail".
	req := mkRequest(t, "GET", "http://host/a/b/tail")
	resp := &http.Response{Header: http.Header{}, Request: req}
	out, err := ExtractTerminator(resp, Terminator{Type: "uri-append"},
		[]string{"/a/", "/a/b/"})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if string(out) != "tail" {
		t.Errorf("longest-prefix tiebreak: want %q got %q", "tail", out)
	}
}

// TestExtractTerminator_URIAppend_NoRegisteredURIMatches returns an error
// rather than silently returning garbage when none of the registered URIs
// appear in the response path.
func TestExtractTerminator_URIAppend_NoRegisteredURIMatches(t *testing.T) {
	req := mkRequest(t, "GET", "http://host/other/ABC")
	resp := &http.Response{Header: http.Header{}, Request: req}
	_, err := ExtractTerminator(resp, Terminator{Type: "uri-append"},
		[]string{"/admin/"})
	if err == nil {
		t.Error("expected error when no URI matches")
	}
}

// TestSend_NilMetadata_FallsBackToLegacy pins Fix 1 (critical):
// when the chosen section's metadata container is nil, sendMalleable must
// fall back to sendLegacy rather than silently dropping the routing
// packet. We verify by firing at a test server and checking the request
// took the legacy shape (session= cookie, no transform-stored header).
func TestSend_NilMetadata_FallsBackToLegacy(t *testing.T) {
	var gotCookie string
	var gotMethod string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok")) // an empty legacy 200 is ErrEmptyResponse
	}))
	defer srv.Close()

	// Malleable profile whose get section has metadata: nil. Legacy
	// pipe-split profile supplies a TaskURIs fallback list.
	mp := &MalleableProfile{
		V: 1,
		Sections: map[string]Section{
			"get": {
				Client: ClientBlock{Verb: "GET", URIs: []string{"/news.php"}, Metadata: nil},
				Server: ServerBlock{Output: &Container{Terminator: Terminator{Type: "print"}}},
			},
		},
	}
	sender := &HttpMessageSender{
		Headers:   map[string]string{},
		malleable: mp,
		TaskURIs:  []string{"/legacy.php"},
		Server:    srv.URL,
	}
	if _, err := sender.Send(RequestTasking, []byte("SMALL")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Legacy tasking path: GET with session= cookie on the legacy URI.
	if gotMethod != "GET" {
		t.Errorf("legacy method: want GET got %s", gotMethod)
	}
	if gotPath != "/legacy.php" {
		t.Errorf("legacy path: want /legacy.php got %s", gotPath)
	}
	if !strings.HasPrefix(gotCookie, "session=") {
		t.Errorf("legacy cookie: want session= prefix, got %q", gotCookie)
	}
}

// TestSend_POST_UsesOutputContainer pins the Empire convention:
// for POST, the routing packet rides on client.output (transforms +
// terminator), not on client.metadata/id. The PS/Python reference agents
// behave this way, and the Empire malleable listener's two-part extract
// concatenates id+output so only one slot needs to carry data.
func TestSend_POST_UsesOutputContainer(t *testing.T) {
	var gotBody []byte
	var gotSnParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSnParam = r.URL.Query().Get("sn")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Mirrors Amazon profile's http-post client:
	//   id { parameter "sn"; }    -- Metadata (ignored by our agent)
	//   output { base64; print; } -- Output (carries routing packet)
	mp := &MalleableProfile{
		V: 1,
		Sections: map[string]Section{
			"post": {
				Client: ClientBlock{
					Verb: "POST",
					URIs: []string{"/amzn.us.sr.aps"},
					Metadata: &Container{
						Transforms: []Transform{},
						Terminator: Terminator{Type: "parameter", Arg: "sn"},
					},
					Output: &Container{
						Transforms: []Transform{{Op: "base64"}},
						Terminator: Terminator{Type: "print"},
					},
				},
				Server: ServerBlock{Output: &Container{Terminator: Terminator{Type: "print"}}},
			},
		},
	}
	sender := &HttpMessageSender{
		Headers:   map[string]string{},
		malleable: mp,
		Server:    srv.URL,
	}
	packet := []byte("THIS_IS_A_ROUTING_PACKET_PAYLOAD")
	if _, err := sender.Send(RequestData, packet); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Body must contain the base64-encoded routing packet (output terminator
	// is PRINT, transforms = [base64]).
	wantB64 := base64.StdEncoding.EncodeToString(packet)
	if string(gotBody) != wantB64 {
		t.Errorf("POST body: want %q got %q", wantB64, string(gotBody))
	}
	// The `sn` parameter (id / Metadata terminator) must be empty — the
	// agent must NOT also place the routing packet there. Doing so would
	// double-send and the server's concat would fail AEAD validation.
	if gotSnParam != "" {
		t.Errorf("sn parameter should be empty, got %q", gotSnParam)
	}
}

// TestSend_POST_NilOutput_FallsBackToLegacy pins the same fallback
// semantics we have for GET: if the POST section's output container is
// missing, drop to the legacy pipe-split path rather than silently dropping
// the routing packet.
func TestSend_POST_NilOutput_FallsBackToLegacy(t *testing.T) {
	var gotMethod string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok")) // an empty legacy 200 is ErrEmptyResponse
	}))
	defer srv.Close()

	mp := &MalleableProfile{
		V: 1,
		Sections: map[string]Section{
			"post": {
				Client: ClientBlock{Verb: "POST", URIs: []string{"/malleable.php"}, Output: nil},
				Server: ServerBlock{Output: &Container{Terminator: Terminator{Type: "print"}}},
			},
		},
	}
	sender := &HttpMessageSender{
		Headers:   map[string]string{},
		malleable: mp,
		TaskURIs:  []string{"/legacy.php"},
		Server:    srv.URL,
	}
	if _, err := sender.Send(RequestData, []byte("RESULTS")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotMethod != "POST" || gotPath != "/legacy.php" {
		t.Errorf("legacy path: want POST /legacy.php got %s %s", gotMethod, gotPath)
	}
}

// TestSend_ProfileHeadersOverrideSenderHeaders pins Fix 2 — the
// profile's declared User-Agent must win over the sender's default.
func TestSend_ProfileHeadersOverrideSenderHeaders(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mp := &MalleableProfile{
		V: 1,
		Sections: map[string]Section{
			"get": {
				Client: ClientBlock{
					Verb:    "GET",
					URIs:    []string{"/news.php"},
					Headers: map[string]string{"User-Agent": "ProfileUA"},
					Metadata: &Container{
						Transforms: []Transform{},
						Terminator: Terminator{Type: "header", Arg: "X-Session"},
					},
				},
				Server: ServerBlock{Output: &Container{Terminator: Terminator{Type: "print"}}},
			},
		},
	}
	sender := &HttpMessageSender{
		Headers:   map[string]string{"User-Agent": "SenderUA"},
		malleable: mp,
		TaskURIs:  []string{"/legacy.php"},
		Server:    srv.URL,
	}
	if _, err := sender.Send(RequestTasking, []byte("SMALL")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotUA != "ProfileUA" {
		t.Errorf("UA override: want ProfileUA got %q", gotUA)
	}
}

func idleGetProfile(serverOutput *Container) *MalleableProfile {
	return &MalleableProfile{
		V: 1,
		Sections: map[string]Section{
			"get": {
				Client: ClientBlock{
					Verb: "GET", URIs: []string{"/news.php"},
					Metadata: &Container{Transforms: []Transform{}, Terminator: Terminator{Type: "parameter", Arg: "sn"}},
				},
				Server: ServerBlock{Output: serverOutput},
			},
		},
	}
}

func wrapPrePost() *Container {
	return &Container{
		Transforms: []Transform{
			{Op: "prepend", Value: base64.StdEncoding.EncodeToString([]byte("<!--PRE-->"))},
			{Op: "append", Value: base64.StdEncoding.EncodeToString([]byte("<!--POST-->"))},
		},
		Terminator: Terminator{Type: "print"},
	}
}

func printOutput() *Container { return &Container{Terminator: Terminator{Type: "print"}} }

// TestSend_GetSectionIdleAndTasking pins the malleable listener's idle answer:
// construct_server with no output yields empty bytes once the profile's
// transforms are reversed, whatever terminator carried them. That is "no
// tasking", not an error; anything non-empty is tasking.
func TestSend_GetSectionIdleAndTasking(t *testing.T) {
	cases := []struct {
		name   string
		body   []byte
		output *Container
		want   []byte // nil = idle
	}{
		{"print terminator, zero-byte 200", nil, printOutput(), nil},
		{"prepend/append reversing to empty", []byte("<!--PRE--><!--POST-->"), wrapPrePost(), nil},
		{"prepend/append around tasking", []byte("<!--PRE-->TASKING<!--POST-->"), wrapPrePost(), []byte("TASKING")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newRecorder(t, 200, tc.body)
			sender := &HttpMessageSender{malleable: idleGetProfile(tc.output), Server: srv.URL}
			data, err := sender.Send(RequestTasking, []byte("POLL"))
			if err != nil || !bytes.Equal(data, tc.want) || (tc.want == nil && data != nil) {
				t.Fatalf("want (%q, nil) got (%q, %v)", tc.want, data, err)
			}
		})
	}
}

// TestSend_GetSection401IsSessionUnknown: no os.Exit in comms any more.
func TestSend_GetSection401IsSessionUnknown(t *testing.T) {
	srv, _ := newRecorder(t, 401, nil)
	sender := &HttpMessageSender{malleable: idleGetProfile(printOutput()), Server: srv.URL}
	if _, err := sender.Send(RequestTasking, []byte("POLL")); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("want ErrSessionUnknown got %v", err)
	}
}

// TestNewMalleableHttpMessageSender_LegacyCarriesCookieAndDefaultPage pins
// the malleable build's legacy fallback end to end: the cookie name and the
// default page given to NewMalleableHttpMessageSender must reach sendLegacy.
func TestNewMalleableHttpMessageSender_LegacyCarriesCookieAndDefaultPage(t *testing.T) {
	page := []byte("<html>default</html>")
	srv, seen := newRecorder(t, 200, page)
	sender, err := NewMalleableHttpMessageSender(srv.URL, nil, "/news.php|UA|", "", "PHPSESSID", page)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	data, err := sender.Send(RequestTasking, []byte("POLL"))
	if err != nil || data != nil {
		t.Fatalf("default page must be idle, got (%q, %v)", data, err)
	}
	if got := (*seen)[0].cookie; !strings.HasPrefix(got, "PHPSESSID=") {
		t.Fatalf("cookie name not carried through: %q", got)
	}
}

// Non-200s other than 401 on the malleable path are errors (misses), never
// parsed as output.
func TestSend_GetSectionNon200IsAnError(t *testing.T) {
	for _, status := range []int{500, 404} {
		srv, _ := newRecorder(t, status, nil)
		sender := &HttpMessageSender{malleable: idleGetProfile(printOutput()), Server: srv.URL}
		_, err := sender.Send(RequestTasking, []byte("POLL"))
		if err == nil || errors.Is(err, ErrSessionUnknown) {
			t.Fatalf("status %d: want a plain error, got %v", status, err)
		}
	}
}

// Output that cannot be reversed (here: not base64) is an error, not idle.
func TestSend_GetSectionUnreversibleOutputIsAnError(t *testing.T) {
	srv, _ := newRecorder(t, 200, []byte("not*base64!"))
	out := &Container{Transforms: []Transform{{Op: "base64"}}, Terminator: Terminator{Type: "print"}}
	sender := &HttpMessageSender{malleable: idleGetProfile(out), Server: srv.URL}
	if data, err := sender.Send(RequestTasking, []byte("POLL")); err == nil {
		t.Fatalf("want an error, got (%q, nil)", data)
	}
}

// A 401 on a results POST through the post section is ErrSessionUnknown too.
func TestSend_PostSection401IsSessionUnknown(t *testing.T) {
	srv, _ := newRecorder(t, 401, nil)
	mp := &MalleableProfile{V: 1, Sections: map[string]Section{
		"post": {
			Client: ClientBlock{Verb: "POST", URIs: []string{"/submit.php"}, Output: &Container{Terminator: Terminator{Type: "print"}}},
			Server: ServerBlock{Output: &Container{Terminator: Terminator{Type: "print"}}},
		},
	}}
	sender := &HttpMessageSender{malleable: mp, Server: srv.URL}
	if _, err := sender.Send(RequestData, []byte("RESULT")); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("want ErrSessionUnknown got %v", err)
	}
}
