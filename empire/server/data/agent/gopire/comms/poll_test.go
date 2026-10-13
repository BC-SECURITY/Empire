package comms

import (
	"errors"
	"testing"
)

func TestClassifyPoll(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		err  error
		want PollResult
	}{
		{"idle", nil, nil, PollIdle},
		{"tasking", []byte("routing"), nil, PollTasking},
		{"unknown session", nil, ErrSessionUnknown, PollUnknownSession},
		{"wrapped unknown session", nil, errors.Join(errors.New("ctx"), ErrSessionUnknown), PollUnknownSession},
		{"empty response", nil, ErrEmptyResponse, PollMissed},
		{"no task uris", nil, ErrNoTaskURIs, PollMissed},
		{"transport error", nil, errors.New("dial tcp: refused"), PollMissed},
		{"data with error is still a miss", []byte("x"), errors.New("http 500"), PollMissed},
	}
	for _, c := range cases {
		if got := ClassifyPoll(c.data, c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestPollStep(t *testing.T) {
	cases := []struct {
		name        string
		result      PollResult
		processedOK bool
		lostLimit   int
		missedIn    int
		wantKeep    bool
		wantMissed  int
	}{
		{"idle resets", PollIdle, false, 3, 2, true, 0},
		{"tasking ok resets", PollTasking, true, 3, 2, true, 0},
		{"tasking bad counts", PollTasking, false, 3, 0, true, 1},
		{"tasking bad reaches limit", PollTasking, false, 3, 2, false, 3},
		{"missed counts", PollMissed, false, 3, 0, true, 1},
		{"missed reaches limit", PollMissed, false, 3, 2, false, 3},
		{"limit 0 never stops", PollMissed, false, 0, 99, true, 100},
		{"negative limit never stops", PollMissed, false, -1, 5, true, 6},
		{"unknown session stops without counting", PollUnknownSession, false, 3, 1, false, 1},
	}
	for _, c := range cases {
		missed := c.missedIn
		keep := PollStep(c.result, c.processedOK, c.lostLimit, &missed)
		if keep != c.wantKeep || missed != c.wantMissed {
			t.Errorf("%s: got keep=%v missed=%d want keep=%v missed=%d", c.name, keep, missed, c.wantKeep, c.wantMissed)
		}
	}
}
