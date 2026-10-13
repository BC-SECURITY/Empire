package comms

import "errors"

// Outcomes Send reports through its error value. The agent classifies polls
// on these, so comms never exits the process itself.
var (
	ErrSessionUnknown = errors.New("server no longer knows this session (401)")
	ErrEmptyResponse  = errors.New("empty 200 response")
	ErrNoTaskURIs     = errors.New("profile has no task URIs")
)

// PollResult is what one tasking poll meant for the agent loop.
type PollResult int

const (
	PollIdle           PollResult = iota // no tasking (Send returned nil, nil)
	PollTasking                          // a body to decode as a routing packet
	PollUnknownSession                   // 401: the server no longer knows this session
	PollMissed                           // any other error from Send: transport, non-200, empty legacy 200, profile/transform failure
)

// ClassifyPoll maps Send's result for a tasking request onto PollResult.
func ClassifyPoll(data []byte, err error) PollResult {
	if errors.Is(err, ErrSessionUnknown) {
		return PollUnknownSession
	}
	if err != nil {
		return PollMissed
	}
	if len(data) == 0 {
		return PollIdle
	}
	return PollTasking
}

// PollStep updates *missed for one poll and reports whether to keep polling.
// processedOK says whether a PollTasking body decoded (ignored otherwise);
// an undecodable 200 counts as a miss. lostLimit <= 0 disables the limit;
// PollUnknownSession always stops.
func PollStep(result PollResult, processedOK bool, lostLimit int, missed *int) bool {
	switch result {
	case PollIdle:
		*missed = 0
		return true
	case PollTasking:
		if processedOK {
			*missed = 0
			return true
		}
	case PollUnknownSession:
		return false
	}
	*missed++
	return !(lostLimit > 0 && *missed >= lostLimit)
}
