//go:build !malleable

package comms

// trySendMalleable is a no-op stub for builds without the `malleable` build
// tag — there's no profile, so the caller always falls back to the legacy
// pipe-split path. The malleable-tagged counterpart lives in
// http_malleable.go.
func (sender *HttpMessageSender) trySendMalleable(kind RequestKind, routingPacket []byte) (bool, []byte, error) {
	return false, nil, nil
}
