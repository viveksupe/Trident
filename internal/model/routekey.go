// Package model defines the routing identity shared by the facade and the backends.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// RouteKey identifies one logical session: an Open WebUI user and chat.
// Missing chat ids (unsaved chats) collapse into the per-user "adhoc" session.
type RouteKey struct {
	UserID string
	ChatID string
}

// AdhocChat is the fallback chat id used when Open WebUI sends no X-Session-Id.
const AdhocChat = "adhoc"

// NewRouteKey normalizes raw header values into a RouteKey.
func NewRouteKey(userID, chatID string) RouteKey {
	if chatID == "" {
		chatID = AdhocChat
	}
	if userID == "" {
		userID = "single"
	}
	return RouteKey{UserID: userID, ChatID: chatID}
}

// Hash8 returns a short stable hash of s (first 8 hex chars).
func Hash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// ActorName builds the DNS-1123-safe actor name for this route. Named chats
// (Open WebUI's X-Session-Id, a UUID) appear verbatim so logs map 1:1 to the
// chat; unsaved chats ("adhoc") and unclean session ids fall back to hashes.
func (k RouteKey) ActorName(prefix string) string {
	if k.ChatID == AdhocChat {
		return fmt.Sprintf("%su%s-adhoc", prefix, Hash8(k.UserID))
	}
	if chat := dnsSafe(k.ChatID); chat != "" {
		return fmt.Sprintf("%su%s-%s", prefix, Hash8(k.UserID), chat)
	}
	return fmt.Sprintf("%su%s-c%s", prefix, Hash8(k.UserID), Hash8(k.ChatID))
}

// dnsSafe sanitizes a session id to a DNS-1123-safe segment. Empty result
// means "not representable".
func dnsSafe(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	var b strings.Builder
	lastDash := true // suppress leading dash
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-', r == '_', r == '.', r == ' ':
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
		default:
			// disallowed byte in the id: fall back to hashing entirely
			return ""
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 38 { // prefix + userhash + this must stay ≤63
		return ""
	}
	return out
}

// ActorRef is the substrate-space reference "<atespace>/<actor>".
func (k RouteKey) ActorRef(atespace, prefix string) string {
	return atespace + "/" + k.ActorName(prefix)
}

// LogString renders a redacted-safe key for logs.
func (k RouteKey) LogString() string { return k.UserID + "/" + k.ChatID }

// EscapePathKey percent-encodes a key for embedding in ids (mirrors Open WebUI's
// terminal_id quoting in agent model ids).
func EscapePathKey(s string) string { return url.PathEscape(s) }
