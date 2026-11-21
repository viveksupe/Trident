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
// chat; anything non-canonical (unsaved chats, ids with "_" or "." or other
// separators) is hashed instead — a_b and a-b must never map to one actor.
func (k RouteKey) ActorName(prefix string) string {
	if k.ChatID == AdhocChat {
		return fmt.Sprintf("%su%s-adhoc", prefix, Hash8(k.UserID))
	}
	if chat := canonicalSegment(k.ChatID); chat != "" {
		return fmt.Sprintf("%su%s-%s", prefix, Hash8(k.UserID), chat)
	}
	return fmt.Sprintf("%su%s-c%s", prefix, Hash8(k.UserID), Hash8(k.ChatID))
}

// SfKey is an unambiguous singleflight key: LogString's "/" separator made
// user "a/b" + chat "c" collide with user "a" + chat "b/c" (and the collision
// handed one caller the other key's session).
func (k RouteKey) SfKey() string {
	return k.UserID + "\x00" + k.ChatID + "\x00sf"
}

// canonicalSegment returns the id verbatim only when it is already a
// DNS-1123-safe label segment (lowercase alphanumerics + inner dashes, no
// leading/trailing dash, short enough to leave room for the prefix + user
// hash); anything else maps to ""
// (→ the caller hashes).
func canonicalSegment(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" || len(id) > 38 {
		return ""
	}
	if strings.HasPrefix(id, "-") || strings.HasSuffix(id, "-") {
		return ""
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return ""
		}
	}
	return id
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
