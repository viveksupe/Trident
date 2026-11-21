package test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/viveksupe/Trident/internal/model"
)

func TestRouteKeyAdhocFallback(t *testing.T) {
	k := model.NewRouteKey("alice", "")
	if k.ChatID != model.AdhocChat {
		t.Fatalf("missing chat must fall back to adhoc, got %q", k.ChatID)
	}
	k2 := model.NewRouteKey("", "chat")
	if k2.UserID != "single" {
		t.Fatalf("missing user must fall back to single, got %q", k2.UserID)
	}
}

func TestActorNameIsDNSLabel(t *testing.T) {
	dnsLabel := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, tc := range [][2]string{
		{"alice@example.com", "чaт-uuid-123"},
		{"", ""},
		{"user-with/odd@characters", "chat_with_under/underscores"},
	} {
		k := model.NewRouteKey(tc[0], tc[1])
		if !dnsLabel.MatchString(k.ActorName("ot-")) {
			t.Fatalf("actor name %q is not a DNS-1123 label", k.ActorName("ot-"))
		}
	}
}

func TestActorNameStable(t *testing.T) {
	a := model.NewRouteKey("u1", "c1").ActorName("ot-")
	b := model.NewRouteKey("u1", "c1").ActorName("ot-")
	c := model.NewRouteKey("u1", "c2").ActorName("ot-")
	if a != b {
		t.Fatal("same key must map to the same actor name")
	}
	if a == c {
		t.Fatal("different chats must map to different actors")
	}
}

// Collision regression: dnsSafe used to fold "_" and "." into "-", mapping
// user a + chat "b_c" onto user a + chat "b-c" (two chats, one sandbox).
func TestActorNameNoSeparatorCollisions(t *testing.T) {
	a := model.NewRouteKey("u1", "b-c").ActorName("ot-")
	b := model.NewRouteKey("u1", "b_c").ActorName("ot-")
	c := model.NewRouteKey("u1", "b.c").ActorName("ot-")
	if a == b || a == c || b == c {
		t.Fatalf("separator variants must hash to distinct actors: %q %q %q", a, b, c)
	}
	if !strings.HasPrefix(a, "ot-u") {
		t.Fatalf("canonical id should appear verbatim: %q", a)
	}
}

// A canonical UUID chat id stays verbatim (log mapping to Open WebUI chats).
func TestActorNameUUIDVerbatim(t *testing.T) {
	id := "e8622b55-2d4f-4986-99d3-48295ca33797"
	name := model.NewRouteKey("u1", id).ActorName("ot-")
	if !strings.Contains(name, id) {
		t.Fatalf("UUID chat id must appear in the actor name: %q", name)
	}
}
