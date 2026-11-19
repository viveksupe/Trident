package test

import (
	"regexp"
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
