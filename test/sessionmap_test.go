package test

import (
	"path/filepath"
	"testing"

	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/sessionmap"
)

func TestSessionMapRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	s, err := sessionmap.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := model.NewRouteKey("alice", "chat-7")
	if err := s.Put(sessionmap.Entry{
		UserID: key.UserID, ChatID: key.ChatID, ActorName: "ot-uabc-cdef",
	}); err != nil {
		t.Fatal(err)
	}
	name, ok, err := s.LatestActor(key)
	if err != nil || !ok || name != "ot-uabc-cdef" {
		t.Fatalf("round trip failed: %q %v %v", name, ok, err)
	}

	// Upsert changes the actor name.
	if err := s.Put(sessionmap.Entry{UserID: key.UserID, ChatID: key.ChatID, ActorName: "ot-new"}); err != nil {
		t.Fatal(err)
	}
	if name, _, _ = s.LatestActor(key); name != "ot-new" {
		t.Fatalf("upsert failed: %q", name)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: durable.
	s2, err := sessionmap.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if name, ok, _ = s2.LatestActor(key); !ok || name != "ot-new" {
		t.Fatalf("not durable: %q %v", name, ok)
	}
}

func TestSessionMapPrune(t *testing.T) {
	s, err := sessionmap.Open(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	k1 := model.NewRouteKey("u", "c1")
	k2 := model.NewRouteKey("u", "c2")
	for _, k := range []model.RouteKey{k1, k2} {
		_ = s.Put(sessionmap.Entry{UserID: k.UserID, ChatID: k.ChatID, ActorName: "x"})
	}
	keep := map[model.RouteKey]sessionmap.Entry{
		k1: {UserID: k1.UserID, ChatID: k1.ChatID, ActorName: "x"},
	}
	if err := s.Prune(keep); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LatestActor(k1); !ok {
		t.Fatal("kept entry was pruned")
	}
	if _, ok, _ := s.LatestActor(k2); ok {
		t.Fatal("stale entry survived prune")
	}
}
