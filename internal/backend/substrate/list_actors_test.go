package substrate

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/viveksupe/Trident/third_party/ateapi"
)

// TestListActorsPaginatesAcrossPages: ListActors must follow NextPageToken
// to the end (S9: the old single-page call fed restart reconcile a truncated
// list, which pruned live sessions).
func TestListActorsPaginatesAcrossPages(t *testing.T) {
	f := &fakeControl{listPages: map[string]*ateapi.ListActorsResponse{
		"": {
			Actors:        []*ateapi.Actor{runningActor("test", "a"), runningActor("test", "b")},
			NextPageToken: "page-2",
		},
		"page-2": {
			Actors: []*ateapi.Actor{runningActor("test", "c")},
		},
	}}
	l := &Lifecycle{client: newTestAPIClient(f)}

	actors, err := l.ListActors(context.Background(), "test")
	if err != nil {
		t.Fatalf("ListActors: %v", err)
	}
	var names []string
	for _, a := range actors {
		names = append(names, a.GetMetadata().GetName())
	}
	if want := []string{"a", "b", "c"}; !slices.Equal(names, want) {
		t.Fatalf("actors = %v, want %v", names, want)
	}
	if want := []string{"", "page-2"}; !slices.Equal(f.listTokens, want) {
		t.Fatalf("page tokens = %v, want %v", f.listTokens, want)
	}
}

// TestListActorsRefusesEmptyPageWithContinuation: a non-empty token behind a
// zero-actor page cannot be proven complete — it must be an error, never a
// short list (S9).
func TestListActorsRefusesEmptyPageWithContinuation(t *testing.T) {
	f := &fakeControl{listPages: map[string]*ateapi.ListActorsResponse{
		"": {NextPageToken: "more"}, // token, no actors: partial listing
	}}
	l := &Lifecycle{client: newTestAPIClient(f)}

	actors, err := l.ListActors(context.Background(), "test")
	if err == nil {
		t.Fatal("expected an error for an empty page with a continuation token")
	}
	if !strings.Contains(err.Error(), "possibly-partial") {
		t.Fatalf("error should say the listing may be partial: %v", err)
	}
	if actors != nil {
		t.Fatalf("must not surface a partial listing, got %d actors", len(actors))
	}
}

// TestListActorsPageFailureYieldsNoPartial: a failure on page 2 must not
// return page 1's actors as if they were everything.
func TestListActorsPageFailureYieldsNoPartial(t *testing.T) {
	f := &fakeControl{listPages: map[string]*ateapi.ListActorsResponse{
		"": { // "page-2" missing → the fake answers InvalidArgument
			Actors:        []*ateapi.Actor{runningActor("test", "a")},
			NextPageToken: "page-2",
		},
	}}
	l := &Lifecycle{client: newTestAPIClient(f)}

	actors, err := l.ListActors(context.Background(), "test")
	if err == nil {
		t.Fatal("expected the page-2 failure to propagate")
	}
	if actors != nil {
		t.Fatalf("partial listing leaked after page failure: %d actors", len(actors))
	}
}

// TestListActorsRefusesRepeatedToken: a server echoing the same page token
// would spin the loop forever; refuse instead.
func TestListActorsRefusesRepeatedToken(t *testing.T) {
	f := &fakeControl{listPages: map[string]*ateapi.ListActorsResponse{
		"": {
			Actors:        []*ateapi.Actor{runningActor("test", "a")},
			NextPageToken: "page-2",
		},
		"page-2": {
			Actors:        []*ateapi.Actor{runningActor("test", "b")},
			NextPageToken: "page-2", // echoes the request token
		},
	}}
	l := &Lifecycle{client: newTestAPIClient(f)}

	actors, err := l.ListActors(context.Background(), "test")
	if err == nil {
		t.Fatal("expected an error for a repeated page token")
	}
	if actors != nil {
		t.Fatalf("must not return actors alongside the error, got %d", len(actors))
	}
}

// TestListActorsSinglePageIsOneRequest: the common case (no truncation)
// stays a single RPC with Options omitted.
func TestListActorsSinglePageIsOneRequest(t *testing.T) {
	f := &fakeControl{listPages: map[string]*ateapi.ListActorsResponse{
		"": {Actors: []*ateapi.Actor{runningActor("test", "only")}},
	}}
	l := &Lifecycle{client: newTestAPIClient(f)}

	actors, err := l.ListActors(context.Background(), "test")
	if err != nil {
		t.Fatalf("ListActors: %v", err)
	}
	if len(actors) != 1 || len(f.listTokens) != 1 || f.listTokens[0] != "" {
		t.Fatalf("actors=%d tokens=%v, want 1 actor and one tokenless request", len(actors), f.listTokens)
	}
}
