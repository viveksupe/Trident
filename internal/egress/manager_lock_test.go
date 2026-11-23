package egress

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// shardNames finds two actor names for the lock-table tests: sameShard=true
// yields equal shard indices, false yields different ones. Brute-force scan
// makes the tests deterministic and independent of hash internals.
func shardNames(t *testing.T, sameShard bool) (string, string) {
	t.Helper()
	base := "tri-actor-0"
	baseIdx := policyShardIndex(base)
	for i := 1; i <= 100000; i++ {
		cand := fmt.Sprintf("tri-actor-%d", i)
		idx := policyShardIndex(cand)
		if (idx == baseIdx) == sameShard {
			return base, cand
		}
	}
	t.Fatalf("no shard pair found (sameShard=%v)", sameShard)
	return "", ""
}

// TestShardedPolicyLocksSerializeOnCollision: two DIFFERENT actors that
// hash to the same mutex must serialize without deadlocking, and the
// one-actor-one-lock guarantee must hold for repeated locks of the same
// name. Together these prove the sharded table preserves the old per-actor
// lock semantics under collision.
func TestShardedPolicyLocksSerializeOnCollision(t *testing.T) {
	m := &Manager{}
	a, b := shardNames(t, true)

	// Hold the shared shard through actor a; a's colliding partner must
	// NOT be admitted while it is held.
	unlockA := m.lockPolicy(a)
	acquired := make(chan func(), 1)
	go func() { acquired <- m.lockPolicy(b) }()
	select {
	case <-acquired:
		unlockA()
		t.Fatal("same-shard actor acquired a shard already held — exclusion broken")
	case <-time.After(150 * time.Millisecond):
	}

	// Release: the blocked shard user must proceed (no deadlock).
	unlockA()
	select {
	case unlockB := <-acquired:
		unlockB()
	case <-time.After(5 * time.Second):
		t.Fatal("same-shard acquisition deadlocked after release")
	}

	// Same-actor exclusion (one actor = one lock): re-locking the SAME
	// name while it is held must block, exactly as the old map did.
	unlockX := m.lockPolicy(a)
	got := make(chan func(), 1)
	go func() { got <- m.lockPolicy(a) }()
	select {
	case <-got:
		unlockX()
		t.Fatal("same actor acquired its own held policy lock")
	case <-time.After(150 * time.Millisecond):
	}
	unlockX()
	select {
	case unlockAgain := <-got:
		unlockAgain()
	case <-time.After(5 * time.Second):
		t.Fatal("same-actor re-acquisition deadlocked after release")
	}
}

// TestShardedPolicyLocksProceedInParallelAcrossShards: a shard must not be
// held hostage across actors — if different-shard actors serialized behind
// each other, sharding would have degenerated to one global lock.
func TestShardedPolicyLocksProceedInParallelAcrossShards(t *testing.T) {
	m := &Manager{}
	a, b := shardNames(t, false)

	unlockA := m.lockPolicy(a)
	defer unlockA()

	acquired := make(chan func(), 1)
	go func() { acquired <- m.lockPolicy(b) }()
	select {
	case unlockB := <-acquired:
		unlockB()
	case <-time.After(2 * time.Second):
		t.Fatal("cross-shard actor blocked behind an unrelated shard — sharding degenerated to a global lock")
	}
}

// TestPolicyLockTableIsFixedSize: the table is a property of the TYPE
// (array of 256 mutexes), so usage churn cannot grow it, and the unbounded
// per-actor map may not come back (finding R3 regression guard).
func TestPolicyLockTableIsFixedSize(t *testing.T) {
	ty := reflect.TypeOf(Manager{})
	f, ok := ty.FieldByName("policyShards")
	if !ok {
		t.Fatal("policyShards field missing")
	}
	if f.Type.Kind() != reflect.Array || f.Type.Len() != policyLockShards {
		t.Fatalf("policyShards type = %v, want [%d]sync.Mutex", f.Type, policyLockShards)
	}
	if _, ok := ty.FieldByName("policyLocks"); ok {
		t.Fatal("policyLocks (unbounded actor->mutex map) is back — finding R3 regression")
	}

	// Churn through many actors: the table's size is fixed by its type,
	// and every shard index must address it.
	m := &Manager{}
	for i := 0; i < 5000; i++ {
		name := fmt.Sprintf("churn-actor-%d", i)
		if idx := policyShardIndex(name); idx >= policyLockShards {
			t.Fatalf("shard index %d out of range for %q", idx, name)
		}
		m.lockPolicy(name)()
	}
	for i := 0; i < 10000; i++ {
		if idx := policyShardIndex(fmt.Sprintf("actor-%d/%%s", i)); idx >= policyLockShards {
			t.Fatalf("shard index %d out of range", idx)
		}
	}
}
