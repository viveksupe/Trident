package substrate

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/viveksupe/Trident/third_party/ateapi"
)

// fakeControl implements the slice of ateapi.ControlClient the substrate
// code touches. It embeds the interface, so an RPC nobody stubs dispatches
// to a nil interface and panics loudly instead of silently succeeding.
type fakeControl struct {
	ateapi.ControlClient

	mu sync.Mutex

	// actor visibility
	actor            *ateapi.Actor
	getActorCalls    int
	createActorCalls int
	resumeCalls      int

	// egress policy singleton
	policy            *ateapi.EgressPolicy
	getPolicyCalls    int
	createPolicyCalls int
	updatePolicyCalls int
	lastUpdateRules   []*ateapi.EgressRule

	// ListActors pages keyed by the request page token.
	listPages  map[string]*ateapi.ListActorsResponse
	listTokens []string
}

var _ ateapi.ControlClient = (*fakeControl)(nil)

// newTestAPIClient wires an APIClient straight onto the fake (no dial).
func newTestAPIClient(f *fakeControl) *APIClient {
	return &APIClient{ControlClient: f}
}

func (f *fakeControl) GetActor(_ context.Context, _ *ateapi.GetActorRequest, _ ...grpc.CallOption) (*ateapi.Actor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getActorCalls++
	if f.actor == nil {
		return nil, status.Error(codes.NotFound, "actor not found")
	}
	return proto.Clone(f.actor).(*ateapi.Actor), nil
}

func (f *fakeControl) CreateActor(_ context.Context, _ *ateapi.CreateActorRequest, _ ...grpc.CallOption) (*ateapi.Actor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createActorCalls++
	if f.actor != nil {
		return nil, status.Error(codes.AlreadyExists, "actor exists")
	}
	f.actor = runningActor("test", "created")
	return proto.Clone(f.actor).(*ateapi.Actor), nil
}

func (f *fakeControl) ResumeActor(_ context.Context, _ *ateapi.ResumeActorRequest, _ ...grpc.CallOption) (*ateapi.ResumeActorResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumeCalls++
	return &ateapi.ResumeActorResponse{}, nil
}

func (f *fakeControl) GetActorEgressPolicy(_ context.Context, _ *ateapi.GetActorEgressPolicyRequest, _ ...grpc.CallOption) (*ateapi.EgressPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getPolicyCalls++
	if f.policy == nil {
		return nil, status.Error(codes.NotFound, "egress policy not found")
	}
	return proto.Clone(f.policy).(*ateapi.EgressPolicy), nil
}

func (f *fakeControl) CreateActorEgressPolicy(_ context.Context, in *ateapi.CreateActorEgressPolicyRequest, _ ...grpc.CallOption) (*ateapi.EgressPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy != nil {
		return nil, status.Error(codes.AlreadyExists, "egress policy exists")
	}
	f.createPolicyCalls++
	f.policy = proto.Clone(in.GetEgressPolicy()).(*ateapi.EgressPolicy)
	return proto.Clone(f.policy).(*ateapi.EgressPolicy), nil
}

func (f *fakeControl) UpdateActorEgressPolicy(_ context.Context, in *ateapi.UpdateActorEgressPolicyRequest, _ ...grpc.CallOption) (*ateapi.EgressPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy == nil {
		return nil, status.Error(codes.NotFound, "egress policy not found")
	}
	f.updatePolicyCalls++
	f.policy = proto.Clone(in.GetEgressPolicy()).(*ateapi.EgressPolicy)
	f.lastUpdateRules = f.policy.GetRules()
	return proto.Clone(f.policy).(*ateapi.EgressPolicy), nil
}

func (f *fakeControl) ListActors(_ context.Context, in *ateapi.ListActorsRequest, _ ...grpc.CallOption) (*ateapi.ListActorsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	token := in.GetOptions().GetPageToken()
	f.listTokens = append(f.listTokens, token)
	page, ok := f.listPages[token]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown page token %q", token)
	}
	return proto.Clone(page).(*ateapi.ListActorsResponse), nil
}

// runningActor is a RUNNING actor record for the fake.
func runningActor(atespace, name string) *ateapi.Actor {
	return &ateapi.Actor{
		Metadata: &ateapi.ResourceMetadata{Atespace: atespace, Name: name},
		Status:   &ateapi.ActorStatus{State: ateapi.ActorState_ACTOR_STATE_RUNNING},
	}
}

// httpRule builds a cleartext rule (legacy callback rules and grant halves).
func httpRule(host string, ports ...int32) *ateapi.EgressRule {
	return &ateapi.EgressRule{
		Http: &ateapi.HttpRule{
			Hostnames: []string{host},
			Ports:     &ateapi.Ports{Numbers: append([]int32(nil), ports...)},
		},
	}
}

// testPolicy wraps rules in a policy singleton record.
func testPolicy(rules ...*ateapi.EgressRule) *ateapi.EgressPolicy {
	return &ateapi.EgressPolicy{
		Metadata: &ateapi.ResourceMetadata{Atespace: "test", Name: SingletonName},
		Rules:    rules,
	}
}

// findTls returns the first tls-passthrough rule covering host, or nil.
func findTls(rules []*ateapi.EgressRule, host string) *ateapi.TlsPassthroughRule {
	for _, r := range rules {
		if tp := r.GetTlsPassthrough(); tp != nil && ruleHasHostname(tp.GetHostnames(), host) {
			return tp
		}
	}
	return nil
}

// hasHttpRule reports whether any cleartext rule covers host.
func hasHttpRule(rules []*ateapi.EgressRule, host string) bool {
	for _, r := range rules {
		if h := r.GetHttp(); h != nil && ruleHasHostname(h.GetHostnames(), host) {
			return true
		}
	}
	return false
}
