// Diagnostic: dump an ActorTemplate as stored in the substrate control plane.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/viveksupe/Trident/internal/backend/substrate"
)

// maskSecret hides values of secret-shaped env names (template dumps used to
// print provider API keys verbatim).
func maskSecret(name, value string) string {
	up := strings.ToUpper(name)
	if strings.Contains(up, "KEY") || strings.Contains(up, "TOKEN") ||
		strings.Contains(up, "SECRET") || strings.Contains(up, "PASSWORD") {
		if value == "" {
			return "<unset>"
		}
		return "<set, len " + fmt.Sprint(len(value)) + ">"
	}
	return value
}

func main() {
	// Argument-count guard first: a missing atespace/actor used to panic on
	// the os.Args index.
	if len(os.Args) < 3 {
		fmt.Println("usage: inspect-tmpl <cmd> <atespace> <name|actor> [extra]",
			"\n  cmds: actors, delete, suspendall, cycle, migrate, policy, (default: dump template)")
		os.Exit(2)
	}
	if os.Args[1] == "delete" && len(os.Args) < 4 {
		fmt.Println("usage: inspect-tmpl delete <atespace> <actor>")
		os.Exit(2)
	}
	if os.Args[1] == "cycle" && len(os.Args) < 4 {
		fmt.Println("usage: inspect-tmpl cycle <atespace> <actor>")
		os.Exit(2)
	}
	if os.Args[1] == "migrate" && len(os.Args) < 5 {
		fmt.Println("usage: inspect-tmpl migrate <atespace> <actor> <callback>")
		os.Exit(2)
	}
	if os.Args[1] == "policy" && len(os.Args) < 4 {
		fmt.Println("usage: inspect-tmpl policy <atespace> <actor>")
		os.Exit(2)
	}

	client, err := substrate.NewAPIClientForTest()
	if err != nil {
		fmt.Println("client:", err)
		os.Exit(1)
	}
	defer client.Close()
	if len(os.Args) > 2 && os.Args[1] == "actors" {
		infos, err := substrate.ListActorInfosForTest(context.Background(), client, os.Args[2])
		if err != nil {
			fmt.Println("list:", err)
			os.Exit(1)
		}
		for _, a := range infos {
			fmt.Println(a.Name, a.Template, a.State)
		}
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "delete" {
		fmt.Println("delete:", substrate.DeleteActorForTest(context.Background(), client, os.Args[2], os.Args[3]))
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "suspendall" {
		n, err := substrate.SuspendAllForTest(context.Background(), client, os.Args[2])
		fmt.Println("suspended:", n, "err:", err)
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "cycle" {
		fmt.Println("cycle:", substrate.CycleActorForTest(context.Background(), client, os.Args[2], os.Args[3]))
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "migrate" {
		err := substrate.MigrateCallbackRuleForTest(context.Background(), client, os.Args[2], os.Args[3], os.Args[4])
		fmt.Println("migrate:", err)
		pol, perr := substrate.GetEgressPolicyForTest(context.Background(), client, os.Args[2], os.Args[3])
		if perr == nil && pol != nil {
			for _, r := range pol.GetRules() {
				if tp := r.GetTlsPassthrough(); tp != nil {
					fmt.Println(" tls:", tp.GetHostnames(), "ports:", tp.GetPorts().GetNumbers())
				}
				if h := r.GetHttp(); h != nil {
					fmt.Println(" http:", h.GetHostnames(), "ports:", h.GetPorts().GetNumbers())
				}
			}
		}
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "policy" {
		atespace, actor := os.Args[2], os.Args[3]
		pol, err := substrate.GetEgressPolicyForTest(context.Background(), client, atespace, actor)
		if err != nil {
			fmt.Println("policy:", err)
			os.Exit(1)
		}
		for _, r := range pol.GetRules() {
			if tp := r.GetTlsPassthrough(); tp != nil {
				fmt.Println(" tls:", tp.GetHostnames(), "ports:", tp.GetPorts().GetNumbers())
			}
			if h := r.GetHttp(); h != nil {
				fmt.Println(" http:", h.GetHostnames(), "ports:", h.GetPorts().GetNumbers())
			}
		}
		return
	}
	atespace, name := os.Args[1], os.Args[2]
	t, err := substrate.GetTemplateForTest(context.Background(), client, atespace, name)
	if err != nil {
		fmt.Println("get:", err)
		os.Exit(1)
	}
	for _, c := range t.GetContainers() {
		fmt.Println("container:", c.GetName(), "image:", c.GetImage())
		for _, e := range c.GetEnv() {
			fmt.Println("  env:", e.GetName(), "=", maskSecret(e.GetName(), e.GetValue()))
		}
		fmt.Println("  mounts:", len(c.GetVolumeMounts()))
	}
	for _, v := range t.GetVolumes() {
		fmt.Println("volume:", v.GetName(), "systemInfo:", v.GetSystemInfo() != nil, "durable:", v.GetDurableDir() != nil)
	}
}
