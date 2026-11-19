// Diagnostic: dump an ActorTemplate as stored in the substrate control plane.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/viveksupe/Trident/internal/backend/substrate"
)

func main() {
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
			fmt.Println("  env:", e.GetName(), "=", e.GetValue())
		}
		fmt.Println("  mounts:", len(c.GetVolumeMounts()))
	}
	for _, v := range t.GetVolumes() {
		fmt.Println("volume:", v.GetName(), "systemInfo:", v.GetSystemInfo() != nil, "durable:", v.GetDurableDir() != nil)
	}
}
