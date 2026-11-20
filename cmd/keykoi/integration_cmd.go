package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdIntegration(sub string, args []string) error {
	fs := flag.NewFlagSet("integration "+sub, flag.ContinueOnError)
	profile := fs.String("profile", "", "adapter profile id")
	id := fs.String("id", "", "integration id (defaults to profile id)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pid := *profile
	if pid == "" {
		pid = *id
	}
	c := client()
	switch sub {
	case "detect":
		if pid == "" {
			return fmt.Errorf("--profile is required")
		}
		// detect 走 plan 的能力检查，避免单独开放一条不校验授权的探测通道。
		var plan map[string]any
		if err := c.Post("/v1/integrations/plan", map[string]any{"profile_id": pid}, &plan); err != nil {
			return err
		}
		if g.json {
			return printJSON(plan["detection"])
		}
		fmt.Printf("profile=%v executable=%v version=%v os=%v supported=%v verified=%v\n",
			plan["profile_id"], plan["detection"], "", "", "", "")
		return nil
	case "plan":
		if pid == "" {
			return fmt.Errorf("--profile is required")
		}
		var plan map[string]any
		if err := c.Post("/v1/integrations/plan", map[string]any{"profile_id": pid}, &plan); err != nil {
			return err
		}
		if g.json {
			return printJSON(plan)
		}
		fmt.Printf("plan for %v (%v)\n", plan["profile_id"], plan["mechanism"])
		fmt.Printf("config: %v section=%v key=%v\n", plan["config_path"], plan["section"], plan["managed_key"])
		if caps, ok := plan["capabilities"].([]any); ok {
			for _, raw := range caps {
				cap := raw.(map[string]any)
				mark := "ok"
				if okv, _ := cap["ok"].(bool); !okv {
					mark = "FAIL"
				}
				fmt.Printf("  [%s] %v %v\n", mark, cap["name"], cap["note"])
			}
		}
		if preview, ok := plan["preview"].(string); ok {
			fmt.Println(preview)
		}
		return nil
	case "attach", "apply":
		if pid == "" {
			return fmt.Errorf("--profile is required")
		}
		var rec map[string]any
		if err := c.Post("/v1/integrations/apply", map[string]any{"profile_id": pid}, &rec); err != nil {
			return err
		}
		if g.json {
			return printJSON(rec)
		}
		fmt.Printf("attached %v state=%v config=%v\n", rec["id"], rec["state"], rec["config_path"])
		return nil
	case "verify":
		if pid == "" {
			return fmt.Errorf("--profile or --id is required")
		}
		var rec map[string]any
		if err := c.Post("/v1/integrations/"+pid+"/verify", map[string]any{}, &rec); err != nil {
			return err
		}
		if g.json {
			return printJSON(rec)
		}
		fmt.Printf("verified %v against %v (tool %v)\n", rec["id"], rec["detail"], rec["tool_version"])
		return nil
	case "detach":
		if pid == "" {
			return fmt.Errorf("--profile or --id is required")
		}
		var rec map[string]any
		if err := c.Post("/v1/integrations/"+pid+"/detach", map[string]any{}, &rec); err != nil {
			return err
		}
		if g.json {
			return printJSON(rec)
		}
		fmt.Printf("detached %v; managed fields removed, unrelated config preserved\n", rec["id"])
		return nil
	case "status":
		if pid == "" {
			return fmt.Errorf("--profile or --id is required")
		}
		var out map[string]any
		if err := c.Get("/v1/integrations/"+pid+"/status", &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("integration: %v\n", out["integration"])
		fmt.Printf("drift: %v\n", out["drift"])
		return nil
	case "", "list":
		var out struct {
			Integrations []map[string]any `json:"integrations"`
		}
		if err := c.Get("/v1/integrations", &out); err != nil {
			return err
		}
		if out.Integrations == nil {
			out.Integrations = []map[string]any{}
		}
		if g.json {
			return printJSON(out.Integrations)
		}
		if len(out.Integrations) == 0 {
			fmt.Println("no integrations attached")
			return nil
		}
		for _, rec := range out.Integrations {
			fmt.Printf("%v state=%v tool=%v verified=%v\n", rec["ID"], rec["State"], rec["ToolVersion"], rec["VerifiedVersion"])
		}
		return nil
	}
	_ = os.Stdout
	return fmt.Errorf("unknown integration subcommand %q; use detect|plan|attach|verify|detach|status|list", sub)
}

var _ = strings.TrimSpace
