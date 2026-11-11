package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const version = "0.6.0"

func usage() {
	fmt.Fprintln(os.Stderr, "limator "+version+`

usage:
  limator rules
  limator scan   <dir> [-c config.json]
  limator report <dir> [-c config.json] -o file [-f json|sarif|html]
  limator gate   <dir> [-c config.json] -b baseline.json
  limator fix    <dir> [-c config.json] [-n yes]
  limator inventory <dir> [-c config.json] -o file [-f json|cyclonedx]
  limator audit  <dir> [-c config.json] -o audit.json`)
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "limator:", err)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if cmd == "rules" {
		for _, r := range rules {
			fmt.Printf("%s  %-16s %s\n", r.ID, r.Name, r.Doc)
		}
		return
	}
	if len(os.Args) < 3 || (cmd != "scan" && cmd != "report" && cmd != "gate" && cmd != "fix" && cmd != "inventory" && cmd != "audit") {
		usage()
	}
	root := os.Args[2]
	opt := map[string]string{}
	rest := os.Args[3:]
	if len(rest)%2 != 0 {
		usage()
	}
	for i := 0; i < len(rest); i += 2 {
		opt[rest[i]] = rest[i+1]
	}
	cfgPath := opt["-c"]
	if cfgPath == "" {
		cfgPath = filepath.Join(root, "limator.json")
	}
	cfg, err := loadConfig(cfgPath, opt["-c"] != "")
	if err != nil {
		fail(err)
	}
	if cmd == "fix" {
		if err := fixAll(root, cfg, opt["-n"] != ""); err != nil {
			fail(err)
		}
	}
	rep, err := scan(root, cfg)
	if err != nil {
		fail(err)
	}
	printSummary(rep)
	switch cmd {
	case "report":
		if opt["-o"] == "" {
			usage()
		}
		var out []byte
		switch opt["-f"] {
		case "", "json":
			out, err = json.MarshalIndent(rep, "", "  ")
		case "sarif":
			out, err = sarif(rep)
		case "html":
			out, err = htmlReport(rep)
		default:
			usage()
		}
		if err == nil {
			err = os.WriteFile(opt["-o"], append(out, '\n'), 0o644)
		}
		if err != nil {
			fail(err)
		}
	case "inventory", "audit":
		if opt["-o"] == "" {
			usage()
		}
		inv, err := inventory(root, cfg)
		if err != nil {
			fail(err)
		}
		var doc any = inv
		if cmd == "audit" {
			doc, err = audit(rep, inv, cfg)
		}
		var out []byte
		if err == nil && cmd == "inventory" && opt["-f"] == "cyclonedx" {
			out, err = cyclonedx(inv)
		} else if err == nil {
			out, err = json.MarshalIndent(doc, "", "  ")
		}
		if err == nil {
			err = os.WriteFile(opt["-o"], append(out, '\n'), 0o644)
		}
		if err != nil {
			fail(err)
		}
		fmt.Printf("%s: %d files, %d dependencies -> %s\n", cmd, len(inv.Files), len(inv.Dependencies), opt["-o"])
	case "gate":
		if opt["-b"] == "" {
			usage()
		}
		code, err := gate(rep, opt["-b"])
		if err != nil {
			fail(err)
		}
		os.Exit(code)
	}
}

func printSummary(rep *Report) {
	fmt.Printf("limator %s  files %d  hash %.16s\n", rep.Version, rep.Files, rep.Hash)
	for _, r := range rep.Rules {
		line := fmt.Sprintf("%s  %-16s %d", r.ID, r.Name, rep.Counts[r.ID])
		if n := rep.Suppressed[r.ID]; n > 0 {
			line += fmt.Sprintf("  (+%d excepted)", n)
		}
		fmt.Println(line)
	}
}

func writeCounts(file string, counts map[string]int) error {
	b, err := json.MarshalIndent(counts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(b, '\n'), 0o644)
}

func gate(rep *Report, file string) (int, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("gate: baseline written to", file)
		return 0, writeCounts(file, rep.Counts)
	}
	if err != nil {
		return 0, err
	}
	base := map[string]int{}
	if err := json.Unmarshal(raw, &base); err != nil {
		return 0, fmt.Errorf("%s: %w", file, err)
	}
	worse, better := false, false
	for _, r := range rep.Rules {
		cur, old := rep.Counts[r.ID], base[r.ID]
		if cur > old {
			worse = true
			fmt.Printf("gate: FAIL %s %s %d -> %d\n", r.ID, r.Name, old, cur)
		} else if cur < old {
			better = true
			fmt.Printf("gate: better %s %s %d -> %d\n", r.ID, r.Name, old, cur)
		}
	}
	if worse {
		return 1, nil
	}
	if better {
		return 0, writeCounts(file, rep.Counts)
	}
	fmt.Println("gate: ok")
	return 0, nil
}
