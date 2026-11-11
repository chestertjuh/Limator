package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type FileEntry struct {
	Path   string `json:"path"`
	Lines  int    `json:"lines"`
	SHA256 string `json:"sha256"`
	Doc    string `json:"doc"`
}

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	License   string `json:"license"`
	Indirect  bool   `json:"indirect"`
	Manifest  string `json:"manifest"`
}

type Inventory struct {
	Tool         string       `json:"tool"`
	Version      string       `json:"version"`
	Files        []FileEntry  `json:"files"`
	Dependencies []Dependency `json:"dependencies"`
	Hash         string       `json:"hash"`
}

type Control struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

type Audit struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	ConfigSHA256  string         `json:"config_sha256"`
	Rules         []Rule         `json:"rules"`
	Counts        map[string]int `json:"counts"`
	Suppressed    map[string]int `json:"suppressed"`
	Exceptions    []Exception    `json:"exceptions"`
	Files         int            `json:"files"`
	Lines         int            `json:"lines"`
	GoFilesNoDoc  int            `json:"go_files_without_doc"`
	Dependencies  int            `json:"dependencies"`
	Licenses      map[string]int `json:"licenses"`
	Reading       Coverage       `json:"reading"`
	Controls      []Control      `json:"controls"`
	ReportHash    string         `json:"report_hash"`
	InventoryHash string         `json:"inventory_hash"`
	Hash          string         `json:"hash"`
}

var controls = []Control{
	{"ISO/IEC 27001:2022 A.5.9", "Inventory of information and other associated assets", "file register and dependency list"},
	{"ISO/IEC 27001:2022 A.8.25", "Secure development life cycle", "rule counts and the gate baseline per revision"},
	{"ISO/IEC 27001:2022 A.8.28", "Secure coding", "findings per rule and exceptions with a reason"},
	{"ISO/IEC 27001:2022 A.8.29", "Security testing in development and acceptance", "imported tool results and tool health"},
}

func docGroup(f *ast.File) *ast.CommentGroup {
	limit := f.End()
	if len(f.Decls) > 0 {
		limit = f.Decls[0].Pos()
	}
	for _, cg := range f.Comments {
		if cg.Pos() < limit && !directive(cg.List[0].Text) {
			return cg
		}
	}
	return nil
}

func fileDoc(src []byte) string {
	f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.ParseComments)
	if err != nil {
		return ""
	}
	cg := docGroup(f)
	if cg == nil {
		return ""
	}
	text := strings.TrimSpace(cg.Text())
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	return text
}
func inventory(root string, cfg Config) (*Inventory, error) {
	inv := &Inventory{Tool: "limator", Version: version, Files: []FileEntry{}, Dependencies: []Dependency{}}
	err := walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		sum := sha256.Sum256(src)
		e := FileEntry{Path: rel, Lines: strings.Count(string(src), "\n") + 1, SHA256: hex.EncodeToString(sum[:])}
		if path.Ext(rel) == ".go" {
			e.Doc = fileDoc(src)
		}
		inv.Files = append(inv.Files, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	add := func(d Dependency) {
		key := d.Ecosystem + "|" + d.Name + "|" + d.Version
		if !seen[key] {
			seen[key] = true
			inv.Dependencies = append(inv.Dependencies, d)
		}
	}
	manifest := func(name string) bool { return name == "go.mod" || name == "package.json" }
	err = walkTree(root, cfg, manifest, func(rel, abs string, src []byte) error {
		dir := filepath.Dir(abs)
		if path.Base(rel) == "go.mod" {
			for _, d := range parseGoMod(src) {
				d.Manifest = rel
				d.License = goLicense(dir, cfg, d)
				add(d)
			}
			return nil
		}
		for _, d := range parseNpm(src, dir) {
			d.Manifest = rel
			add(d)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].Path < inv.Files[j].Path })
	sort.Slice(inv.Dependencies, func(i, j int) bool {
		a, b := inv.Dependencies[i], inv.Dependencies[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	h := sha256.New()
	fmt.Fprintln(h, version)
	for _, f := range inv.Files {
		fmt.Fprintf(h, "f|%s|%s\n", f.Path, f.SHA256)
	}
	for _, d := range inv.Dependencies {
		fmt.Fprintf(h, "d|%s|%s|%s|%s\n", d.Ecosystem, d.Name, d.Version, d.License)
	}
	inv.Hash = hex.EncodeToString(h.Sum(nil))
	return inv, nil
}

func parseGoMod(src []byte) []Dependency {
	var out []Dependency
	block := false
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			block = true
			continue
		case line == ")":
			block = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !block:
			continue
		}
		if f := strings.Fields(line); len(f) == 2 {
			out = append(out, Dependency{Ecosystem: "go", Name: f[0], Version: f[1], Indirect: indirect})
		}
	}
	return out
}

func parseNpm(src []byte, dir string) []Dependency {
	var m struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(src, &m) != nil {
		return nil
	}
	declared := map[string]string{}
	for name, v := range m.DevDependencies {
		declared[name] = v
	}
	for name, v := range m.Dependencies {
		declared[name] = v
	}
	var out []Dependency
	for name, v := range declared {
		d := Dependency{Ecosystem: "npm", Name: name, Version: v, License: "unknown"}
		raw, err := os.ReadFile(filepath.Join(dir, "node_modules", filepath.FromSlash(name), "package.json"))
		if err == nil {
			var p struct {
				Version string          `json:"version"`
				License json.RawMessage `json:"license"`
			}
			if json.Unmarshal(raw, &p) == nil {
				if p.Version != "" {
					d.Version = p.Version
				}
				var id string
				var obj struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(p.License, &id) == nil && id != "" {
					d.License = id
				} else if json.Unmarshal(p.License, &obj) == nil && obj.Type != "" {
					d.License = obj.Type
				}
			}
		}
		out = append(out, d)
	}
	return out
}

func moduleCache(cfg Config) string {
	if cfg.ModuleCache != "" {
		return cfg.ModuleCache
	}
	if p := os.Getenv("GOMODCACHE"); p != "" {
		return p
	}
	if p := os.Getenv("GOPATH"); p != "" {
		return filepath.Join(filepath.SplitList(p)[0], "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

func escapeModule(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func goLicense(dir string, cfg Config, d Dependency) string {
	places := []string{filepath.Join(dir, "vendor", filepath.FromSlash(d.Name))}
	if cache := moduleCache(cfg); cache != "" {
		places = append(places, filepath.Join(cache, filepath.FromSlash(escapeModule(d.Name))+"@"+d.Version))
	}
	for _, p := range places {
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, e := range entries {
			up := strings.ToUpper(e.Name())
			if strings.HasPrefix(up, "LICENSE") || strings.HasPrefix(up, "LICENCE") || strings.HasPrefix(up, "COPYING") {
				if raw, err := os.ReadFile(filepath.Join(p, e.Name())); err == nil {
					return classify(string(raw))
				}
			}
		}
	}
	return "unknown"
}

func classify(text string) string {
	t := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	has := func(s string) bool { return strings.Contains(t, s) }
	switch {
	case has("apache license") && has("version 2.0"):
		return "Apache-2.0"
	case has("mozilla public license") && has("2.0"):
		return "MPL-2.0"
	case has("gnu affero general public license"):
		return "AGPL-3.0"
	case has("gnu lesser general public license"):
		return "LGPL"
	case has("gnu general public license") && has("version 3"):
		return "GPL-3.0"
	case has("gnu general public license"):
		return "GPL-2.0"
	case has("permission is hereby granted, free of charge"):
		return "MIT"
	case has("permission to use, copy, modify, and/or distribute this software for any purpose"):
		return "ISC"
	case has("redistribution and use in source and binary forms") && has("neither the name"):
		return "BSD-3-Clause"
	case has("redistribution and use in source and binary forms"):
		return "BSD-2-Clause"
	}
	return "unknown"
}

func cyclonedx(inv *Inventory) ([]byte, error) {
	components := []map[string]any{}
	for _, d := range inv.Dependencies {
		kind := "golang"
		if d.Ecosystem == "npm" {
			kind = "npm"
		}
		c := map[string]any{
			"type":    "library",
			"name":    d.Name,
			"version": d.Version,
			"purl":    "pkg:" + kind + "/" + strings.Replace(d.Name, "@", "%40", 1) + "@" + d.Version,
		}
		if d.License != "unknown" {
			c["licenses"] = []any{map[string]any{"license": map[string]any{"name": d.License}}}
		}
		components = append(components, c)
	}
	return json.MarshalIndent(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components,
	}, "", "  ")
}

func audit(rep *Report, inv *Inventory, cov Coverage, cfg Config) (*Audit, error) {
	a := &Audit{
		Tool: "limator", Version: version, ConfigSHA256: cfg.sum, Rules: rep.Rules, Counts: rep.Counts,
		Suppressed: rep.Suppressed, Exceptions: rep.Exceptions, Files: len(inv.Files), Dependencies: len(inv.Dependencies),
		Licenses: map[string]int{}, Reading: cov, Controls: controls, ReportHash: rep.Hash, InventoryHash: inv.Hash,
	}
	for _, f := range inv.Files {
		a.Lines += f.Lines
		if path.Ext(f.Path) == ".go" && f.Doc == "" {
			a.GoFilesNoDoc++
		}
	}
	for _, d := range inv.Dependencies {
		a.Licenses[d.License]++
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	a.Hash = hex.EncodeToString(sum[:])
	return a, nil
}
