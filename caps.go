package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type Law struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Files            string   `json:"files"`
	ForbidImports    []string `json:"forbid_imports"`
	HandlersMustCall []string `json:"handlers_must_call"`
	Msg              string   `json:"msg"`
}

var capOf = map[string]string{
	"net": "network", "os/exec": "exec", "database/sql": "sql", "unsafe": "unsafe", "C": "cgo",
	"reflect": "reflect", "syscall": "syscall", "plugin": "plugin",
}

func capability(importPath string) string {
	if c, ok := capOf[importPath]; ok {
		return c
	}
	switch {
	case strings.HasPrefix(importPath, "net/"):
		return "network"
	case strings.HasPrefix(importPath, "crypto/"), strings.Contains(importPath, "/crypto/"):
		return "crypto"
	}
	return ""
}

func capabilities(root string, cfg Config) (map[string][]string, error) {
	sets := map[string]map[string]bool{}
	err := walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		if path.Ext(rel) != ".go" || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		dir := path.Dir(rel)
		for _, im := range f.Imports {
			if c := capability(strings.Trim(im.Path.Value, `"`)); c != "" {
				if sets[dir] == nil {
					sets[dir] = map[string]bool{}
				}
				sets[dir][c] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for dir, set := range sets {
		for c := range set {
			out[dir] = append(out[dir], c)
		}
		sort.Strings(out[dir])
	}
	return out, nil
}

func checkCapabilities(root string, cfg Config) []Finding {
	file := cfg.CapsBaseline
	if !filepath.IsAbs(file) {
		file = filepath.Join(cfg.dir, file)
	}
	raw, err := os.ReadFile(file)
	base := map[string][]string{}
	if err == nil {
		err = json.Unmarshal(raw, &base)
	}
	if err != nil {
		return []Finding{{"H001", cfg.CapsBaseline, 1, "capability baseline: " + err.Error()}}
	}
	now, err := capabilities(root, cfg)
	if err != nil {
		return []Finding{{"H001", cfg.CapsBaseline, 1, "capability check: " + err.Error()}}
	}
	var out []Finding
	for dir, caps := range now {
		known := map[string]bool{}
		for _, c := range base[dir] {
			known[c] = true
		}
		for _, c := range caps {
			if !known[c] {
				out = append(out, Finding{"CAP001", dir, 1, "gained capability " + c})
			}
		}
	}
	return out
}

func lawApplies(l Law, rel string) bool {
	if ok, err := path.Match(l.Files, rel); err == nil && ok {
		return true
	}
	ok, err := path.Match(l.Files, path.Base(rel))
	return err == nil && ok
}

func callsAny(body *ast.BlockStmt, names []string) bool {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			found = found || want[fun.Name]
		case *ast.SelectorExpr:
			found = found || want[fun.Sel.Name]
		}
		return !found
	})
	return found
}

func checkLaws(rel string, src []byte, cfg Config) []Finding {
	var laws []Law
	for _, l := range cfg.Laws {
		if lawApplies(l, rel) {
			laws = append(laws, l)
		}
	}
	if len(laws) == 0 {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, l := range laws {
		for _, im := range f.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			for _, bad := range l.ForbidImports {
				if p == bad {
					out = append(out, Finding{l.ID, rel, fset.Position(im.Pos()).Line, l.Msg + ": imports " + p})
				}
			}
		}
		if len(l.HandlersMustCall) == 0 {
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			handler := false
			for _, p := range fn.Type.Params.List {
				handler = handler || isHTTPRequest(p.Type)
			}
			if handler && !callsAny(fn.Body, l.HandlersMustCall) {
				out = append(out, Finding{l.ID, rel, fset.Position(fn.Pos()).Line, l.Msg + ": " + funcName(fn)})
			}
		}
	}
	return out
}

func writeCaps(root string, cfg Config, out string) error {
	caps, err := capabilities(root, cfg)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(caps, "", "  ")
	if err != nil {
		return err
	}
	if out == "" {
		_, err = os.Stdout.Write(append(raw, '\n'))
		return err
	}
	return os.WriteFile(out, append(raw, '\n'), 0o644)
}
