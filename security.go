package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var secretKinds = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"JSON web token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

var assigned = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)\b["']?\s*[:=]\s*` +
	`["']([A-Za-z0-9+/_=.-]{16,})["']`)

var hint = regexp.MustCompile(`(?i)-----BEGIN|AKIA|gh[pousr]_|github_pat_|xox[baprs]-|eyJ|passw|secret|token|api[_-]?key|private[_-]?key`)

func plausible(v string) bool {
	low := strings.ToLower(v)
	for _, w := range []string{"example", "changeme", "placeholder", "xxxx", "your", "test", "dummy", "sample"} {
		if strings.Contains(low, w) {
			return false
		}
	}
	return strings.ContainsAny(v, "0123456789") && strings.ContainsAny(low, "abcdefghijklmnopqrstuvwxyz")
}

func checkSecrets(rel string, src []byte) []Finding {
	if bytes.IndexByte(src, 0) >= 0 || !hint.Match(src) {
		return nil
	}
	var out []Finding
	for i, l := range strings.Split(string(src), "\n") {
		if !hint.MatchString(l) {
			continue
		}
		kind := ""
		for _, k := range secretKinds {
			if k.re.MatchString(l) {
				kind = k.name
				break
			}
		}
		if kind == "" {
			if m := assigned.FindStringSubmatch(l); m != nil && plausible(m[2]) {
				kind = "hard-coded " + strings.ToLower(m[1])
			}
		}
		if kind != "" {
			out = append(out, Finding{"SEC001", rel, i + 1, "possible " + kind})
		}
	}
	return out
}

func secretFile(name string, cfg Config) bool {
	ext := filepath.Ext(name)
	for _, e := range cfg.Extensions {
		if e == ext {
			return false
		}
	}
	if strings.HasPrefix(name, ".env") {
		return true
	}
	for _, e := range cfg.SecretExtensions {
		if e == ext {
			return true
		}
	}
	return false
}

var sqlArg = map[string]int{"Query": 0, "QueryRow": 0, "Exec": 0, "QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1}

var permCall = map[string]bool{"WriteFile": true, "OpenFile": true, "Mkdir": true, "MkdirAll": true, "Chmod": true}

func literal(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.ParenExpr:
		return literal(x.X)
	case *ast.BinaryExpr:
		return x.Op == token.ADD && literal(x.X) && literal(x.Y)
	}
	return false
}

func formatted(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "fmt" && sel.Sel.Name == "Sprintf"
	case *ast.BinaryExpr:
		return x.Op == token.ADD && !literal(x)
	}
	return false
}

func checkSecurity(f *ast.File, add func(string, token.Pos, string)) {
	for _, im := range f.Imports {
		switch strings.Trim(im.Path.Value, `"`) {
		case "crypto/md5", "crypto/sha1", "crypto/des", "crypto/rc4":
			add("SEC012", im.Pos(), "weak algorithm "+im.Path.Value)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.KeyValueExpr:
			k, ok := x.Key.(*ast.Ident)
			v, isIdent := x.Value.(*ast.Ident)
			if ok && isIdent && k.Name == "InsecureSkipVerify" && v.Name == "true" {
				add("SEC011", x.Pos(), "TLS certificate check switched off")
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if i, ok := sqlArg[sel.Sel.Name]; ok && len(x.Args) > i && formatted(x.Args[i]) {
				add("SEC010", x.Pos(), "SQL text built with formatting or concatenation")
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" || !permCall[sel.Sel.Name] || len(x.Args) == 0 {
				return true
			}
			lit, ok := x.Args[len(x.Args)-1].(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				return true
			}
			if mode, err := strconv.ParseInt(lit.Value, 0, 64); err == nil && mode&0o002 != 0 {
				add("SEC013", x.Pos(), "file mode "+lit.Value+" is world-writable")
			}
		}
		return true
	})
}

type advisory struct {
	id     string
	events [][2]string
}

func loadVulns(dir string) (map[string][]advisory, error) {
	db := map[string][]advisory{}
	count := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".json" {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var o struct {
			ID       string `json:"id"`
			Affected []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Ranges []struct {
					Type   string              `json:"type"`
					Events []map[string]string `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		}
		if json.Unmarshal(raw, &o) != nil || o.ID == "" {
			return nil
		}
		count++
		for _, a := range o.Affected {
			if a.Package.Ecosystem != "Go" {
				continue
			}
			for _, r := range a.Ranges {
				if r.Type != "SEMVER" {
					continue
				}
				adv := advisory{id: o.ID}
				for _, e := range r.Events {
					for kind, v := range e {
						adv.events = append(adv.events, [2]string{kind, v})
					}
				}
				db[a.Package.Name] = append(db[a.Package.Name], adv)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, fmt.Errorf("no advisories found in %s", dir)
	}
	return db, nil
}

func semver(v string) ([3]int, string) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, pre = v[:i], v[i+1:]
	}
	var n [3]int
	for i, p := range strings.SplitN(v, ".", 3) {
		if x, err := strconv.Atoi(p); err == nil {
			n[i] = x
		}
	}
	return n, pre
}

func cmpVersion(a, b string) int {
	na, pa := semver(a)
	nb, pb := semver(b)
	for i := range na {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return strings.Compare(pa, pb)
}

func affects(v string, events [][2]string) bool {
	in := false
	for _, e := range events {
		switch e[0] {
		case "introduced":
			if e[1] == "0" || cmpVersion(v, e[1]) >= 0 {
				in = true
			}
		case "fixed":
			if cmpVersion(v, e[1]) >= 0 {
				in = false
			}
		}
	}
	return in
}

func checkVulns(root string, cfg Config) []Finding {
	dir := cfg.VulnDB
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(cfg.dir, dir)
	}
	db, err := loadVulns(dir)
	if err != nil {
		return []Finding{{"H001", cfg.VulnDB, 1, "vulnerability database: " + err.Error()}}
	}
	var out []Finding
	seen := map[string]bool{}
	err = walkTree(root, cfg, func(name string) bool { return name == "go.mod" }, func(rel, abs string, src []byte) error {
		for _, d := range parseGoMod(src) {
			for _, adv := range db[d.Name] {
				key := rel + "|" + d.Name + "|" + adv.id
				if affects(d.Version, adv.events) && !seen[key] {
					seen[key] = true
					out = append(out, Finding{"SEC020", rel, 1, d.Name + "@" + d.Version + ": " + adv.id})
				}
			}
		}
		return nil
	})
	if err != nil {
		return []Finding{{"H001", cfg.VulnDB, 1, "vulnerability check: " + err.Error()}}
	}
	return out
}
