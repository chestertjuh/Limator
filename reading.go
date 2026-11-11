package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Unit struct {
	File       string   `json:"file"`
	Func       string   `json:"func"`
	Line       int      `json:"line"`
	Lines      int      `json:"lines"`
	Hash       string   `json:"hash"`
	Complexity int      `json:"complexity"`
	Sensitive  []string `json:"sensitive"`
	Findings   int      `json:"findings"`
	Score      int      `json:"score"`
	Read       bool     `json:"read"`
}

type ReadMark struct {
	File string `json:"file"`
	Func string `json:"func"`
	Hash string `json:"hash"`
	Who  string `json:"who"`
	Date string `json:"date"`
}

type Coverage struct {
	Functions     int `json:"functions"`
	Read          int `json:"functions_read"`
	Sensitive     int `json:"sensitive_functions"`
	SensitiveRead int `json:"sensitive_functions_read"`
}

var authWords = []string{"auth", "login", "password", "passwd", "token", "session", "permission", "role", "tenant", "secret",
	"credential", "mfa", "jwt"}

var fileWrite = map[string]bool{"WriteFile": true, "Remove": true, "RemoveAll": true, "Rename": true, "OpenFile": true, "Chmod": true}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + fn.Name.Name
		}
		return fn.Name.Name
	}
}

func isHTTPRequest(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Request" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http"
}

func fileUnits(rel string, src []byte) []Unit {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil
	}
	pkgs := map[string]string{}
	for _, im := range f.Imports {
		p := strings.Trim(im.Path.Value, `"`)
		name := path.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		pkgs[name] = p
	}
	var out []Unit
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start, end := fset.Position(fn.Pos()), fset.Position(fn.End())
		toks, err := tokens(src[start.Offset:end.Offset])
		if err != nil {
			continue
		}
		sum := sha256.Sum256([]byte(strings.Join(toks, "\n")))
		u := Unit{File: rel, Func: funcName(fn), Line: start.Line, Lines: end.Line - start.Line + 1, Complexity: 1}
		u.Hash = hex.EncodeToString(sum[:8])
		tags := map[string]bool{}
		low := strings.ToLower(fn.Name.Name)
		for _, w := range authWords {
			if strings.Contains(low, w) {
				tags["auth"] = true
			}
		}
		for _, p := range fn.Type.Params.List {
			if isHTTPRequest(p.Type) {
				tags["http"] = true
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CommClause:
				u.Complexity++
			case *ast.CaseClause:
				if x.List != nil {
					u.Complexity++
				}
			case *ast.BinaryExpr:
				if x.Op == token.LAND || x.Op == token.LOR {
					u.Complexity++
				}
			case *ast.SelectorExpr:
				if _, ok := sqlArg[x.Sel.Name]; ok {
					tags["sql"] = true
				}
				id, ok := x.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch p := pkgs[id.Name]; {
				case p == "os/exec":
					tags["exec"] = true
				case strings.Contains(p, "crypto"):
					tags["crypto"] = true
				case p == "os" && fileWrite[x.Sel.Name]:
					tags["file-write"] = true
				}
			}
			return true
		})
		u.Sensitive = []string{}
		for t := range tags {
			u.Sensitive = append(u.Sensitive, t)
		}
		sort.Strings(u.Sensitive)
		out = append(out, u)
	}
	return out
}

func marksFile(root string, cfg Config) string {
	if cfg.ReadFile == "" {
		return filepath.Join(root, ".limator-read.json")
	}
	if filepath.IsAbs(cfg.ReadFile) {
		return cfg.ReadFile
	}
	return filepath.Join(cfg.dir, cfg.ReadFile)
}

func loadMarks(file string) ([]ReadMark, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var marks []ReadMark
	if err := json.Unmarshal(raw, &marks); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return marks, nil
}

func units(root string, cfg Config, rep *Report) ([]Unit, error) {
	marks, err := loadMarks(marksFile(root, cfg))
	if err != nil {
		return nil, err
	}
	read := map[string]string{}
	for _, m := range marks {
		read[m.File+"|"+m.Func] = m.Hash
	}
	lines := map[string][]int{}
	if rep != nil {
		for _, f := range rep.Findings {
			if f.Rule != "L006" && f.Rule != "L007" && f.Rule != "L008" {
				lines[f.File] = append(lines[f.File], f.Line)
			}
		}
	}
	var all []Unit
	err = walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		if path.Ext(rel) != ".go" || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		for _, u := range fileUnits(rel, src) {
			for _, l := range lines[rel] {
				if l >= u.Line && l < u.Line+u.Lines {
					u.Findings++
				}
			}
			u.Score = 3*len(u.Sensitive) + u.Complexity + 2*u.Findings
			u.Read = read[rel+"|"+u.Func] == u.Hash
			all = append(all, u)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Line < all[j].Line
	})
	return all, nil
}

func coverage(all []Unit) Coverage {
	var c Coverage
	for _, u := range all {
		c.Functions++
		if u.Read {
			c.Read++
		}
		if len(u.Sensitive) > 0 {
			c.Sensitive++
			if u.Read {
				c.SensitiveRead++
			}
		}
	}
	return c
}

func percent(part, whole int) string {
	if whole == 0 {
		return "n/a"
	}
	return strconv.Itoa(part*100/whole) + "%"
}

func readlist(root string, cfg Config, rep *Report, opt map[string]string) error {
	all, err := units(root, cfg, rep)
	if err != nil {
		return err
	}
	n := 20
	if opt["-n"] != "" {
		if n, err = strconv.Atoi(opt["-n"]); err != nil || n < 1 {
			return fmt.Errorf("-n must be a positive number")
		}
	}
	top := []Unit{}
	for _, u := range all {
		if !u.Read && len(top) < n {
			top = append(top, u)
		}
	}
	for _, u := range top {
		fmt.Printf("%4d  %s:%d  %s  [%s]  complexity %d, findings %d\n",
			u.Score, u.File, u.Line, u.Func, strings.Join(u.Sensitive, " "), u.Complexity, u.Findings)
	}
	if opt["-o"] == "" {
		return nil
	}
	raw, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(opt["-o"], append(raw, '\n'), 0o644)
}

func reading(cmd, root string, cfg Config, opt map[string]string) error {
	all, err := units(root, cfg, nil)
	if err != nil {
		return err
	}
	if cmd == "coverage" {
		c := coverage(all)
		fmt.Printf("functions read: %d of %d (%s)\n", c.Read, c.Functions, percent(c.Read, c.Functions))
		fmt.Printf("sensitive functions read: %d of %d (%s)\n", c.SensitiveRead, c.Sensitive, percent(c.SensitiveRead, c.Sensitive))
		return nil
	}
	who, file, fn := opt["-who"], filepath.ToSlash(opt["-f"]), opt["-fn"]
	if who == "" || file == "" {
		return fmt.Errorf("read needs -who <name> and -f <file>, and optionally -fn <function>")
	}
	date := opt["-d"]
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}
	target := marksFile(root, cfg)
	old, err := loadMarks(target)
	if err != nil {
		return err
	}
	marks := map[string]ReadMark{}
	for _, m := range old {
		marks[m.File+"|"+m.Func] = m
	}
	count := 0
	for _, u := range all {
		if u.File == file && (fn == "" || u.Func == fn) {
			marks[u.File+"|"+u.Func] = ReadMark{File: u.File, Func: u.Func, Hash: u.Hash, Who: who, Date: date}
			count++
		}
	}
	if count == 0 {
		return fmt.Errorf("no function matched %s %s", file, fn)
	}
	list := make([]ReadMark, 0, len(marks))
	for _, m := range marks {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].File != list[j].File {
			return list[i].File < list[j].File
		}
		return list[i].Func < list[j].Func
	})
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("read: marked %d functions in %s as read by %s\n", count, file, who)
	return os.WriteFile(target, append(raw, '\n'), 0o644)
}
