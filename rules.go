package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Doc  string `json:"doc"`
}

var rules = []Rule{
	{"H001", "tool-health", "an imported tool produced no usable output"},
	{"H002", "unused-exception", "an exception in the config matches nothing"},
	{"L000", "parse-error", "Go file does not parse"},
	{"L001", "comment-pattern", "comment matches a forbidden pattern from the config"},
	{"L002", "swallowed-scan", "result of Scan compared to nil, the error is dropped"},
	{"L003", "rows-err", "loop over Next with Scan but Err is never checked in the function"},
	{"L004", "blank-call", "call result discarded with a blank assignment"},
	{"L005", "invisible-char", "invisible or zero-width character"},
	{"L006", "file-doc", "Go file has no leading comment saying what it is for"},
	{"L007", "file-length", "file longer than max_file_lines"},
	{"L008", "line-length", "line longer than max_line_length"},
	{"SEC001", "secret", "possible secret or key in a file"},
	{"SEC010", "sql-format", "SQL text built with formatting or concatenation"},
	{"SEC011", "tls-skip-verify", "TLS certificate check switched off"},
	{"SEC012", "weak-crypto", "import of a weak algorithm"},
	{"SEC013", "world-writable", "file or folder created world-writable"},
	{"SEC020", "vulnerable-dep", "Go module version listed in the local vulnerability database"},
	{"TS001", "ts-suppressed", "TypeScript or lint check switched off in a comment"},
	{"TS002", "ts-any", "use of the any type"},
	{"TS003", "ts-console", "console output left in code"},
	{"CAP001", "new-capability", "a folder gained a capability that is not in the baseline"},
}

type Finding struct {
	Rule string `json:"rule"`
	File string `json:"file"`
	Line int    `json:"line"`
	Msg  string `json:"msg"`
}

func builtin(id string) bool {
	for _, r := range rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

var invisible = map[rune]bool{0x200B: true, 0x200C: true, 0x200D: true, 0x2060: true, 0xFEFF: true, 0x00AD: true, 0x2003: true}

func checkText(rel string, src []byte, cfg Config) []Finding {
	var out []Finding
	var data []DataRule
	base := path.Base(rel)
	for _, r := range cfg.Rules {
		if ok, err := path.Match(r.Files, base); err == nil && ok && r.re != nil {
			data = append(data, r)
		}
	}
	lines := strings.Split(strings.TrimPrefix(string(src), string(rune(0xFEFF))), "\n")
	if n := len(lines); n > cfg.MaxFileLines {
		out = append(out, Finding{"L007", rel, 1, fmt.Sprintf("%d lines, limit %d", n, cfg.MaxFileLines)})
	}
	for i, l := range lines {
		l = strings.TrimSuffix(l, "\r")
		if n := utf8.RuneCountInString(l); n > cfg.MaxLineLength {
			out = append(out, Finding{"L008", rel, i + 1, fmt.Sprintf("%d characters, limit %d", n, cfg.MaxLineLength)})
		}
		for _, r := range l {
			if invisible[r] {
				out = append(out, Finding{"L005", rel, i + 1, fmt.Sprintf("U+%04X", r)})
				break
			}
		}
		for _, r := range data {
			if r.re.MatchString(l) {
				out = append(out, Finding{r.ID, rel, i + 1, r.Msg})
			}
		}
	}
	return out
}

func checkGo(rel string, src []byte, pats []*regexp.Regexp) []Finding {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if err != nil {
		return []Finding{{"L000", rel, 1, "parse error"}}
	}
	var out []Finding
	add := func(rule string, pos token.Pos, msg string) {
		out = append(out, Finding{rule, rel, fset.Position(pos).Line, msg})
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			for _, re := range pats {
				if re.MatchString(c.Text) {
					add("L001", c.Pos(), "comment matches "+re.String())
					break
				}
			}
		}
	}
	if !hasFileDoc(f) {
		add("L006", f.Package, "no leading file comment")
	}
	checkSecurity(f, add)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if x.Op == token.EQL && isNil(x.Y) && receiver(x.X, "Scan", true) != "" {
				add("L002", x.Pos(), "Scan(...) == nil drops the error")
			}
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && allBlank(x.Lhs) {
				if _, ok := x.Rhs[0].(*ast.CallExpr); ok {
					add("L004", x.Pos(), "call result discarded")
				}
			}
		case *ast.FuncDecl:
			if x.Body != nil {
				checkRows(x.Body, add)
			}
		case *ast.FuncLit:
			checkRows(x.Body, add)
		}
		return true
	})
	return out
}

func hasFileDoc(f *ast.File) bool {
	return docGroup(f) != nil
}

func isNil(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

func allBlank(lhs []ast.Expr) bool {
	for _, e := range lhs {
		id, ok := e.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	return len(lhs) > 0
}

func receiver(e ast.Expr, method string, anyReceiver bool) string {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		return id.Name
	}
	if anyReceiver {
		return "?"
	}
	return ""
}

func checkRows(body *ast.BlockStmt, add func(string, token.Pos, string)) {
	loops := map[string]token.Pos{}
	checked := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ForStmt:
			name := receiver(x.Cond, "Next", false)
			if name == "" {
				return true
			}
			scans := false
			ast.Inspect(x.Body, func(m ast.Node) bool {
				if e, ok := m.(ast.Expr); ok && receiver(e, "Scan", false) == name {
					scans = true
				}
				return !scans
			})
			if _, seen := loops[name]; scans && !seen {
				loops[name] = x.Pos()
			}
		case *ast.CallExpr:
			if name := receiver(x, "Err", false); name != "" {
				checked[name] = true
			}
		}
		return true
	})
	for name, pos := range loops {
		if !checked[name] {
			add("L003", pos, name+".Err() is never checked")
		}
	}
}
