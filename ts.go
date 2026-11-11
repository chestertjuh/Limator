package main

import (
	"regexp"
	"strings"
)

var tsExt = map[string]bool{".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true}

var (
	tsSuppress = regexp.MustCompile(`@ts-ignore|@ts-nocheck|@ts-expect-error|eslint-disable`)
	tsAny      = regexp.MustCompile(`:\s*any\b|\bas\s+any\b|<any>`)
	tsConsole  = regexp.MustCompile(`\bconsole\.(log|debug)\(`)
)

func tsViews(src []byte) (code, comments []byte) {
	code, comments = make([]byte, len(src)), make([]byte, len(src))
	const (
		inCode = iota
		inLine
		inBlock
		inString
	)
	state, quote := inCode, byte(0)
	for i := 0; i < len(src); i++ {
		c := src[i]
		code[i], comments[i] = ' ', ' '
		if c == '\n' || c == '\r' {
			code[i], comments[i] = c, c
			if state == inLine || (state == inString && quote != '`') {
				state = inCode
			}
			continue
		}
		next := byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}
		switch state {
		case inCode:
			switch {
			case c == '/' && next == '/' && (i == 0 || src[i-1] != ':'):
				state = inLine
				comments[i] = c
			case c == '/' && next == '*':
				state = inBlock
				comments[i] = c
			case c == '"' || c == '\'' || c == '`':
				state, quote = inString, c
				code[i] = c
			default:
				code[i] = c
			}
		case inLine:
			comments[i] = c
		case inBlock:
			comments[i] = c
			if c == '/' && i > 0 && src[i-1] == '*' {
				state = inCode
			}
		case inString:
			if c == '\\' && i+1 < len(src) && next != '\n' {
				i++
				code[i], comments[i] = ' ', ' '
			} else if c == quote {
				state = inCode
				code[i] = c
			}
		}
	}
	return code, comments
}

func checkTS(rel string, src []byte, cfg Config) []Finding {
	code, comments := tsViews(src)
	codeLines, commentLines := strings.Split(string(code), "\n"), strings.Split(string(comments), "\n")
	var out []Finding
	for i := range codeLines {
		c, m := codeLines[i], commentLines[i]
		if tsSuppress.MatchString(m) {
			out = append(out, Finding{"TS001", rel, i + 1, "check switched off in a comment"})
		}
		if tsAny.MatchString(c) {
			out = append(out, Finding{"TS002", rel, i + 1, "type any"})
		}
		if tsConsole.MatchString(c) {
			out = append(out, Finding{"TS003", rel, i + 1, "console output left in code"})
		}
		for _, re := range cfg.comments {
			if re.MatchString(m) {
				out = append(out, Finding{"L001", rel, i + 1, "comment matches " + re.String()})
				break
			}
		}
	}
	return out
}
