# Limator

Offline code hygiene for codebases that grow faster than people can read them.

Limator scans a local folder, counts what is wrong per rule, and refuses changes that make a count go up. It runs on CPU only: no AI, no network, no telemetry. The same input always gives the same report and the same hash.

Status: 0.5.0, early. Go rules, text rules for any file type, rules as data, exceptions with a reason, import of other tools' output, JSON, SARIF and HTML reports. The HTML report is one file that opens in any browser, with no server and nothing loaded from outside. Every rule has a test.

## Use

```
go build -o limator .
limator rules
limator scan   ./myproject
limator report ./myproject -o report.json
limator report ./myproject -o report.sarif -f sarif
limator report ./myproject -o report.html -f html
limator gate   ./myproject -b baseline.json
limator fix    ./myproject -n yes
limator fix    ./myproject
limator inventory ./myproject -o inventory.json
limator inventory ./myproject -o bom.json -f cyclonedx
limator audit  ./myproject -o audit.json
```

`gate` writes the baseline on the first run. After that it exits 1 when any rule count rises, and tightens the baseline when a count drops. Delete the baseline to start over after adding rules.

## Built-in rules

| ID | Name | What it finds |
|---|---|---|
| H001 | tool-health | an imported tool produced no usable output |
| H002 | unused-exception | an exception in the config matches nothing |
| L000 | parse-error | Go file does not parse |
| L001 | comment-pattern | comment matches a forbidden pattern from the config |
| L002 | swallowed-scan | `Scan(...) == nil`, the error is dropped |
| L003 | rows-err | loop over `Next` with `Scan` but `Err` is never checked |
| L004 | blank-call | call result discarded with `_ =` |
| L005 | invisible-char | zero-width or invisible character |
| L006 | file-doc | Go file has no leading comment saying what it is for |
| L007 | file-length | file longer than `max_file_lines` |
| L008 | line-length | line longer than `max_line_length` |

## Config

Optional `limator.json` in the scanned folder, or pass `-c path`.

```json
{
  "comment_patterns": ["TICKET-[0-9]+"],
  "max_file_lines": 1000,
  "max_line_length": 160,
  "skip_dirs": ["vendor", "node_modules", ".git", "tmp-*"],
  "extensions": [".go", ".ts", ".tsx"],
  "rules": [
    {"id": "X001", "name": "inline-style", "pattern": "style=\\{\\{", "files": "*.tsx", "msg": "inline style"}
  ],
  "exceptions": [
    {"rule": "L004", "path": "internal/legacy/", "reason": "scheduled for removal"}
  ],
  "imports": [
    {"id": "S001", "name": "staticcheck", "file": "staticcheck.txt"}
  ]
}
```

- `rules` are your own rules as data: a regular expression checked per line, for files whose name matches `files`.
- `exceptions` need a reason. A path ending in `/` matches a folder; otherwise it is a glob on the path or the file name. An exception that matches nothing is reported as H002.
- `imports` read the saved text output of another tool (`file:line: message` lines, path relative to the config). Limator does not run other programs. If the output is missing or shows a crash, that is reported as H001 and never silently ignored.

## Fix

`fix` changes Go files in place. It removes comments that match `comment_patterns` and strips invisible characters from comments. With `"fix_scope": "group"` it removes the whole comment block that contains a match; the default removes only the matching comment. `-n yes` shows what would change without writing.

Every change is proven before it is written: the code tokens of the file must be identical before and after, so only comments can differ. Directives such as `//go:build` are never touched, and files that import `C` are skipped.

## Web UI

`limator-ui` is a separate small program for working from the browser: scan again, preview a fix, apply a fix, and read the report.

```
go build -o limator-ui ./cmd/limator-ui
limator-ui -dir ./myproject
```

It listens on 127.0.0.1 only and prints a link with a one-time token; requests without that token are refused. It runs the scanner as a separate process, so the scanner itself stays free of network code. Applying a fix asks for confirmation first.

## Inventory and audit

`inventory` writes a register of every scanned file (path, line count, SHA-256, and the leading comment of Go files) and of every dependency found in `go.mod` and `package.json` files, with the license where it can be read locally. Go licenses are read from `vendor` or the module cache, npm licenses from `node_modules`. Nothing is downloaded; what cannot be read locally is listed as `unknown`. `-f cyclonedx` writes the dependencies as a CycloneDX 1.5 document.

`audit` writes one document for a revision: tool version, the SHA-256 of the config, the count per rule, every exception with its reason, the inventory totals, the licenses in use, and a hash over all of it. The same input gives the same document. It also lists which ISO/IEC 27001:2022 controls this evidence can support. It is evidence for an audit, not a statement of compliance.

## Limits

Rules L002 to L004 work on syntax, not on types, so they can miss or over-report. A clean scan is not proof of correct or secure code.

## License

Apache-2.0.
