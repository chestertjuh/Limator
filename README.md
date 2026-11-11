# Limator

Offline code hygiene for codebases that grow faster than people can read them.

Limator scans a local folder, counts what is wrong per rule, and refuses changes that make a count go up. It runs on CPU only: no AI, no network, no telemetry. The same input always gives the same report and the same hash.

Status: 0.9.0, early. Go rules, text rules for any file type, rules as data, exceptions with a reason, import of other tools' output, JSON, SARIF and HTML reports. The HTML report is one file that opens in any browser, with no server and nothing loaded from outside. Every rule has a test.

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
limator readlist ./myproject -n 20
limator read   ./myproject -who alice -f internal/auth/login.go
limator coverage ./myproject
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

## Security checks

These run as part of every scan.

| ID | Name | What it finds |
|---|---|---|
| SEC001 | secret | private keys, access keys, tokens and hard-coded passwords, in code and in config files such as `.env`, `.json` and `.yml` |
| SEC010 | sql-format | SQL text built with `fmt.Sprintf` or string concatenation and passed to `Query` or `Exec` |
| SEC011 | tls-skip-verify | `InsecureSkipVerify: true` |
| SEC012 | weak-crypto | import of `crypto/md5`, `crypto/sha1`, `crypto/des` or `crypto/rc4` |
| SEC013 | world-writable | files or folders created with a world-writable mode |
| SEC020 | vulnerable-dep | a Go module version listed in a local copy of the Go vulnerability database |

A secret is never written to a report; a finding only names the kind and the line. Files of any size are searched; only binary files are skipped. For SEC020 set `"vuln_db"` to a folder holding an unpacked copy of the Go vulnerability database. Limator reads it from disk and never downloads it. The match is on module and version, not on whether the vulnerable code is reached, so it can over-report. If the folder is missing or empty, that is reported as H001.

This is static analysis of source text. It does not replace a penetration test of a running system.

## Reading list and read coverage

Code can grow faster than anyone can read it. Limator does not ask you to read everything; it tells you what to read first and keeps track of what a person has read.

`readlist` ranks every Go function that nobody has marked as read. The score is `3 x sensitive areas + complexity + 2 x findings`; layout findings (file-doc, file-length, line-length) are not counted. Sensitive areas are detected from the code: SQL calls, cryptography, starting processes, HTTP handlers, writing or deleting files, and names that point at authentication or tenancy. Test files are left out.

`read` records that a person read a file or one function. The record stores a hash of the code tokens of each function, so a mark stays valid when only comments change and expires as soon as the code changes. Marks are kept in `.limator-read.json` in the scanned folder (or `read_file` in the config); commit that file with the code.

`coverage` prints how many functions, and how many sensitive functions, currently carry a valid mark. The same numbers are part of the audit document.

## Rule packs and plug-ins

A rule pack is a JSON file with `rules` and `comment_patterns`, shared between projects. The config names each pack with its SHA-256; a pack whose content does not match the pinned hash is refused, so a pack cannot change unnoticed.

```json
{"packs": [{"file": "packs/go-web.json", "sha256": "..."}]}
```

A plug-in is any program that writes its results to a file. Limator reads that file through `imports`: plain `file:line: message` lines, or a SARIF document when the file name ends in `.sarif`. Limator never starts the program itself.

## Updates

`limator-update` is a separate program and the only part that uses the network. The scanner never calls it; you run it yourself or from your own scheduler.

```
go build -o limator-update ./cmd/limator-update
limator-update vulndb -dir ./vulndb
limator-update pack -url https://example.org/pack.json -sha256 <hash> -o packs/pack.json
```

`vulndb` downloads the Go vulnerability database, unpacks it next to the old copy, and only then swaps them; the previous copy is kept as `<folder>.old`. An archive with unsafe paths or no files is refused and the existing copy stays in place. `pack` only writes a pack when its SHA-256 matches the one you give. On a machine without internet, copy the folder or the pack by hand.

## Origin

`origin` records who wrote a function: `ai`, `human` or `mixed`. Limator does not guess this; you declare it, per function, per file, or for everything at once with `-all yes`. Together with the read marks this answers one question for an audit: how much of the AI-written code has a person read? `coverage` and the audit document report that number.

## Capabilities and laws

`caps` lists per folder what its Go code can reach, judged from its imports: network, exec, sql, crypto, unsafe, cgo, reflect, syscall, plugin. Save that list and name it as `caps_baseline` in the config; from then on a folder that gains a capability is reported as CAP001. Only direct imports are looked at, not what dependencies do.

Laws are project rules about structure, written as data:

```json
{"laws": [{
  "id": "LAW001", "name": "tenant-check", "files": "*.go",
  "handlers_must_call": ["tenantScope"],
  "forbid_imports": ["net/http/pprof"],
  "msg": "every HTTP handler checks the tenant"
}]}
```

`handlers_must_call` reports every function with an `*http.Request` parameter that calls none of the named functions. `forbid_imports` reports the import.

## TypeScript and JavaScript

For `.ts`, `.tsx`, `.js` and `.jsx` files Limator separates code, comments and strings and reports: TS001 checks switched off in a comment (`@ts-ignore`, `eslint-disable`), TS002 the `any` type, TS003 `console.log` left in code, and L001 comments that match `comment_patterns`. This is a text-level split, not a full parser, so it can misjudge unusual syntax. For that reason `fix` does not change these files.

## Limits

Rules L002 to L004 work on syntax, not on types, so they can miss or over-report. A clean scan is not proof of correct or secure code.

## License

Apache-2.0.
