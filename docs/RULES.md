# Rule catalogue

Every built-in rule, what it reports, and what to do about it. `limator rules` prints the same list from the program.

## Health

| ID | Reports | What to do |
|---|---|---|
| H001 | An imported tool result, vulnerability database or capability baseline is missing, empty or unreadable | Fix the input; a check that cannot run is never treated as passed |
| H002 | An exception in the config matches nothing | Remove the exception |

## Go

| ID | Reports | Before | After |
|---|---|---|---|
| L000 | A Go file that does not parse | | Fix the syntax error |
| L001 | A comment matching a forbidden pattern from the config | `// TICKET-17 moved this` | Remove it; `limator fix` does this |
| L002 | The error from `Scan` is dropped | `if rows.Scan(&s) == nil { ... }` | `if err := rows.Scan(&s); err != nil { return err }` |
| L003 | A loop over `Next` with `Scan`, and `Err` is never checked | loop, then `return out` | `return out, rows.Err()` |
| L004 | A call result discarded with a blank assignment | `_ = db.Ping()` | Handle or return the error |
| L006 | A Go file without a leading comment that says what it is for | | One line above `package` |

## All scanned files

| ID | Reports | What to do |
|---|---|---|
| L005 | An invisible or zero-width character | Remove it; in Go comments `limator fix` does this |
| L007 | A file longer than `max_file_lines` | Split the file |
| L008 | A line longer than `max_line_length` | Break the line |

## Security

| ID | Reports | What to do |
|---|---|---|
| SEC001 | A possible private key, access key, token or hard-coded password | Move it out of the repository and rotate it |
| SEC010 | SQL text built with `fmt.Sprintf` or concatenation | Pass values as query parameters; an identifier from your own code is fine and can get an exception |
| SEC011 | `InsecureSkipVerify: true` | Verify the certificate |
| SEC012 | Import of `crypto/md5`, `crypto/sha1`, `crypto/des` or `crypto/rc4` | Use a current algorithm where security depends on it |
| SEC013 | A file or folder created world-writable | Use `0o644`, `0o600` or `0o755` |
| SEC020 | A Go module version listed in the local vulnerability database | Upgrade the module; the match is on module and version only |

## TypeScript and JavaScript

| ID | Reports | What to do |
|---|---|---|
| TS001 | A check switched off in a comment (`@ts-ignore`, `eslint-disable`) | Fix the cause, or keep it with an exception and a reason |
| TS002 | The `any` type | Give the value a real type |
| TS003 | `console.log` or `console.debug` left in code | Remove it |

## Structure

| ID | Reports | What to do |
|---|---|---|
| CAP001 | A folder gained a capability that is not in the baseline | Check that the new reach is intended, then update the baseline |

Your own rules, rule packs, laws and imported tools appear in reports under the ids you give them.
