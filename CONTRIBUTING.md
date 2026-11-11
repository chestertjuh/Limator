# Contributing

Ideas, rules and fixes are welcome. Limator has three promises, and every change has to keep them:

1. The scanner never uses the network and never starts another program. A test checks its imports.
2. The same input gives the same output. No clocks, no randomness, no ordering that depends on a map.
3. A fix is only written when Limator can prove that the code itself did not change.

## Propose a rule

Open an issue with the "Rule idea" template. A good proposal has a short piece of code that should be reported, a piece that should not, and one sentence on why it matters. You do not need to write Go to propose a rule.

Many rules need no code at all. A pattern per line can go into a rule pack, see "Rule packs and plug-ins" in the README.

## Add a built-in rule

1. Add the rule to the table in `rules.go` with an id, a short name and one line of documentation.
2. Implement the check next to the existing ones.
3. Add a test with code that must be reported and code that must not.
4. Describe the rule in `docs/RULES.md` with a before and after.

## Before you send a pull request

```
gofmt -l .
go vet ./...
go test ./...
go build -o limator . && ./limator scan .
```

All four must be clean. Sign your commits with `git commit -s` to state that you wrote the change and may contribute it (Developer Certificate of Origin).

## Style

Small functions, no comments that repeat the code, no dependencies outside the Go standard library. Error values are handled or returned, never dropped.
