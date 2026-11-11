# Security

## Reporting a problem

Please report a vulnerability through the "Report a vulnerability" button under the Security tab of this repository, not in a public issue. Describe what you did, what happened and what you expected.

## What Limator does and does not do

- `limator` (the scanner) reads files and writes reports. It has no network code and does not start other programs.
- `limator-ui` listens on 127.0.0.1 only, requires a random token on every request, and starts the scanner as a separate process. Do not expose it to other machines.
- `limator-update` is the only program that uses the network. It refuses archives with unsafe paths and rule packs whose hash does not match.

A clean scan is not proof that code is secure.
