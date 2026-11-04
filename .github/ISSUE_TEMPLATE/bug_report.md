---
name: Bug report
about: Report a reproducible assembler or packaging failure
---

## Version and lane

Paste `basm --version`, host OS/architecture and whether this is the sovereign
or host diagnostic build.

## Minimal source and command

Use a small synthetic source without secrets. Include the exact command line.

## Expected and observed result

Include expected bytes/symbols/relocations, actual result and exit status.

## Evidence

Attach relevant non-sensitive diagnostics and state whether NASM agrees on the
documented common subset. Sensitive findings follow SECURITY.md.
