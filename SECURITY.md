# Security Policy

## Reporting a vulnerability

Please report security issues privately by emailing **security@hi.institute**. Do not open
a public GitHub issue for a suspected vulnerability — that discloses it to anyone watching
the repo before a fix is available.

Include what you found, the affected file(s) or function(s), a reproduction (input leaves,
media, or a test case) if you have one, and your assessment of impact. We will acknowledge
your report within **3 business days** and aim to provide an initial assessment — confirmed,
not applicable, or need more information — within **10 business days**. We'll keep you
updated as a fix is developed and will credit you in the fix, unless you ask us not to.

## What counts as a security issue here

This is a verification tool. Its entire job is to tell someone whether a record is
genuine, unmodified, and still in good standing. That means **correctness bugs are security
bugs**, not just quality bugs:

- Any input (leaf bytes, media file, log response) that causes the verifier to report
  **VERIFIED**, an **exact match**, or a **fuzzy match** when it should not.
- Any bypass of signature verification, log-inclusion proof verification, or the
  fail-closed behavior of `pkg/status` (a status check that cannot be completed must never
  resolve to VERIFIED).
- Any way to make identity resolution attribute a signing key to the wrong creator, or to
  accept an identity binding that was not actually logged.
- Memory-safety or panic conditions reachable from untrusted input (a hostile leaf file or
  a hostile server response to the WebAssembly verifier), since a crash on adversarial input
  is itself a denial-of-service and a signal that the same input might be mishandled less
  loudly elsewhere.

A false "verified" is a trust failure, not a cosmetic one — please report it the same way
you'd report a signature bypass, even if the path to trigger it looks obscure or requires an
adversarial log operator.

## Scope

In scope: `pkg/`, `internal/`, `cmd/hiiverify`, `cmd/wasmverify`, and the verification logic
in `web/` (the JS glue around the WebAssembly module). Out of scope: the availability or
operational security of HII's own hosted transparency log and certification service — report
those through the same address, but they are a separate system from the code in this
repository.
