# Security policy

quelda decides whether untrusted files may reach other software, so a bug that lets a dangerous
file through is a security vulnerability. Please report it privately.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting**: on
[github.com/tranhuucanh/quelda](https://github.com/tranhuucanh/quelda), open the **Security**
tab and choose **Report a vulnerability**. Only the maintainer sees the report.

Do not open a public issue, pull request or discussion for a vulnerability, and do not attach
working exploits for other software (for example a Ghostscript exploit) to anything public.

Please include:

- the quelda version (`quelda version`, or the npm package version) and how you ran it (CLI,
  npm in a browser or Node, the Rust library);
- the policy you used;
- a file that shows the problem, or a description of how to build one. Keep payloads harmless
  where you can (a file that would only *print* something is enough to show a missed rule);
- what you expected and what happened (the verdict JSON).

You will get an answer within 7 days. Fixes are released as soon as they are ready, with a
note in the [changelog](CHANGELOG.md) and a GitHub security advisory; reporters are credited
unless they prefer not to be.

## What counts as a vulnerability

- A file that should be `REJECT` or `ERROR` under a preset or policy but gets `PASS` (a rule
  bypass), for example through an encoding, an object stream, an old revision or a damaged
  structure that the engine reads differently from Ghostscript or other PDF software.
- A file that crashes, hangs or exhausts the memory of the CLI, the WebAssembly engine or the
  Rust library despite the limits in the policy.
- A way to make the CLI read or write anything other than the file and policy it was given.

A file that is rejected although it is harmless (a false positive) is a normal bug: please
open a public issue, without attaching private documents.

## Supported versions

Security fixes go into the latest release. Keep the CLI and the npm package on the same,
latest version.
