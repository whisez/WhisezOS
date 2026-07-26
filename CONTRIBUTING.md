# Contributing to WhisezOS

WhisezOS welcomes focused fixes, tests, documentation, and small platform
improvements. The production kernel, drivers, installer, and desktop handoff
are still research work; pull requests must not describe unfinished code as a
production-ready operating system.

## Development setup

Follow [INSTALL.md](INSTALL.md), then run:

```powershell
cargo xtask setup
cargo xtask test
```

The test command checks Whisez Guard, the host verification harness, Clippy,
and the UEFI preview build. Shader validation is skipped when `glslc` is not
installed.

## Pull request guidelines

- Keep each pull request focused on one problem.
- Add or update tests when behavior changes.
- Update `README.md`, `INSTALL.md`, or `BUILD.md` when commands change.
- Keep generated output, VM state, signing keys, and local configuration out of
  commits.
- Do not include real names, personal email addresses, private file paths,
  access tokens, logs containing personal data, or scanned user files.
- Run `cargo xtask test` before requesting review.

## Security reports

Do not open a public issue for a possible vulnerability. Use the repository's
private vulnerability reporting form described in [SECURITY.md](SECURITY.md).

All contributions are licensed under the Mozilla Public License 2.0.
