# Contributing to WhisezOS

**[Türkçe](CONTRIBUTING.md) · [English](CONTRIBUTING.en.md)**

WhisezOS welcomes focused bug fixes, tests, documentation improvements, and
small platform enhancements. The production kernel, drivers, disk installer,
and real desktop session remain research and development work. Changes that
present unfinished code as production-ready will not be accepted.

## Development environment

Follow [INSTALL.en.md](INSTALL.en.md), then run:

```powershell
cargo xtask setup
cargo xtask test
```

The test command runs Whisez Guard tests, the host verification suite, Clippy,
and the UEFI preview build. Shader validation is skipped if `glslc` is not
installed.

## Pull request guidelines

- Keep each pull request focused on one problem.
- Add or update tests when behavior changes.
- Update `README.md`, `README.en.md`, `INSTALL.md`, `INSTALL.en.md`, or
  `BUILD.md` when user-facing commands change.
- Do not commit generated output, virtual-machine state, signing keys, or local
  configuration.
- Do not share real names, personal email addresses, private file paths, access
  tokens, logs with personal information, or scanned user files.
- Run `cargo xtask test` before opening a pull request.
- Clearly state that the project is under development and is not ready for
  physical hardware.

## Commit messages

Use short messages that explain what changed:

```text
Fix mouse selection in desktop preview
Improve setup troubleshooting
Test capability revocation edge case
```

## Security reports

Do not open a public issue for a possible vulnerability. Use the private
reporting path described in [SECURITY.en.md](SECURITY.en.md).

All contributions are licensed under the Mozilla Public License 2.0.
