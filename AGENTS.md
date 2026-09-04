# Agent guide

## Purpose

This repository builds a dependency-free Windows PowerShell 5.1 bootstrapper
for key-only OpenSSH administration from macOS, plus the POSIX `winctl` helper
for reading and changing Windows display and sleep timeouts.

## Verification

- Run `git diff --check` and `sh -n winctl` locally.
- Native verification is `.github/workflows/windows-ci.yml`: Windows Server
  2022 and 2025, each with `smoke` and `recovery` suites.
- Preserve Windows PowerShell 5.1 compatibility; do not validate only with
  PowerShell 7.

## Boundaries

- Use only in-box Windows components. Do not add a custom daemon, WinRM, a
  password-auth fallback, UAC weakening, or router port forwarding.
- Installation and cleanup are journaled ownership transactions. Never weaken
  exact audit or rollback checks merely to make a test pass.
- Do not publish or recommend an installer URL until all four jobs for the
  exact release commit are green.
- Publish only versioned, SHA-256-pinned assets in an immutable GitHub Release;
  never install from `main` or `latest`.
- Keep `README.md` and `SHA256SUMS` synchronized with frozen release bytes.

## Layout

- `install.ps1`: installer, audit, uninstall, and recovery state machine.
- `winctl`: dependency-free macOS SSH/power configuration helper.
- `tests/Run.ps1`: native smoke, drift, and hard-crash recovery coverage.
- `tests/Static.Tests.ps1`: static security regressions.

## Current state

v1.0.0 is unreleased. README hash placeholders are deliberate until an exact
commit passes the complete matrix and its release assets are independently
downloaded and verified.
