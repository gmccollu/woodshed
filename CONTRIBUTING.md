# Contributing to Woodshed

Thanks for helping. Bug reports, fixes and docs are all welcome. For a security problem, don't open an issue: see
[SECURITY.md](SECURITY.md).

## Build

You need Go (the version in `go.mod`) and Node.js 24 with npm. No C compiler: everything is pure Go.

```sh
make build          # the UI (web/) and the binary, into dist/woodshed
./dist/woodshed     # portable mode: runs here, data in dist/woodshed-data
```

`make web` builds only the UI into `web/dist`, which the Go binary embeds. For UI work, `cd web && npm run dev:mock`
serves it against mock data, and `npm run dev` against a Woodshed running on `127.0.0.1:8514`.

## Test

```sh
make test                  # go vet + go test -race ./..., including the end-to-end tests of the real binary
go test -short ./...       # everything except the end-to-end tests
WOODSHED_LONG_TESTS=1 go test ./internal/search/   # the search tests at full fixture size (CI: once, without -race)
make fuzz                  # every fuzz target for 30 s (FUZZTIME=5m make fuzz for longer)
cd web && npm run check    # type-check the UI
```

CI runs these on Linux, Windows and macOS (`.github/workflows/ci.yml`), plus a snapshot build of every package. The
installers are tested for real (install, send, restart, upgrade, uninstall) by `.github/workflows/install-smoke.yml`;
it runs on pushes to the `ci/install-smoke` branch, or by hand from the Actions tab.

Packaging: `make snapshot` builds the archives, deb and rpm into `dist/` without publishing anything;
`make pkg` builds the macOS installer; `packaging/windows/build-msi.ps1` the MSI (on Windows). See
[docs/install.md](docs/install.md) for what each one does.

## Rules

- **No outbound connections, except the update check and SNMP polls.** Woodshed never dials out on its own: no
  telemetry, fonts or CDNs. The exceptions are the opt-in update check in `internal/updatecheck` (SPEC §10.2), the
  only package allowed to reach the internet, and the SNMP poller in `internal/poller` (SPEC §12), which sends only to
  the devices an administrator configured. Tests enforce both; don't work around them.
- **Never lose or change a message.** The raw message is stored exactly as received; parsing only adds metadata.
  Anything dropped or truncated is counted and shown, never silent.
- **Plain files stay the source of truth.** The index must always be rebuildable from the log files.
- **Least privilege.** The service runs as its own unprivileged account on every OS. Changes to the installers or
  the service setup keep that, and are covered by the install smoke tests.
- **Tests with the change.** New behavior comes with tests; a fix comes with a test that fails without it.
- **Same on every OS.** Windows, macOS and Linux get equal care: if a change touches one, check the others.
- **Vendor-neutral.** No company or product names in code, docs or examples; use generic device names and the
  documentation address ranges (`192.0.2.0/24`, `2001:db8::/32`).
- **Dependencies:** prefer the standard library. A new dependency needs a permissive license (MIT, BSD, Apache-2.0,
  ISC and the like) and a regenerated `THIRD_PARTY_NOTICES.txt` (`make notices`; CI fails if it's stale).
- **Changelog:** add user-visible changes under the top section of [CHANGELOG.md](CHANGELOG.md).
- Text files use LF line endings (`.gitattributes`).

## Pull requests

Keep a pull request to one change, describe what it does and why, and make sure CI is green. By contributing you
agree that your contribution is licensed under the project's [MIT License](LICENSE).

## Releases (maintainers)

1. Move the changes under a dated `## [X.Y.Z] - YYYY-MM-DD` heading in `CHANGELOG.md`.
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. A tag with a suffix (`v1.1.0-rc1`) makes a prerelease.
3. `.github/workflows/release.yml` builds everything, attaches it to a draft release with the notes from the
   changelog, runs the benchmark, and publishes it.
