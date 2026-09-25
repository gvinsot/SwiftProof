# Building and publishing releases

The release workflow builds portable archives and can publish them to GitHub
Releases. Only its final publication job has repository write permission.

## Build Windows and Linux from a checkout

Install Go 1.23 or newer and Git, then run from the `app` directory of the repository:

```sh
go test ./...
go vet ./...
go run ./tools/build -version dev
```

The build helper runs on Windows, Linux and macOS without shell-specific tools.
It cross-compiles with `CGO_ENABLED=0` and produces all three default targets:

| Target | Executable | Archive |
| --- | --- | --- |
| Windows amd64 | `dist/windows-amd64/swiftproof.exe` | `dist/swiftproof-dev-windows-amd64.zip` |
| Linux amd64 | `dist/linux-amd64/swiftproof` | `dist/swiftproof-dev-linux-amd64.tar.gz` |
| Linux arm64 | `dist/linux-arm64/swiftproof` | `dist/swiftproof-dev-linux-arm64.tar.gz` |

Each archive contains the executable, `LICENSE` and `README.md`. Linux tar
archives preserve executable permissions, including when built on Windows.
`dist/SHA256SUMS` lists checksums for archives produced by the current invocation.
Replace `dev` with your version; `-out` selects another output directory.
To select targets explicitly:

```sh
go run ./tools/build -version v0.2.0 -targets linux/amd64,linux/arm64
```

Supported combinations are `windows`, `linux` and `darwin`, each with `amd64`
or `arm64`. Git is still required at runtime; sandbox execution additionally
requires Docker with Linux containers. To build only for the current host,
`go build ./cmd/swiftproof` remains available.

Every successful regular CI run creates a **swiftproof-build** artifact with
the three default archives and checksums, retained for 30 days. Download it
from the workflow run's artifacts section.

## Produce downloadable archives

In GitHub Actions, run **Build release artifacts** manually on the desired
branch. Leave **publish** unchecked to produce artifacts only. The optional
**version** field selects the embedded version; leaving it blank produces
`dev-<12-character-commit>`.

The workflow tests and vets on Linux, Windows and macOS, including Linux race
and Docker integration tests, then uses the same helper with `CGO_ENABLED=0`
for Linux, macOS (`darwin`), and Windows, each on `amd64` and `arm64`. This is
cross-compilation, not a runtime test of every target. The regular CI workflow
runs native tests on Linux, Windows, and macOS runners.

Download the **swiftproof-release** artifact from the completed run. It contains
six archives and `SHA256SUMS`. Each archive contains the executable, `LICENSE`,
and `README.md` inside a directory named after its version and target. Individual
target artifacts are also available. Artifacts expire after 30 days.

After extracting the downloaded Actions artifact, verify the archives before
unpacking the target you need:

```sh
# Linux
sha256sum --check SHA256SUMS
# macOS
shasum -a 256 --check SHA256SUMS
```

On Windows, compute a selected archive's digest with
`Get-FileHash ./swiftproof-<version>-windows-amd64.zip -Algorithm SHA256` and
compare it with its entry in `SHA256SUMS`.

Checksums detect mismatched bytes; these artifacts are not signed or notarized.

## Publish a GitHub Release

After committing and pushing the changes, open **Actions → Build release
artifacts → Run workflow**, select the branch, enter a version such as
`v0.1.0`, check **publish**, then run it. The workflow creates the tag at the
exact commit used for the build. Versions with a suffix such as `-rc.1` are
marked as prereleases.

Alternatively, push a version tag from your checkout:

```sh
git tag -a v0.1.0 -m "SwiftProof v0.1.0"
git push origin v0.1.0
```

Pushing a `v*` tag triggers verification, packaging and publication automatically.
Published versions must use `vMAJOR.MINOR.PATCH` with an optional prerelease suffix.
Use a new version for each release. An existing release is never overwritten;
if publication fails after draft creation, inspect and complete that draft.

The publication job verifies checksums and creates a draft with all six archives
and `SHA256SUMS`, then publishes it. Notes come from `app/docs/releases/<version>.md`
when present, otherwise GitHub generates them. Release assets remain downloadable
after the 30-day Actions artifact retention period.
