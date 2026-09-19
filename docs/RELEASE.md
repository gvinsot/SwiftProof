# Building release artifacts

The repository includes a packaging workflow; no release has been published by
this change. It uploads GitHub Actions artifacts and has read-only repository
permissions. It does not create a GitHub Release or upload to a package registry.

## Build from a checkout

Install Go 1.23 or newer and Git, then run from the repository root:

```sh
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=dev" -o swiftproof ./cmd/swiftproof
./swiftproof --version
```

On Windows, use `-o swiftproof.exe` and run `./swiftproof.exe --version`.
Replace `dev` with the version being built. The binary still requires Git at
runtime; sandbox checks additionally require Docker with Linux containers.

## Produce downloadable archives

In GitHub Actions, run **Build release artifacts** manually on the desired
checkout. An explicitly pushed `v*` tag also triggers it. Manual branch runs use
`dev-<12-character-commit>`; tagged runs embed the tag name through
`-X main.version`.

The workflow tests and vets on Linux, then cross-compiles with `CGO_ENABLED=0`
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
Review and publish them separately if distribution is desired.
