# SwiftProof

**Spend review time on the changes that need your judgment.**

SwiftProof is a Go CLI for reviewing AI-assisted pull requests: it maps Git
changes to risk signals, runs isolated checks and adversarial tests, and
produces a focused review plan with traceable evidence.

## Repository layout

| Directory | Contents |
| --- | --- |
| [`app/`](app/README.md) | The SwiftProof CLI (Go module `github.com/gvinsot/SwiftProof/app`) and its documentation, examples and report schema. |
| [`hub/`](hub/README.md) | The SwiftProof Hub web application (Go module `github.com/gvinsot/SwiftProof/hub`): forge sign-in, policy bootstrap and the live report viewer. |
| [`web/`](web/) | The static promotional website, served by nginx. |
| [`devops/`](devops/) | PulsarCD / Docker Swarm deployment of the website. |
| [`specs/`](specs/) | General product specifications. |

A root `go.work` includes `app/` and `hub/`, so Go commands also work from the
repository root with workspace patterns (`go test ./app/...`, `go test ./hub/...`). SwiftProof
reviews its own pull requests with the root [`.swiftproof.json`](.swiftproof.json).

## Quick start

Download a binary from [GitHub Releases](https://github.com/gvinsot/SwiftProof/releases),
or build from source:

```sh
cd app
go build -o swiftproof ./cmd/swiftproof
```

See [app/README.md](app/README.md) for usage, configuration and CI integration.

## Website

```sh
docker build -t swiftproof-web web
docker run --rm -p 8080:80 swiftproof-web   # http://localhost:8080
```

Deployment goes through PulsarCD with `devops/docker-compose.swarm.yml`; copy
`devops/.env.example` to `devops/.env` to set the public domain.

## Web application

The hub complements the website: sign in with GitHub or GitLab, let it create a
`.swiftproof.json` policy in the repositories that have none, and read a
severity-filtered report for every new commit — clicking an alert unfolds the
modifications it concerns.

```sh
docker build -f hub/Dockerfile -t swiftproof-hub .
docker run --rm -p 8080:8080 \
  -e SWIFTPROOF_HUB_BASE_URL=http://localhost:8080 \
  -e SWIFTPROOF_HUB_GITHUB_CLIENT_ID=... \
  -e SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET=... \
  swiftproof-hub
```

It runs as a single container with no database, so a company can deploy it
internally against its own GitHub Enterprise or GitLab instance. Images are
published to Docker Hub by `hub/scripts/postbuild.sh` (wired into CI by
`devops/github-workflows/hub.yml`, to be copied into `.github/workflows/`); see
[hub/README.md](hub/README.md) for the configuration and the security model.

Licensed under the GNU AGPL-3.0 with an attribution term (section 7(b)), see [LICENSE](LICENSE) and [NOTICE](NOTICE). Releases up to v0.3.0 remain available under the MIT license.
