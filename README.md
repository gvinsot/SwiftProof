# SwiftProof

**Spend review time on the changes that need your judgment.**

SwiftProof is a Go CLI for reviewing AI-assisted pull requests: it maps Git
changes to risk signals, runs isolated checks and adversarial tests, and
produces a focused review plan with traceable evidence.

## Repository layout

| Directory | Contents |
| --- | --- |
| [`app/`](app/README.md) | The SwiftProof CLI (Go module `github.com/gvinsot/SwiftProof/app`) and its documentation, examples and report schema. |
| [`web/`](web/) | The static promotional website, served by nginx. |
| [`devops/`](devops/) | PulsarCD / Docker Swarm deployment of the website. |
| [`specs/`](specs/) | General product specifications. |

A root `go.work` includes `app/`, so Go commands also work from the
repository root with workspace patterns (`go test ./app/...`). SwiftProof
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

Licensed under the GNU AGPL-3.0 with an attribution term (section 7(b)), see [LICENSE](LICENSE) and [NOTICE](NOTICE). Releases up to v0.3.0 remain available under the MIT license.
