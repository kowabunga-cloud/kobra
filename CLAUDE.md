# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Kobra

Kobra is a DevOps deployment swiss-army knife CLI tool written in Go. It wraps [OpenTofu](https://opentofu.org/), [Ansible](https://www.redhat.com/en/technologies/management/ansible), and [Helmfile](https://helmfile.readthedocs.io/en/latest/) with integrated secrets management (via SOPS), removing the complexity of multi-tool deployment pipelines.

## Commands

```sh
make all          # mod + fmt + vet + fix + lint + build
make build        # compile binaries to bin/
make tests        # run test suite with coverage (coverage.txt)
make fmt          # go fmt
make vet          # go vet
make lint         # golangci-lint (auto-downloaded to bin/ if missing)
make vuln         # govulncheck
make sec          # gosec
make release      # goreleaser snapshot build
make clean        # remove bin/*
```

Run a single test:
```sh
go test ./kobra/... -run TestFunctionName -count=1
```

## Architecture

**Entry point**: `cmd/kobra/main.go` — initializes logging, then calls `kobra.ParseCommands()`.

All logic lives in the `kobra/` package:

| Area | Files | Role |
|------|-------|------|
| CLI commands | `commands.go`, `cmd_tf.go`, `cmd_ansible.go`, `cmd_helmfile.go`, `cmd_secrets.go`, `cmd_kubeseal.go`, `cmd_version.go` | Cobra command definitions; each tool gets its own `cmd_*.go` |
| Tool execution | `exec.go`, `tf.go`, `ansible.go`, `helmfile.go`, `kubeseal.go`, `sops.go` | `exec.go` is the low-level binary runner; tool-specific files build args and env for it |
| Configuration | `platform_config.go` | Parses `kobra.yml` — the per-platform config file users must provide |
| Secrets | `secrets.go`, `secrets_provider_*.go` | Provider abstraction; concrete providers: `env`, `file`, `hcp` (Vault), `input`, `keyring` |
| Infrastructure | `git.go`, `ssh.go` | Git clone/auth and SSH key management |
| Toolchain setup | `setup.go` | Downloads and manages pinned versions of tofu/helm/helmfile/ansible/sops/kubeseal |
| Utilities | `lookups.go`, `errors.go` | Shared helpers |

## Platform Configuration (`kobra.yml`)

Every managed platform requires a `kobra.yml` at its root. Key sections:
- `git` — authentication method (ssh/http) and credentials
- `secrets` — provider selection (`aws`/`env`/`file`/`hcp`/`input`/`keyring`) and provider-specific config; `master_key_id` references the SOPS master key
- `ssh` — remote and bootstrap SSH user/key for Ansible
- `toolchain` — opt-in to system tools (`use_system: true`) or pin specific versions; supports `tf`, `helm`, `helmfile`, `sops`, `kubeseal`, `ansible`

## Environment Variables

- `KOBRA_DEBUG=1` — maximum verbosity
- `KOBRA_NOLOG=1` — disable all log output

## Key Conventions

- The `kobra/` package version string is injected at build time via `-ldflags '-X $(PKG_NAME).version=$(VERSION)'`
- External tools (tofu, helm, etc.) are downloaded to a local toolchain directory when `use_system: false` (default); `setup.go` handles version resolution and binary caching
- Secrets are encrypted with SOPS; the master key is fetched at runtime from the configured provider before any SOPS operation
- CI uses shared reusable workflows from `kowabunga-cloud/kowabunga` (`.github/workflows/ci.yml` and `release.yml` delegate to those)
