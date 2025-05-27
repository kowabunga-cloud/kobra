<p align="center">
  <picture>
    <source srcset="https://raw.githubusercontent.com/kowabunga-cloud/infographics/master/art/kobra-raw.png" media="(prefers-color-scheme: dark)" />
    <source srcset="https://raw.githubusercontent.com/kowabunga-cloud/infographics/master/art/kobra-raw.png" media="(prefers-color-scheme: light), (prefers-color-scheme: no-preference)" />
    <img src="https://raw.githubusercontent.com/kowabunga-cloud/infographics/master/art/kobra-raw.png" alt="Kobra" width="200">
  </picture>
</p>

# Kobra

This is **Kobra**, a DevOps deployment swiss-army knife utility. It provides a convenient wrapper over [OpenTofu](https://opentofu.org/), [Ansible](https://www.redhat.com/en/technologies/management/ansible) and [Helmfile](https://helmfile.readthedocs.io/en/latest/) with proper secrets management, removing the hassle of complex deployment startegy.

[![License: Apache License, Version 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://spdx.org/licenses/Apache-2.0.html)
[![Build Status](https://github.com/kowabunga-cloud/kobra/actions/workflows/ci.yml/badge.svg)](https://github.com/kowabunga-cloud/kobra/actions/workflows/ci.yml)
[![GoSec Status](https://github.com/kowabunga-cloud/kobra/actions/workflows/sec.yml/badge.svg)](https://github.com/kowabunga-cloud/kobra/actions/workflows/sec.yml)
[![GovulnCheck Status](https://github.com/kowabunga-cloud/kobra/actions/workflows/vuln.yml/badge.svg)](https://github.com/kowabunga-cloud/kobra/actions/workflows/vuln.yml)
[![Coverage Status](https://codecov.io/gh/kowabunga-cloud/kobra/branch/master/graph/badge.svg)](https://codecov.io/gh/kowabunga-cloud/kobra)
[![GoReport](https://goreportcard.com/badge/github.com/kowabunga-cloud/kobra)](https://goreportcard.com/report/github.com/kowabunga-cloud/kobra)
[![GoCode](https://img.shields.io/badge/go.dev-pkg-007d9c.svg?style=flat)](https://pkg.go.dev/github.com/kowabunga-cloud/kobra)
[![time tracker](https://wakatime.com/badge/github/kowabunga-cloud/kobra.svg)](https://wakatime.com/badge/github/kowabunga-cloud/kobra)
![Code lines](https://sloc.xyz/github/kowabunga-cloud/kobra/?category=code)
![Comments](https://sloc.xyz/github/kowabunga-cloud/kobra/?category=comments)
![COCOMO](https://sloc.xyz/github/kowabunga-cloud/kobra/?category=cocomo&avg-wage=100000)

## Current Releases

| Project            | Release Badge                                                                                       |
|--------------------|-----------------------------------------------------------------------------------------------------|
| **Kobra**           | [![Kowabunga Release](https://img.shields.io/github/v/release/kowabunga-cloud/kobra)](https://github.com/kowabunga-cloud/kobra/releases) |

## Managed Platform Configuration

Kobra-managed platforms require a specific **kobra.yml** file to exist at the root of your platform. This YAML-formated file contains several important pieces of configuration, e.g:

```yaml
git:                                  # optional
  method: string                      # optional, accepts 'ssh' (default) and 'http'
  ssh:                                # optional
    user: string                      # optional, 'git' if unspecified
    private_key_file: string          # optional, guessed from ~/.ssh/config if unspecified
    password: string                  # optional, password used to decrypt private key file, if any
  http:                               # optional
    username: string                  # optional, basic auth username
    password: string                  # optional, basic auth password
    token: string                     # optional, e.g GitHub PAT (Personal Access Token)
secrets:
  provider: string                    # aws, env, file, hcp, input, keyring
  aws:                                # optional, aws-provider specific
    region: string
    role_arn: string
    id: string
  env:                                # optional, env-provider specific
    var: string                       # optional, defaults to KOBRA_MASTER_KEY
  file:                               # optional, file-provider specific
    path: string
  hcp:                                # optional, hcp-provider specific
    endpoint: string                  # optional, default to "http://127.0.0.1:8200" if unspecified
  master_key_id: string
toolchain:                            # optional
  use_system: bool                    # optional, 'false' if unspecified
  tf:                                 # optional
    provider: string                  # optional, accepts 'opentofu' (default) and 'terraform'
    version: string                   # optional, 'latest' if unspecified
```

## Secrets Management

Kobra supports different secrets management **providers**:

- **aws**: AWS Secrets Manager
- **env**: Environment variable stored master-key
- **file**: local plain text master-key file (not recommended for production)
- **hcp**: Hashicorp Vault
- **input**: interactive command-line input prompt for master-key
- **keyring**: local OS keyring (macOS Keychain, Windows Credentials Manager, Linux Gnome Keyring/KWallet)

**WARNING**: it is highly recommended not to use local secret management backends if secret is to be used by other contributors. When working as a team, always rely on distributed secret management backends.

## License

Licensed under [Apache License, Version 2.0](https://opensource.org/license/apache-2-0), see [`LICENSE`](LICENSE).
