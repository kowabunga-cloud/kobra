<p align="center">
  <picture>
    <source srcset="https://raw.githubusercontent.com/kowabunga-cloud/infographics/master/art/kobra-raw.png" media="(prefers-color-scheme: dark)" />
    <source srcset="https://raw.githubusercontent.com/kowabunga-cloud/infographics/master/art/kobra-raw.png" media="(prefers-color-scheme: light), (prefers-color-scheme: no-preference)" />
    <img src="https://raw.githubusercontent.com/kowabunga-cloud/infographics/master/art/kobra-raw.png" alt="Kobra" width="200">
  </picture>
</p>

# Kobra

This is **Kobra**, a DevOps deployment swiss-army knife utility. It provides a convenient wrapper over [OpenTofu](https://opentofu.org/), [Ansible](https://www.redhat.com/en/technologies/management/ansible) and [Helmfile](https://helmfile.readthedocs.io/en/latest/) with proper secrets management, removing the hassle of complex deployment strategy.

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

# Installation

## Ubuntu Linux

Register [Kowabunga APT repository](https://packages.kowabunga.cloud/) and then simply:

```sh
$ sudo apt-get install kobra
```

## macOS

macOS can install **Kobra** through [Homebrew](https://brew.sh/). Simply do:

```sh
$ brew tap kowabunga/cloud https://github.com/kowabunga-cloud/homebrew-tap.git
$ brew update
$ brew install kobra
```

## Manual

**Kobra** can be manually installed through [released binaries](https://github.com/kowabunga-cloud/kobra/releases).

Just download and extract the tarball for your target.

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
    mount: string                     # optional, default to "secret" if unspecified
    token_env: string                 # optional, default to "VAULT_TOKEN" if unspecified
    token_file: string                # optional, default to "$HOME/.vault-token" if unspecified
  master_key_id: string
ssh:                                  # optional
  remote:                             # remote servers SSH connection parameters
    user: string                      # username to be used
    key_file: string                  # path to associated SSH private key file
  bootstrap:                          # optional, remote servers SSH connection parameters for first-deployment
    user: string                      # username to be used
    key_file: string                  # path to associated SSH private key file
toolchain:                            # optional
  use_system: bool                    # optional, 'false' if unspecified
  tf:                                 # optional
    provider: string                  # optional, accepts 'opentofu' (default) and 'terraform'
    version: string                   # optional, 'latest' if unspecified
  helm:                               # optional
    version: string                   # optional, 'latest' if unspecified
  helmfile:                           # optional
    version: string                   # optional, 'latest' if unspecified
  sops:                               # optional
    version: string                   # optional, 'latest' if unspecified
  kubeseal:                           # optional
    version: string                   # optional, 'latest' if unspecified
    controller:                       # optional
      namespace: string               # optional, 'kube-system' if unspecified
      name: string                    # optional, 'sealed-secrets' if unspecified
  ansible:                            # optional
    version: string                   # optional, 'latest' if unspecified
    packages:                         # optional, list of extra Python packages from PyPI to be added to toolchain
      freename: version               # key/value tuple with key being PyPI package name
                                      # and value being package version (use 'latest' if unpinned).
```

Note that **kobra.yml** configuration is global at plaform-level, and source of truth for all of your contributors. Consequently, it's not supposed to define user (or contributor) specific parameters (such as path to local files ...).

It is however possible to locally override its global content with a user specific one. One can consequently override it with a custom **.kobra.yml** configuration file, located at the root of platform's repository. If such a file exists, its content will be merged will global one.

**NOTE**: If using local override, do not forget to decalre **.kobra.yml** in your project's **.gitignore** as no one wants local overrides to be part of your Git history.

## Git Authentication

Note that Kobra will try to connect to Git before doing any deployment action. This is an intended extra security measure to ensure no divergence between your local copy and the remote one. More specifically, it is understood (and allowed) that your local branch can be ahead of origin repository's one, but not the opposite. This is meant to ensure you're not going to deploy a possibly outdated configuration of your platform.

Kobra will try auto-detecting Git repository's access as much as can be, but it can be further tuned in **git.{*}** configuration options in **kobra.yml** file.

Note that it is always possible to bypass this behavior by specifiying the **--skip** (or **-s**) command-line flag.

## SSH Connectivity

While global SSH connection (either to Git or managed instances, through Ansible) can be set in **kobra.yml** file, it is highly recommended to keep it properly managed at OS level.

By default, Git connectivity will rely on [SSH Agent](https://linux.die.net/man/1/ssh-agent), if available.

If not, a good approach is to ensure you have a **$HOME/.ssh/config** file, with global (i.e. fallback) **User** and/or **IdentityFile** definition, and optional per-host(s)s or subnet(s) override, e.g.:

```
User jdoe
IdentityFile /home/jdoe/.ssh/id_ecdsa

Host 10.*
    User ubuntu
    IdentityFile /home/jdoe/.ssh/priv-key
```

Alternatively, one can also set per-host settings and overrides and let Ansible address hosts by himself, e.g. with **ansible/inventories/hosts.txt**:

```ini
[all]
host-1 ansible_host=192.168.0.1 ansible_ssh_user=root ansible_ssh_private_key_file=/path/to/file
host-2 ansible_host=192.168.0.2 ansible_ssh_user=ubuntu ansible_ssh_private_key_file=/path/to/another/file
```

## Secrets Management

Kobra supports different secrets management **providers**:

- **aws**: AWS Secrets Manager (*TODO*)
- **env**: Environment variable stored master-key
- **file**: local plain text master-key file (not recommended for production)
- **hcp**: Hashicorp Vault
- **input**: interactive command-line input prompt for master-key
- **keyring**: local OS keyring (macOS Keychain, Windows Credentials Manager, Linux Gnome Keyring/KWallet)

**WARNING**: it is highly recommended not to use local secret management backends if secret is to be used by other contributors. When working as a team, always rely on distributed secret management backends.

## Tips & Ticks

Kobra supports various environment variables to tune its behavior:

- **KOBRA_DEBUG=1** would turn maximum verbosity.
- **KOBRA_NOLOG=1** would completely disable logs.

Ansible deployments being somehow imperative, you won't know the end state before changes are being applied. While it is always *somehow* possible to run deployment in dry-run mode (**kobra deploy -c**), the complete execution flow is not guaranteed.

If you care about planning changes (as you would get with OpenTofu/Terraform for example), it is possible to extract Ansible values as they would be interpreted, to provide pre-flight sanity checks that everything's ordered the way you expect.

A simple way to collect per-host variables interpolation would be:

```sh
$ kobra ansible inventory host -H machine_hostname -p playbook_name
```

Keep in mind that all secrets and sensitive variables, if any will be displayed plain-text.

Another approach, more 'GitOps-friendly', is to expose per-host computed into your platform's filesystem, e.g.:

```sh
$ kobra ansible inventory export -o path/to/gitops/ansible -f '^secret_' -f '^vault_' -p playbook_name
```

This example will output per-host YAML files into **path/to/gitops/ansible/{group_name}** directory by ensuring that all variables starting with **secret_** or **vault_** prefixes (as defined by regexp) are redacted, as to ensure they can be stored safely on Git. Running this command prior to any actual deployment, associated with **git diff** command will provide you extra insurance that host vars changes, if any, are as expected.

## Development Guidelines

Kobra development relies on [pre-commit hooks](http://www.pre-commit.com/) to ensure proper commits.

Follow installation instructions [here](https://pre-commit.com/#install).

Local per-repository installation can be done through:

```sh
$ pre-commit install --install-hooks
```

And system-wide global installation, through:

```sh
$ git config --global init.templateDir ~/.git-template
$ pre-commit init-templatedir ~/.git-template
```

## Development

Kobra development relies on [Semantic Versioning](https://semver.org/) and unscoped [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for development.

Changelog is automatically triggered from commits summary from the following commits types: **feat**, **fix**, **perf**, **chore**, **docs**, e.g.

```
feat!: upgrade API version         <- will increase version major number at release
feat: add new super nice feature   <- will increase version minor number at release
fix: correct bug XYZ               <- will increase version patch number at release
```

## Versioning

Versioning generally follows [Semantic Versioning](https://semver.org/).

## Authors

Kobra is maintained by [Kowabunga maintainers](https://github.com/orgs/kowabunga-cloud/teams/maintainers).

## License

Licensed under [Apache License, Version 2.0](https://opensource.org/license/apache-2-0), see [`LICENSE`](LICENSE).
