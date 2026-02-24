## unreleased

## 0.3.1 - 2026.02.24
* **Global**: Fix possible parsing of invalid semantic releases versions.
* **Global**: Built-in Kubseal support within platform's toolchain.
* **Helmfile**: Use platform's native Kubeseal binary, prevent system's one requirement (if needed).

## 0.3.0 - 2026.02.20
* **Global**: Use --skip instead of --yes for Git checks bypass.
* **Global**: Built-in Sops support within platform's toolchain.
* **Global**: Fix automatic toolchain third-party components upgrade based on SemVer syntax.
* **Global**: Updated build and runtime dependencies.
* **Global**: Fix Git URL parsing and authentication.
* **Global**: Allow for SSH keyfile path expansion, if specified.
* **Ansible**: Use platform's native Sops binary, prevent system's one requirement.
* **Ansible**: Fix SSH credentials override parameters.
* **Ansible**: Don't enforce SSH credentials from ssh_config content, Ansible's smart enough to pick the right ones per-host, if defined.
* **Ansible**: Only pass user/key-file params to ansible when defined.

## 0.2.1 - 2026.02.13
* Support additional Helmfile templating parameters.
* Remove deprecated KobraConfig user configuration (and warning).
* Prevent error on secrets edit feature if file remains unchanged.
* Updated build and runtime dependencies.
* Rely on Go 1.26.

## 0.2.0 - 2025.12.11
* Proper Hashicorp's Vault implementation, supports variable mount path, uses authentication token from file or environment variable.

## 0.1.0 - 2025.08.21
* Initial release
