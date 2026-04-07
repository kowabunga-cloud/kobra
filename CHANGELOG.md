# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0](https://github.com/kowabunga-cloud/kobra/compare/v0.3.2...v0.4.0) (2026-04-07)

### Chores

* add conditional build strip flags ([28d4cb9](https://github.com/kowabunga-cloud/kobra/commit/28d4cb99e14dfbccfb437d32a01a9a5fdf03df51))
* add editor configuration ([310d9bb](https://github.com/kowabunga-cloud/kobra/commit/310d9bbb24bb242e2c9b09449882a3e19bbfca6b))
* add pre-commit hooks config ([d5116bf](https://github.com/kowabunga-cloud/kobra/commit/d5116bf9eb9527efe29ee48e731027e8eed4b94c))
* add support for semantic-release ([e7075c0](https://github.com/kowabunga-cloud/kobra/commit/e7075c022a4a68cc95c1fd79c8ab578dfc52f224))
* always use latest version of build tools ([210ece2](https://github.com/kowabunga-cloud/kobra/commit/210ece264631635d2c7a9bf68b0454f2e9e97624))
* configure goreleaser to strip symbols ([6a2c14e](https://github.com/kowabunga-cloud/kobra/commit/6a2c14e696fba1c23a24a4c602dd02256ce1ad11))
* disable auto debug symbols on debian builds ([271e19d](https://github.com/kowabunga-cloud/kobra/commit/271e19dbefbd05920a59c5483663d5e725dfd285))
* do not explicitly exclude gosec checks ([07b956c](https://github.com/kowabunga-cloud/kobra/commit/07b956c0bebbfa1c349fafdaa1bc4d782648e86c))
* explicit ignorance of gosec G101 issues ([613e561](https://github.com/kowabunga-cloud/kobra/commit/613e561e7b25e212ccdf1c050fe20625db9b5e92))
* explicit ignorance of gosec G115 issues ([a173eea](https://github.com/kowabunga-cloud/kobra/commit/a173eea5754798663991688315bf47960dd7830a))
* explicit ignorance of gosec G302 issues ([96a8c45](https://github.com/kowabunga-cloud/kobra/commit/96a8c45085bb52c50787bcbb25886b191a3d2aaa))
* extend helmfile template sub-command to output a default suffix if only a raw directory is passed as option ([1947940](https://github.com/kowabunga-cloud/kobra/commit/1947940355ff61aaace4ba7030b75d1bde29b3cf))
* extend helmfile template sub-command to output a default suffix if only a raw directory is passed as option ([52c546a](https://github.com/kowabunga-cloud/kobra/commit/52c546adcd79e0e8b8f2379de3c2a39f6e1ded31))
* ignore debian build residues from git ([d7105be](https://github.com/kowabunga-cloud/kobra/commit/d7105be4c7e51fa52f1c26166f6a743d5f677cd5))
* ignore extra files from git ([d9e6cab](https://github.com/kowabunga-cloud/kobra/commit/d9e6cab60dcd74bad4d1c92d77ff1ffc46c83715))
* re-use shared kowabunga action workflows ([98ddcf9](https://github.com/kowabunga-cloud/kobra/commit/98ddcf9e696c604b2036b4d8c19875a14e286db1))
* update build dependencies ([ada6f24](https://github.com/kowabunga-cloud/kobra/commit/ada6f24920a26328b7244d0ca5f6172188bd7cd8))
* update debian versioning process ([fb6c75a](https://github.com/kowabunga-cloud/kobra/commit/fb6c75a4ca6ea55f307a5b8c2bd7aa851d5695fb))
* update release action workflow ([37bda16](https://github.com/kowabunga-cloud/kobra/commit/37bda168d12ffeeb9ddf3f2cea10f43144244439))
* use git revision as default version for non-release builds ([beb4431](https://github.com/kowabunga-cloud/kobra/commit/beb443194d56d97a90efdaf5067b86dcb663f975))
* use new klog package location ([91a1f60](https://github.com/kowabunga-cloud/kobra/commit/91a1f60bbb9eedfffd049da49fdc4cd9639c7894))
* use workflow dispatch on release, not call ([324a563](https://github.com/kowabunga-cloud/kobra/commit/324a5630862adae020723fbeb7ea487403ded9d9))

### Documentation

* add CLAUDE description ([2252f12](https://github.com/kowabunga-cloud/kobra/commit/2252f12cda7712f65d7a6039ad7503dfd01651fc))
* add code owners description ([c4084b3](https://github.com/kowabunga-cloud/kobra/commit/c4084b337d9838556812f71ec14054afc0d6a6e0))
* remove trailing whitespace ([bc1c28e](https://github.com/kowabunga-cloud/kobra/commit/bc1c28e195fe5c2a168a5040703f9a8714cda673))
* updated README ([f5e6c93](https://github.com/kowabunga-cloud/kobra/commit/f5e6c932ac77d203a5d9c8bd1563b30c2534c679))

### Features

* add new env var to fully disable output ([f588b54](https://github.com/kowabunga-cloud/kobra/commit/f588b54b3e39564ef9e09ff0bffc3fc64cb8eeb2))
* extend helmfile support with write-values and print-env sub-commands ([ddf57c1](https://github.com/kowabunga-cloud/kobra/commit/ddf57c1fa567a2d56ae66ba9427564a68757fa12))

## unreleased

## 0.3.2 - 2026.02.26
* **Global**: Add unit tests suite.
* **Global**: Updated build and runtime dependencies.
* **kubeseal**: Introduce Kubeseal support for Kubernetes Sealed Secrets encryption.

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
