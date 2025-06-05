/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"io"
	"os"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"gopkg.in/yaml.v3"
)

// PlatformConfig is the root definition of a managed platform
type PlatformConfig struct {
	Git       PlatformConfigGit       `yaml:"git,omitempty"`
	Secrets   PlatformConfigSecrets   `yaml:"secrets"`
	SSH       PlatformConfigSSH       `yaml:"ssh,omitempty"`
	Toolchain PlatformConfigToolchain `yaml:"toolchain"`
}

// PlatformConfigGit contains git-specific configuration
type PlatformConfigGit struct {
	Method string                `yaml:"method,omitempty"`
	SSH    PlatformConfigGitSSH  `yaml:"ssh,omitempty"`
	HTTP   PlatformConfigGitHTTP `yaml:"http,omitempty"`
}

// PlatformConfigGitSSH contains git-ssh-specific configuration
type PlatformConfigGitSSH struct {
	User       string `yaml:"user,omitempty"`
	PrivateKey string `yaml:"private_key_file,omitempty"`
	Password   string `yaml:"password,omitempty"`
}

// PlatformConfigGitHTTP contains git-http-specific configuration
type PlatformConfigGitHTTP struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
}

// PlatformConfigSecrets contains secrets-specific configuration
type PlatformConfigSecrets struct {
	Provider    string                    `yaml:"provider"`
	MasterKeyID string                    `yaml:"master_key_id"`
	AWS         PlatformConfigSecretsAWS  `yaml:"aws,omitempty"`
	Env         PlatformConfigSecretsEnv  `yaml:"env,omitempty"`
	File        PlatformConfigSecretsFile `yaml:"file,omitempty"`
	HCP         PlatformConfigSecretsHCP  `yaml:"hcp,omitempty"`
}

// PlatformConfigSSH contains ssh-specific configuration
type PlatformConfigSSH struct {
	Remote    PlatformConfigSshConfig `yaml:"remote,omitempty"`
	Bootstrap PlatformConfigSshConfig `yaml:"bootstrap,omitempty"`
}

// PlatformConfigSshConfig contains ssh-specific configuration
type PlatformConfigSshConfig struct {
	User    string `yaml:"user"`
	KeyFile string `yaml:"key_file"`
}

// PlatformConfigSecretsAWS contains AWS Secrets Manager secrets-specific configuration
type PlatformConfigSecretsAWS struct {
	Region  string `yaml:"region"`
	ID      string `yaml:"id"`
	RoleARN string `yaml:"role_arn"`
}

// PlatformConfigSecretsEnv contains environment variable secrets-specific configuration
type PlatformConfigSecretsEnv struct {
	Var string `yaml:"var,omitempty"`
}

// PlatformConfigSecretsFile contains file-based secrets-specific configuration
type PlatformConfigSecretsFile struct {
	Path string `yaml:"path"`
}

// PlatformConfigSecretsHCP contains Hashicorp Vault secrets-specific configuration
type PlatformConfigSecretsHCP struct {
	Endpoint string `yaml:"endpoint,omitempty"`
}

// PlatformConfigToolchain toolchain-specific configuration
type PlatformConfigToolchain struct {
	UseSystem bool                            `yaml:"use_system,omitempty"`
	TF        PlatformConfigToolchainTF       `yaml:"tf,omitempty"`
	Helm      PlatformConfigToolchainHelm     `yaml:"helm,omitempty"`
	Helmfile  PlatformConfigToolchainHelmfile `yaml:"helmfile,omitempty"`
	Ansible   PlatformConfigToolchainAnsible  `yaml:"ansible,omitempty"`
}

// PlatformConfigToolchainTF contains tf-specific configuration
type PlatformConfigToolchainTF struct {
	Provider string `yaml:"provider,omitempty"`
	Version  string `yaml:"version,omitempty"`
}

// PlatformConfigToolchainHelm contains helm-specific configuration
type PlatformConfigToolchainHelm struct {
	Version string `yaml:"version,omitempty"`
}

// PlatformConfigToolchainHelmfile contains helmfile-specific configuration
type PlatformConfigToolchainHelmfile struct {
	Version string `yaml:"version,omitempty"`
}

// PlatformConfigToolchainAnsible contains ansible-specific configuration
type PlatformConfigToolchainAnsible struct {
	Version  string            `yaml:"version,omitempty"`
	Packages map[string]string `yaml:"packages,omitempty"`
}

const (
	PlatformConfigFile = "kobra.yml"
	InvalidConfigField = "empty or invalid %s in platform configuration file: '%s'"

	GitMethodSSH  = "ssh"
	GitMethodHTTP = "http"

	GitDefaultUserSSH = "git"

	SecretsProviderAWS     = "aws"
	SecretsProviderEnv     = "env"
	SecretsProviderFile    = "file"
	SecretsProviderHCP     = "hcp"
	SecretsProviderInput   = "input"
	SecretsProviderKeyring = "keyring"

	ToolchainVersionLatest = "latest"

	TfProviderOpenTofu  = "opentofu"
	TfProviderTerraform = "terraform"
)

func isSupportedGitMethod(method string) bool {
	switch method {
	case
		GitMethodSSH,
		GitMethodHTTP:
		return true
	}
	return false
}

func isSupportedSecretsProvider(provider string) bool {
	switch provider {
	case
		SecretsProviderAWS,
		SecretsProviderEnv,
		SecretsProviderFile,
		SecretsProviderHCP,
		SecretsProviderInput,
		SecretsProviderKeyring:
		return true
	}
	return false
}

func isSupportedTfProvider(t string) bool {
	switch t {
	case
		TfProviderOpenTofu,
		TfProviderTerraform:
		return true
	}
	return false
}

func (p *PlatformConfig) IsValid() error {
	err := false
	type configValidateFunc func(string) bool
	type configParam struct {
		key     string
		f       configValidateFunc
		comment string
	}

	params := []configParam{
		configParam{p.Git.Method, isSupportedGitMethod, "git method"},
		configParam{p.Secrets.Provider, isSupportedSecretsProvider, "secrets provider"},
		configParam{p.Toolchain.TF.Provider, isSupportedTfProvider, "TF provider"},
	}

	for _, pr := range params {
		if !pr.f(pr.key) {
			klog.Warningf(InvalidConfigField, pr.comment, pr.key)
			err = true
		}
	}

	if err {
		return fmt.Errorf("invalid value")
	}

	return nil
}

func GetPlatformConfigFile() string {
	ptfDir, err := LookupPlatformDir()
	if err != nil {
		klog.Fatalf("can't find platform directory")
	}

	return fmt.Sprintf("%s/%s", ptfDir, PlatformConfigFile)
}

func GetPlatformConfig() (*PlatformConfig, error) {
	var cfg PlatformConfig

	f, err := os.Open(GetPlatformConfigFile())
	if err != nil {
		errS := fmt.Errorf("platform_configuration: file (%s) does not exist", PlatformConfigFile)
		return nil, errS
	}
	defer func() {
		_ = f.Close()
	}()

	contents, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// unmarshal configuration
	err = yaml.Unmarshal(contents, &cfg)
	if err != nil {
		e := fmt.Errorf("platform_configuration: unable to unmarshal config (%s)", err)
		klog.Error(e)
		return nil, e
	}

	// set default value
	LookupDefault(&cfg.Git.Method, "Git Method", GitMethodSSH)
	LookupDefault(&cfg.Toolchain.TF.Provider, "TF Provider", TfProviderOpenTofu)
	LookupDefault(&cfg.Toolchain.TF.Version, "TF Version", ToolchainVersionLatest)
	LookupDefault(&cfg.Toolchain.Helm.Version, "Helm Version", ToolchainVersionLatest)
	LookupDefault(&cfg.Toolchain.Helmfile.Version, "Helmfile Version", ToolchainVersionLatest)
	LookupDefault(&cfg.Toolchain.Ansible.Version, "Ansible Version", ToolchainVersionLatest)

	// check for valid configuration
	err = cfg.IsValid()
	if err != nil {
		e := fmt.Errorf("platform_configuration: file seems to be invalid and with unsupported keys/values (%s)", err)
		klog.Error(e)
		return nil, e
	}

	return &cfg, nil
}
